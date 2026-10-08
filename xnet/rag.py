"""Private local RAG catalog and disposable predictive prefetch queue.

The authoritative bytes live in the existing SHA-256 CAS.  SQLite contains
only rebuildable aliases, provenance, lexical/feature indexes, checkpoints,
and short-lived prefetch records.  This module never opens a network socket
and only indexes paths below roots supplied explicitly by the caller.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import sqlite3
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from .protocol import canonical, digest, sha256
from .routing_protocols import routing_envelope, validate_routing_envelope


CATALOG_SCHEMA = "xnet.rag-catalog-record.v1"
CHECKPOINT_SCHEMA = "xnet.rag-scan-checkpoint.v1"
PREDICTION_SCHEMA = "xnet.rag-prediction.v1"

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_SCAN_FILES = 10_000
MAX_QUERY_CHARS = 512
MAX_RETRIEVAL_RESULTS = 20
MAX_RETRIEVAL_CHARS = 24_000
MAX_SEMANTIC_CANDIDATES = 4_096
VECTOR_DIMENSIONS = 64

TEXT_EXTENSIONS = frozenset(
    {
        ".c", ".cc", ".cpp", ".css", ".csv", ".go", ".h", ".hpp",
        ".html", ".ini", ".java", ".js", ".json", ".jsx", ".md",
        ".ps1", ".py", ".rb", ".rs", ".rst", ".sh", ".sql", ".toml",
        ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml", ".zig",
    }
)
PERMISSION_CLASSES = frozenset({"private", "restricted", "public"})
TAG_RE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}\Z")
HEX64_RE = re.compile(r"[0-9a-f]{64}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,64}")

SECRET_PATH_PARTS = frozenset(
    {
        ".env", ".ssh", "auth", "authentication", "credential", "credentials",
        "key", "keys", "oauth", "secret", "secrets", "token", "tokens",
    }
)
SECRET_SUFFIXES = frozenset({".key", ".pem", ".p12", ".pfx", ".jks", ".kdbx"})
BENCHMARK_MARKERS = frozenset({"benchmark", "benchmarks", "swe-bench", "swebench", "evaluation", "evaluator"})
BENCHMARK_ARTIFACT_MARKERS = frozenset(
    {"answer", "answers", "dataset", "datasets", "gold", "prompt", "prompts", "solution", "solutions", "test", "tests"}
)
BOOK_MARKERS = frozenset({"book", "books", "corpus", "corpora", "ebook", "ebooks", "library"})
BOOK_SUFFIXES = frozenset({".epub", ".mobi", ".azw", ".azw3"})

SECRET_PATTERNS = (
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    re.compile(rb"(?i)(?:api[_-]?key|access[_-]?token|refresh[_-]?token|auth[_-]?token|client[_-]?secret|authorization|password|token)[\"']?\s*[:=]\s*[\"']?[^\s\",;]{8,}"),
    re.compile(rb"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._~+/=-]{8,}"),
    re.compile(rb"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{16,}"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{24,}\b"),
)

WORKER_CAPABILITIES: dict[str, frozenset[str]] = {
    "solver": frozenset({"consume", "execute_tools", "mutate_task_state"}),
    "scout": frozenset({"prefetch"}),
}


class RagError(ValueError):
    """Base error for fail-closed local RAG operations."""


class RagPolicyError(RagError):
    """An input violates corpus, privacy, or role policy."""


class RagFirewallError(RagPolicyError):
    """Benchmark firewall mode blocked an operation."""


def require_worker_action(role: str, action: str) -> None:
    """Enforce the two-role boundary independently of caller prose."""
    if role not in WORKER_CAPABILITIES:
        raise RagPolicyError("unknown RAG worker role")
    if action not in WORKER_CAPABILITIES[role]:
        raise RagPolicyError(f"RAG worker role {role} may not {action}")


def worker_policy(role: str) -> dict[str, Any]:
    if role not in WORKER_CAPABILITIES:
        raise RagPolicyError("unknown RAG worker role")
    capabilities = WORKER_CAPABILITIES[role]
    return {
        "role": role,
        "prefetch": "prefetch" in capabilities,
        "consume": "consume" in capabilities,
        "execute_tools": "execute_tools" in capabilities,
        "mutate_task_state": "mutate_task_state" in capabilities,
    }


def _parts_lower(path: Path) -> list[str]:
    return [part.casefold() for part in path.parts if part not in (path.anchor, "", ".")]


def _has_marker(parts: Iterable[str], markers: frozenset[str]) -> bool:
    for part in parts:
        words = set(filter(None, re.split(r"[^a-z0-9]+", part.casefold())))
        if words & markers or part.casefold() in markers:
            return True
    return False


def _benchmark_sensitive(path: Path | None = None, tags: Sequence[str] = ()) -> bool:
    parts = _parts_lower(path) if path is not None else []
    lowered_tags = [tag.casefold() for tag in tags]
    benchmark_context = _has_marker(parts, BENCHMARK_MARKERS) or _has_marker(lowered_tags, BENCHMARK_MARKERS)
    artifact = _has_marker(parts, BENCHMARK_ARTIFACT_MARKERS) or _has_marker(lowered_tags, BENCHMARK_ARTIFACT_MARKERS)
    tag_artifact = _has_marker(lowered_tags, BENCHMARK_ARTIFACT_MARKERS)
    strong_path_artifact = _has_marker(parts, frozenset({"answers", "dataset", "datasets", "gold", "prompt", "prompts", "solution", "solutions"}))
    return benchmark_context or tag_artifact or strong_path_artifact or artifact and any("bench" in part for part in parts)


def _firewall_reference(path: Path | None = None, tags: Sequence[str] = ()) -> bool:
    parts = _parts_lower(path) if path is not None else []
    lowered_tags = [tag.casefold() for tag in tags]
    return _has_marker(parts, BENCHMARK_MARKERS | BENCHMARK_ARTIFACT_MARKERS) or _has_marker(
        lowered_tags, BENCHMARK_MARKERS | BENCHMARK_ARTIFACT_MARKERS
    )


def _book_sensitive(path: Path) -> bool:
    parts = _parts_lower(path)
    inference_or_public = any(part in {"inference", "public"} for part in parts)
    return path.suffix.casefold() in BOOK_SUFFIXES or inference_or_public and _has_marker(parts, BOOK_MARKERS)


def _normalize_tag(tag: str) -> str:
    value = tag.strip().casefold()
    if not TAG_RE.fullmatch(value):
        raise RagPolicyError("RAG tags must match [a-z0-9][a-z0-9_.-]{0,63}")
    return value


def _normalize_root_alias(alias: str) -> str:
    return _normalize_tag(alias)


def _normalize_source_alias(alias: str) -> str:
    value = alias.replace("\\", "/").strip("/")
    parts = value.split("/")
    if not value or len(value) > 512 or any(part in ("", ".", "..") for part in parts):
        raise RagPolicyError("invalid source path alias")
    return value


def _stem(token: str) -> str:
    token = token.casefold()
    if len(token) > 5 and token.endswith("ies"):
        return token[:-3] + "y"
    for suffix in ("ingly", "edly", "ation", "ments", "ment", "ing", "ers", "ed", "es", "s"):
        if len(token) >= len(suffix) + 3 and token.endswith(suffix):
            return token[: -len(suffix)]
    return token


def _tokens(text: str) -> list[str]:
    return [_stem(match.group(0)) for match in TOKEN_RE.finditer(text.casefold())]


def _features(text: str) -> list[str]:
    tokens = _tokens(text)
    features = list(tokens)
    features.extend(f"{left}:{right}" for left, right in zip(tokens, tokens[1:]))
    for token in tokens:
        if len(token) >= 5:
            features.extend(f"~{token[i:i + 3]}" for i in range(len(token) - 2))
    return features


def _semantic_vector(text: str) -> list[int]:
    vector = [0] * VECTOR_DIMENSIONS
    for feature in _features(text):
        raw = hashlib.sha256(feature.encode("utf-8")).digest()
        index = int.from_bytes(raw[:2], "big") % VECTOR_DIMENSIONS
        vector[index] += 1 if raw[2] & 1 else -1
    return vector


def _cosine(left: Sequence[int], right: Sequence[int]) -> float:
    dot = sum(a * b for a, b in zip(left, right))
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    return max(0.0, dot / (left_norm * right_norm))


def _chunk_text(text: str, max_chars: int = 1_600) -> list[tuple[int, int, str]]:
    chunks: list[tuple[int, int, str]] = []
    current: list[str] = []
    current_size = 0
    start_line = 1
    line_no = 0
    for line_no, line in enumerate(text.splitlines(keepends=True), 1):
        pieces = [line[i:i + max_chars] for i in range(0, len(line), max_chars)] or [""]
        for piece in pieces:
            if current and current_size + len(piece) > max_chars:
                chunks.append((start_line, line_no - 1 if len(pieces) == 1 else line_no, "".join(current)))
                current = []
                current_size = 0
                start_line = line_no
            if not current:
                start_line = line_no
            current.append(piece)
            current_size += len(piece)
            if current_size >= max_chars:
                chunks.append((start_line, line_no, "".join(current)))
                current = []
                current_size = 0
    if current:
        chunks.append((start_line, max(line_no, start_line), "".join(current)))
    if not chunks and text:
        chunks.append((1, 1, text[:max_chars]))
    return chunks


def _source_byte_chunks(raw: bytes, maximum: int) -> list[dict[str, Any]]:
    """Partition exact UTF-8 bytes; prefer line ends and never split CRLF."""
    chunks: list[dict[str, Any]] = []
    start = 0
    while start < len(raw):
        end = min(start + maximum, len(raw))
        while end < len(raw) and raw[end] & 0xC0 == 0x80:
            end -= 1
        if end < len(raw) and raw[end - 1:end + 1] == b"\r\n":
            end -= 1
        newline = raw.rfind(b"\n", start, end) + 1
        if newline >= start + maximum // 2:
            end = newline
        piece = raw[start:end]
        chunks.append({"ordinal": len(chunks), "start_byte": start, "end_byte": end,
                       "sha256": sha256(piece), "token_length": len(_tokens(piece.decode("utf-8")))})
        if len(chunks) > MAX_SEMANTIC_CANDIDATES:
            raise RagPolicyError("sealed source exceeds bounded slice chunk count")
        start = end
    return chunks


def _source_ranges(raw: bytes, ranges: Sequence[Sequence[int]]) -> list[list[int]]:
    if type(ranges) not in (list, tuple) or len(ranges) > 16:
        raise RagPolicyError("at most sixteen explicit required source ranges")
    checked = []
    for bounds in ranges:
        if (type(bounds) not in (list, tuple) or len(bounds) != 2
            or any(type(value) is not int for value in bounds)
            or not 0 <= bounds[0] < bounds[1] <= len(raw)):
            raise RagPolicyError("invalid required UTF-8 byte range")
        for offset in bounds:
            if (offset < len(raw) and raw[offset] & 0xC0 == 0x80
                or 0 < offset < len(raw) and raw[offset - 1:offset + 1] == b"\r\n"):
                raise RagPolicyError("source range splits UTF-8 or CRLF")
        checked.append(list(bounds))
    return _merge_source_ranges(checked)


def _merge_source_ranges(ranges: Sequence[Sequence[int]]) -> list[list[int]]:
    merged: list[list[int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(end, merged[-1][1])
        else:
            merged.append([start, end])
    return merged


def _source_rendered_size(parent_bytes: int, ranges: Sequence[Sequence[int]]) -> int:
    if not ranges:
        return 0
    size, previous = 0, 0
    for start, end in ranges:
        size += end - start + (7 if start > previous else 0)
        previous = end
    return size + (7 if previous < parent_bytes else 0)


def _render_source_ranges(raw: bytes, ranges: Sequence[Sequence[int]]) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    marker = b"\n[...]\n"
    rendered = bytearray()
    selected, omitted = [], []
    previous = 0
    for start, end in ranges:
        if start > previous:
            missing = raw[previous:start]
            omitted.append({"start_byte": previous, "end_byte": start, "sha256": sha256(missing)})
            rendered.extend(marker)
        slice_start = len(rendered)
        rendered.extend(raw[start:end])
        selected.append({"start_byte": start, "end_byte": end, "sha256": sha256(raw[start:end]),
                         "start_line": raw[:start].count(b"\n") + 1,
                         "end_line": raw[:end].count(b"\n") + (0 if raw[end - 1:end] == b"\n" else 1),
                         "slice_start_byte": slice_start, "slice_end_byte": len(rendered),
                         "text": raw[start:end].decode("utf-8")})
        previous = end
    if previous < len(raw):
        omitted.append({"start_byte": previous, "end_byte": len(raw), "sha256": sha256(raw[previous:])})
        if selected:
            rendered.extend(marker)
    return rendered.decode("utf-8"), selected, omitted


def _rank_source_chunks(raw: bytes, chunks: list[dict[str, Any]], query: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Pure lexical BM25-style scores with stable term and tie ordering."""
    terms = sorted(set(_tokens(query)))
    docs = [_tokens(raw[row["start_byte"]:row["end_byte"]].decode("utf-8")) for row in chunks]
    doc_terms = [set(tokens) for tokens in docs]
    frequencies = {term: sum(term in tokens for tokens in doc_terms) for term in terms}
    average = sum(map(len, docs)) / max(1, len(docs))
    ranked = []
    for row, tokens in zip(chunks, docs):
        counts: dict[str, int] = {}
        for term in tokens:
            counts[term] = counts.get(term, 0) + 1
        score = 0.0
        for term in terms:
            frequency = counts.get(term, 0)
            if not frequency:
                continue
            inverse = math.log1p((len(docs) - frequencies[term] + 0.5) / (frequencies[term] + 0.5))
            denominator = frequency + 1.2 * (0.25 + 0.75 * len(tokens) / max(average, 1))
            score += inverse * frequency * 2.2 / denominator
        ranked.append({**row, "score": round(score, 12)})
    return ranked, {"query_terms": terms, "document_frequency": frequencies,
                    "documents": len(docs), "average_token_length": average,
                    "k1": 1.2, "b": 0.75, "score_decimal_places": 12,
                    "tie_order": "source-ordinal-ascending", "embeddings": False}


class RagCatalog:
    """Content-addressed catalog restricted to explicit local roots."""

    def __init__(
        self,
        data_root: Path,
        *,
        allowed_roots: Sequence[Path] = (),
        benchmark_firewall: bool = False,
        clock: Callable[[], float] = time.time,
    ):
        self.data_root = Path(data_root)
        self.db_path = self.data_root / "rag" / "catalog.sqlite3"
        self.cas_dir = self.data_root / "cas" / "sha256"
        env_firewall = os.environ.get("XNET_RAG_BENCHMARK_FIREWALL", "").strip().casefold() in {"1", "true", "yes", "on"}
        self.benchmark_firewall = bool(benchmark_firewall or env_firewall)
        self.clock = clock
        self.allowed_roots = tuple(self._validate_root(Path(root)) for root in allowed_roots)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.cas_dir.mkdir(parents=True, exist_ok=True)
        self._fts5 = False
        self._initialize()

    @staticmethod
    def _validate_root(root: Path) -> Path:
        resolved = root.resolve(strict=True)
        if not resolved.is_dir():
            raise RagPolicyError("RAG allowlist roots must be directories")
        anchor = Path(resolved.anchor).resolve()
        home = Path.home().resolve()
        if resolved == anchor or resolved == home:
            raise RagPolicyError("raw drive and full-home scans are forbidden")
        if str(resolved).startswith("\\\\"):
            raise RagPolicyError("network roots are forbidden")
        if resolved.is_symlink() or (hasattr(resolved, "is_junction") and resolved.is_junction()):
            raise RagPolicyError("linked allowlist roots are forbidden")
        return resolved

    @contextmanager
    def _conn(self):
        db = sqlite3.connect(self.db_path, timeout=20)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA foreign_keys=ON")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _initialize(self) -> None:
        with self._conn() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS rag_sources (
                    source_hash TEXT PRIMARY KEY, size INTEGER NOT NULL, indexed_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rag_aliases (
                    source_path_alias TEXT PRIMARY KEY, source_hash TEXT NOT NULL,
                    mtime_ns INTEGER NOT NULL, permission_class TEXT NOT NULL,
                    freshness_until INTEGER NOT NULL, retention_until INTEGER NOT NULL,
                    indexed_at INTEGER NOT NULL,
                    FOREIGN KEY(source_hash) REFERENCES rag_sources(source_hash)
                );
                CREATE TABLE IF NOT EXISTS rag_tags (
                    source_path_alias TEXT NOT NULL, tag TEXT NOT NULL,
                    PRIMARY KEY(source_path_alias, tag),
                    FOREIGN KEY(source_path_alias) REFERENCES rag_aliases(source_path_alias) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS rag_chunks (
                    chunk_hash TEXT PRIMARY KEY, text TEXT NOT NULL, vector_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS rag_source_chunks (
                    source_hash TEXT NOT NULL, ordinal INTEGER NOT NULL, chunk_hash TEXT NOT NULL,
                    start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
                    PRIMARY KEY(source_hash, ordinal),
                    FOREIGN KEY(source_hash) REFERENCES rag_sources(source_hash),
                    FOREIGN KEY(chunk_hash) REFERENCES rag_chunks(chunk_hash)
                );
                CREATE TABLE IF NOT EXISTS rag_lexical (
                    source_path_alias TEXT NOT NULL, source_hash TEXT NOT NULL, ordinal INTEGER NOT NULL,
                    chunk_hash TEXT NOT NULL, text TEXT NOT NULL,
                    PRIMARY KEY(source_path_alias, ordinal)
                );
                CREATE TABLE IF NOT EXISTS rag_predictions (
                    hypothesis_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, confidence REAL NOT NULL,
                    created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    record_json TEXT NOT NULL, payload_json TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS rag_prediction_task_expiry ON rag_predictions(task_id, expires_at);
                CREATE INDEX IF NOT EXISTS rag_alias_source ON rag_aliases(source_hash);
                """
            )
            try:
                db.execute(
                    "CREATE VIRTUAL TABLE IF NOT EXISTS rag_fts USING fts5(source_path_alias UNINDEXED, source_hash UNINDEXED, ordinal UNINDEXED, chunk_hash UNINDEXED, text)"
                )
                self._fts5 = True
            except sqlite3.DatabaseError:
                self._fts5 = False

    def _reject_benchmark_reference(self, path: Path | None = None, tags: Sequence[str] = ()) -> None:
        if self.benchmark_firewall and _firewall_reference(path, tags):
            raise RagFirewallError("benchmark firewall rejects benchmark dataset/gold/test/prompt/solution paths or tags")
        if _benchmark_sensitive(path, tags):
            raise RagPolicyError("benchmark material is excluded from the RAG corpus")

    def _reject_benchmark_root(self, root: Path) -> None:
        if _has_marker(_parts_lower(root), BENCHMARK_MARKERS):
            if self.benchmark_firewall:
                raise RagFirewallError("benchmark firewall rejects benchmark dataset/gold/test/prompt/solution paths or tags")
            raise RagPolicyError("benchmark material is excluded from the RAG corpus")

    def _ensure_enabled(self, operation: str) -> None:
        if self.benchmark_firewall:
            raise RagFirewallError(f"benchmark firewall disables RAG {operation}")

    def _root_for(self, path: Path) -> tuple[Path, Path]:
        if not self.allowed_roots:
            raise RagPolicyError("indexing requires at least one explicit allowlist root")
        resolved = path.resolve(strict=True)
        matches: list[tuple[int, Path, Path]] = []
        for root in self.allowed_roots:
            try:
                relative = resolved.relative_to(root)
            except ValueError:
                continue
            matches.append((len(root.parts), root, relative))
        if not matches:
            raise RagPolicyError("path is outside the allowlisted local corpus")
        _, root, relative = max(matches, key=lambda item: item[0])
        current = root
        for part in relative.parts:
            current = current / part
            if current.is_symlink() or (hasattr(current, "is_junction") and current.is_junction()):
                raise RagPolicyError("links and junctions inside the corpus are forbidden")
        return root, relative

    def _validate_file_policy(self, path: Path, tags: Sequence[str]) -> tuple[Path, Path]:
        root, relative = self._root_for(path)
        self._reject_benchmark_root(root)
        self._reject_benchmark_reference(relative, tags)
        parts = _parts_lower(path)
        if _has_marker(parts, SECRET_PATH_PARTS) or path.suffix.casefold() in SECRET_SUFFIXES:
            raise RagPolicyError("secret/key/auth-token paths are excluded from the RAG corpus")
        if _book_sensitive(path):
            raise RagPolicyError("copyright-sensitive book corpora from inference/public paths are excluded")
        if path.suffix.casefold() not in TEXT_EXTENSIONS:
            raise RagPolicyError("file type is not in the local text allowlist")
        return root, relative

    def _object_path(self, object_hash: str) -> Path:
        if not HEX64_RE.fullmatch(object_hash):
            raise RagError("invalid CAS object hash")
        return self.cas_dir / object_hash[:2] / object_hash

    def _store_object(self, data: bytes) -> str:
        object_hash = sha256(data)
        target = self._object_path(object_hash)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if sha256(target.read_bytes()) != object_hash:
                raise RagError("RAG CAS object hash conflict")
            return object_hash
        fd, staged = tempfile.mkstemp(prefix=".xnet-rag-", dir=target.parent)
        try:
            with os.fdopen(fd, "wb") as out:
                out.write(data)
                out.flush()
                os.fsync(out.fileno())
            if sha256(Path(staged).read_bytes()) != object_hash:
                raise RagError("staged RAG object hash mismatch")
            os.replace(staged, target)
        finally:
            if os.path.exists(staged):
                os.unlink(staged)
        return object_hash

    def _load_object(self, object_hash: str) -> bytes:
        data = self._object_path(object_hash).read_bytes()
        if sha256(data) != object_hash:
            raise RagError("RAG CAS object hash mismatch")
        return data

    @staticmethod
    def _validated_tags(tags: Sequence[str]) -> tuple[str, ...]:
        return tuple(sorted({_normalize_tag(tag) for tag in tags}))

    @staticmethod
    def _validate_lifetimes(fresh_for: int, retain_for: int) -> None:
        maximum = 10 * 366 * 86400
        if not 0 <= fresh_for <= maximum or not 1 <= retain_for <= maximum:
            raise RagPolicyError("freshness/retention must be bounded to ten years")
        if retain_for < fresh_for:
            raise RagPolicyError("retention may not end before freshness")

    def index_file(
        self,
        path: Path,
        *,
        root_alias: str,
        tags: Sequence[str] = (),
        permission_class: str = "private",
        fresh_for: int = 86400,
        retain_for: int = 30 * 86400,
    ) -> dict[str, Any]:
        path = Path(path)
        normalized_tags = self._validated_tags(tags)
        root, relative = self._validate_file_policy(path, normalized_tags)
        self._ensure_enabled("indexing")
        del root  # Absolute roots are deliberately not persisted.
        root_alias = _normalize_root_alias(root_alias)
        if permission_class not in PERMISSION_CLASSES:
            raise RagPolicyError("invalid RAG permission class")
        self._validate_lifetimes(fresh_for, retain_for)
        stat = path.stat()
        if not path.is_file() or stat.st_size > MAX_FILE_BYTES:
            raise RagPolicyError("RAG files must be regular files of at most 2 MiB")
        raw = path.read_bytes()
        final_stat = path.stat()
        if len(raw) != stat.st_size or final_stat.st_size != stat.st_size or final_stat.st_mtime_ns != stat.st_mtime_ns:
            raise RagError("file changed while being indexed")
        if b"\x00" in raw:
            raise RagPolicyError("binary content is excluded from the RAG corpus")
        if any(pattern.search(raw) for pattern in SECRET_PATTERNS):
            raise RagPolicyError("content appears to contain a secret/key/auth token")
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RagPolicyError("RAG text must be valid UTF-8") from exc
        if not text.strip():
            raise RagPolicyError("empty text is not indexed")

        source_hash = self._store_object(raw)
        alias = _normalize_source_alias(f"{root_alias}/{relative.as_posix()}")
        now = int(self.clock())
        chunks = _chunk_text(text)
        if not chunks:
            raise RagPolicyError("no indexable text chunks")

        chunk_rows: list[tuple[int, str, int, int, str, str]] = []
        for ordinal, (start_line, end_line, chunk_text) in enumerate(chunks):
            chunk_bytes = chunk_text.encode("utf-8")
            chunk_hash = self._store_object(chunk_bytes)
            vector_json = canonical(_semantic_vector(chunk_text)).decode("utf-8")
            chunk_rows.append((ordinal, chunk_hash, start_line, end_line, chunk_text, vector_json))

        with self._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute(
                "SELECT source_hash FROM rag_aliases WHERE source_path_alias=?", (alias,)
            ).fetchone()
            source_exists = db.execute(
                "SELECT 1 FROM rag_sources WHERE source_hash=?", (source_hash,)
            ).fetchone()
            db.execute(
                "INSERT OR IGNORE INTO rag_sources(source_hash,size,indexed_at) VALUES(?,?,?)",
                (source_hash, len(raw), now),
            )
            if not source_exists:
                for ordinal, chunk_hash, start_line, end_line, chunk_text, vector_json in chunk_rows:
                    db.execute(
                        "INSERT OR IGNORE INTO rag_chunks(chunk_hash,text,vector_json) VALUES(?,?,?)",
                        (chunk_hash, chunk_text, vector_json),
                    )
                    db.execute(
                        "INSERT INTO rag_source_chunks(source_hash,ordinal,chunk_hash,start_line,end_line) VALUES(?,?,?,?,?)",
                        (source_hash, ordinal, chunk_hash, start_line, end_line),
                    )
            db.execute(
                """INSERT INTO rag_aliases(source_path_alias,source_hash,mtime_ns,permission_class,freshness_until,retention_until,indexed_at)
                   VALUES(?,?,?,?,?,?,?)
                   ON CONFLICT(source_path_alias) DO UPDATE SET
                     source_hash=excluded.source_hash,mtime_ns=excluded.mtime_ns,
                     permission_class=excluded.permission_class,freshness_until=excluded.freshness_until,
                     retention_until=excluded.retention_until,indexed_at=excluded.indexed_at""",
                (alias, source_hash, stat.st_mtime_ns, permission_class, now + fresh_for, now + retain_for, now),
            )
            db.execute("DELETE FROM rag_tags WHERE source_path_alias=?", (alias,))
            db.executemany(
                "INSERT INTO rag_tags(source_path_alias,tag) VALUES(?,?)",
                [(alias, tag) for tag in normalized_tags],
            )
            db.execute("DELETE FROM rag_lexical WHERE source_path_alias=?", (alias,))
            if self._fts5:
                db.execute("DELETE FROM rag_fts WHERE source_path_alias=?", (alias,))
            indexed_chunks = db.execute(
                """SELECT sc.ordinal,sc.chunk_hash,c.text
                   FROM rag_source_chunks sc JOIN rag_chunks c ON c.chunk_hash=sc.chunk_hash
                   WHERE sc.source_hash=? ORDER BY sc.ordinal""",
                (source_hash,),
            ).fetchall()
            for row in indexed_chunks:
                values = (alias, source_hash, row["ordinal"], row["chunk_hash"], row["text"])
                db.execute("INSERT INTO rag_lexical VALUES(?,?,?,?,?)", values)
                if self._fts5:
                    db.execute("INSERT INTO rag_fts VALUES(?,?,?,?,?)", values)

        if previous and previous["source_hash"] == source_hash:
            status = "unchanged"
        elif source_exists:
            status = "aliased"
        else:
            status = "indexed"
        return self.describe_alias(alias) | {"status": status, "object_path": f"cas/sha256/{source_hash[:2]}/{source_hash}"}

    def describe_alias(self, source_path_alias: str) -> dict[str, Any]:
        alias = _normalize_source_alias(source_path_alias)
        with self._conn() as db:
            row = db.execute("SELECT * FROM rag_aliases WHERE source_path_alias=?", (alias,)).fetchone()
            if not row:
                raise RagError("RAG source alias not found")
            tags = [item["tag"] for item in db.execute("SELECT tag FROM rag_tags WHERE source_path_alias=? ORDER BY tag", (alias,))]
            chunks = [
                {
                    "ordinal": item["ordinal"],
                    "chunk_hash": item["chunk_hash"],
                    "start_line": item["start_line"],
                    "end_line": item["end_line"],
                }
                for item in db.execute(
                    "SELECT ordinal,chunk_hash,start_line,end_line FROM rag_source_chunks WHERE source_hash=? ORDER BY ordinal",
                    (row["source_hash"],),
                )
            ]
        return {
            "schema_version": CATALOG_SCHEMA,
            "source_path_alias": alias,
            "source_hash": row["source_hash"],
            "mtime_ns": row["mtime_ns"],
            "permission_class": row["permission_class"],
            "freshness_until": row["freshness_until"],
            "retention_until": row["retention_until"],
            "tags": tags,
            "chunks": chunks,
        }

    def aliases_for(self, source_hash: str) -> list[str]:
        if not HEX64_RE.fullmatch(source_hash):
            raise RagError("invalid source hash")
        with self._conn() as db:
            return [
                row["source_path_alias"]
                for row in db.execute(
                    "SELECT source_path_alias FROM rag_aliases WHERE source_hash=? ORDER BY source_path_alias",
                    (source_hash,),
                )
            ]

    def slice_sealed_source(
        self, source_path_alias: str, *, task_id: str, query: str,
        parent_seal: Mapping[str, Any], fetch_parent: Callable[[str], Mapping[str, Any]],
        max_bytes: int = 8192, chunk_bytes: int = 1600,
        required_ranges: Sequence[Sequence[int]] = (),
        permission_classes: Sequence[str] = ("public",),
    ) -> dict[str, Any]:
        """Slice one explicitly selected parent through a borrowed FETCH callback.

        Parent seal and task are supplied by the admitted caller. This verifies
        exact bytes, not browser completeness, scope authority or peer identity.
        No cleaning or newline normalization changes source offsets. Required
        title/release ranges are retained in full or the request fails closed.
        """
        self._ensure_enabled("sealed source slicing")
        if (type(task_id) is not str or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", task_id)
            or type(query) is not str or not query.strip() or len(query) > MAX_QUERY_CHARS):
            raise RagPolicyError("explicit bounded task and query required for source slicing")
        if (type(max_bytes) is not int or not 128 <= max_bytes <= 32768
            or type(chunk_bytes) is not int or not 32 <= chunk_bytes <= 8192):
            raise RagPolicyError("bounded byte budgets required for source slicing")
        fields = {"digest", "bytes", "receipt_seq", "receipt_hash"}
        if (not isinstance(parent_seal, Mapping) or set(parent_seal) != fields
            or any(type(parent_seal[key]) is not str or not HEX64_RE.fullmatch(parent_seal[key])
                   for key in ("digest", "receipt_hash"))
            or type(parent_seal["bytes"]) is not int or not 0 < parent_seal["bytes"] <= MAX_FILE_BYTES
            or type(parent_seal["receipt_seq"]) is not int or parent_seal["receipt_seq"] < 0):
            raise RagPolicyError("exact sealed parent digest, byte count and receipt required")
        if (type(permission_classes) not in (list, tuple) or not permission_classes
            or any(type(value) is not str or value not in PERMISSION_CLASSES for value in permission_classes)):
            raise RagPolicyError("explicit source permission classes required")
        permissions = sorted(set(permission_classes))
        source = self.describe_alias(source_path_alias)
        if (source["source_hash"] != parent_seal["digest"]
            or source["permission_class"] not in permissions):
            raise RagPolicyError("catalog alias does not match the authorized sealed parent")
        self._reject_benchmark_reference(tags=source["tags"])
        now = int(self.clock())
        if source["freshness_until"] <= now or source["retention_until"] <= now:
            raise RagPolicyError("sealed source alias is stale or expired")
        if not callable(fetch_parent):
            raise RagPolicyError("borrowed exact-parent FETCH callback required")
        fetched = fetch_parent(parent_seal["digest"])
        if (not isinstance(fetched, Mapping) or set(fetched) != {"digest", "text"}
            or fetched["digest"] != parent_seal["digest"] or type(fetched["text"]) is not str
            or len(fetched["text"]) > MAX_FILE_BYTES):
            raise RagError("FETCH did not return the exact declared sealed parent")
        try:
            raw = fetched["text"].encode("utf-8")
        except UnicodeError as exc:
            raise RagError("sealed parent is not exact valid UTF-8") from exc
        if (len(raw) != parent_seal["bytes"] or sha256(raw) != parent_seal["digest"]
            or raw != self._load_object(source["source_hash"])):
            raise RagError("fetched sealed parent bytes differ from digest, size or catalog CAS")
        required = _source_ranges(raw, required_ranges)
        chunks = _source_byte_chunks(raw, chunk_bytes)
        candidates, ranking = _rank_source_chunks(raw, chunks, query)
        order = sorted(candidates, key=lambda row: (-row["score"], row["ordinal"]))
        chosen = required
        if _source_rendered_size(len(raw), chosen) > max_bytes:
            raise RagPolicyError("mandatory title/release source ranges exceed slice byte budget")
        decisions = []
        for row in order:
            if row["score"] <= 0:
                decisions.append({"ordinal": row["ordinal"], "status": "no-lexical-match"})
                continue
            proposal = _merge_source_ranges([*chosen, [row["start_byte"], row["end_byte"]]])
            if len(proposal) > MAX_RETRIEVAL_RESULTS or _source_rendered_size(len(raw), proposal) > max_bytes:
                decisions.append({"ordinal": row["ordinal"], "status": "budget-omitted"})
                continue
            chosen = proposal
            decisions.append({"ordinal": row["ordinal"], "status": "included"})
        rendered, selected, omitted = _render_source_ranges(raw, chosen)
        body = {
            "schema_version": "xnet.rag-sealed-source-slice.v1", "task_id": task_id,
            "parent_seal": dict(parent_seal), "source": source, "query": query,
            "query_sha256": sha256(query.encode("utf-8")),
            "implementation_sha256": sha256(Path(__file__).read_bytes()),
            "config": {"max_bytes": max_bytes, "chunk_bytes": chunk_bytes,
                       "required_ranges": required, "permission_classes": permissions,
                       "range_units": "utf8-bytes-half-open", "cleaning": "none",
                       "ranking": "lexical-bm25-style-v1", "marker": "\n[...]\n"},
            "ranking": ranking, "candidates": candidates,
            "ranking_order": [row["ordinal"] for row in order], "decisions": decisions,
            "selected": selected, "omitted_ranges": omitted, "cleaned_ranges": [],
            "slice_text": rendered, "slice_bytes": len(rendered.encode("utf-8")),
            "slice_sha256": sha256(rendered.encode("utf-8")),
            "capture_completeness": "caller-declared-partial-or-unknown",
            "authority": "none", "work_performed": False,
        }
        return {**body, "receipt_sha256": digest(body)}

    def replay_sealed_source_slice(
        self, receipt: Mapping[str, Any], *, task_id: str, parent_seal: Mapping[str, Any],
        fetch_parent: Callable[[str], Mapping[str, Any]], expected_receipt_sha256: str,
    ) -> dict[str, Any]:
        """Recompute against external task/parent/receipt pins and current bytes."""
        self._ensure_enabled("sealed source slice replay")
        if (type(expected_receipt_sha256) is not str or not HEX64_RE.fullmatch(expected_receipt_sha256)
            or not isinstance(receipt, Mapping) or receipt.get("receipt_sha256") != expected_receipt_sha256):
            raise RagError("external source-slice receipt pin required")
        body = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if digest(body) != expected_receipt_sha256:
            raise RagError("source-slice receipt hash changed")
        if (receipt.get("schema_version") != "xnet.rag-sealed-source-slice.v1"
            or receipt.get("task_id") != task_id or receipt.get("parent_seal") != parent_seal
            or receipt.get("implementation_sha256") != sha256(Path(__file__).read_bytes())):
            raise RagError("source-slice task, parent or implementation changed")
        config = receipt.get("config")
        if not isinstance(config, Mapping):
            raise RagError("source-slice configuration missing")
        replay = self.slice_sealed_source(
            receipt["source"]["source_path_alias"], task_id=task_id, query=receipt["query"],
            parent_seal=parent_seal, fetch_parent=fetch_parent,
            max_bytes=config["max_bytes"], chunk_bytes=config["chunk_bytes"],
            required_ranges=config["required_ranges"], permission_classes=config["permission_classes"],
        )
        if canonical(replay) != canonical(receipt):
            raise RagError("source-slice ranking, ranges or exact excerpts changed on replay")
        return replay

    def _checkpoint(self, *, root_token: str, root_alias: str, processed: Mapping[str, str], completed: bool) -> str:
        body = {
            "schema_version": CHECKPOINT_SCHEMA,
            "root_token": root_token,
            "root_alias": root_alias,
            "processed": dict(sorted(processed.items())),
            "completed": completed,
        }
        return self._store_object(canonical(body))

    def _load_checkpoint(self, checkpoint_hash: str, *, root_token: str, root_alias: str) -> dict[str, Any]:
        try:
            body = json.loads(self._load_object(checkpoint_hash))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RagError("invalid RAG scan checkpoint") from exc
        required = {"schema_version", "root_token", "root_alias", "processed", "completed"}
        if set(body) != required or body["schema_version"] != CHECKPOINT_SCHEMA:
            raise RagError("unsupported RAG scan checkpoint")
        if body["root_token"] != root_token or body["root_alias"] != root_alias:
            raise RagPolicyError("checkpoint does not belong to this allowlisted scan")
        if not isinstance(body["processed"], dict) or any(
            not isinstance(alias, str) or not isinstance(value, str) or not HEX64_RE.fullmatch(value)
            for alias, value in body["processed"].items()
        ):
            raise RagError("invalid RAG checkpoint entries")
        return body

    def scan(
        self,
        path: Path,
        *,
        root_alias: str,
        tags: Sequence[str] = (),
        permission_class: str = "private",
        fresh_for: int = 86400,
        retain_for: int = 30 * 86400,
        resume_checkpoint: str | None = None,
        max_files: int = 256,
    ) -> dict[str, Any]:
        path = Path(path)
        normalized_tags = self._validated_tags(tags)
        root_alias = _normalize_root_alias(root_alias)
        if not 1 <= max_files <= MAX_SCAN_FILES:
            raise RagPolicyError(f"max_files must be 1..{MAX_SCAN_FILES}")
        root, relative = self._root_for(path)
        self._reject_benchmark_root(root)
        self._reject_benchmark_reference(relative, normalized_tags)
        self._ensure_enabled("indexing")
        if path.is_dir() and (path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())):
            raise RagPolicyError("linked scan paths are forbidden")
        root_token = digest({"root": os.path.normcase(str(root)), "scan": relative.as_posix()})
        processed: dict[str, str] = {}
        if resume_checkpoint:
            checkpoint = self._load_checkpoint(resume_checkpoint, root_token=root_token, root_alias=root_alias)
            processed.update(checkpoint["processed"])

        if path.is_file():
            candidates = [path.resolve(strict=True)]
        elif path.is_dir():
            candidates = sorted(
                (
                    candidate
                    for candidate in path.rglob("*")
                    if candidate.is_file() and candidate.suffix.casefold() in TEXT_EXTENSIONS
                ),
                key=lambda candidate: candidate.relative_to(root).as_posix().casefold(),
            )
            if len(candidates) > MAX_SCAN_FILES:
                raise RagPolicyError(f"scan exceeds the {MAX_SCAN_FILES}-file safety bound")
        else:
            raise RagPolicyError("scan target must be a file or directory")

        counts = {"indexed": 0, "aliased": 0, "unchanged": 0, "checkpoint_skipped": 0, "denied": 0}
        denials: list[dict[str, str]] = []
        attempted = 0
        complete = True
        for candidate in candidates:
            _, candidate_relative = self._root_for(candidate)
            alias = _normalize_source_alias(f"{root_alias}/{candidate_relative.as_posix()}")
            known_hash = processed.get(alias)
            if known_hash is None and attempted >= max_files:
                complete = False
                break
            stat = candidate.stat()
            raw_hash = (
                sha256(candidate.read_bytes())
                if stat.st_size <= MAX_FILE_BYTES
                else digest({"denied": "oversize", "size": stat.st_size, "mtime_ns": stat.st_mtime_ns})
            )
            if processed.get(alias) == raw_hash:
                counts["checkpoint_skipped"] += 1
                continue
            if attempted >= max_files:
                complete = False
                break
            attempted += 1
            try:
                record = self.index_file(
                    candidate,
                    root_alias=root_alias,
                    tags=normalized_tags,
                    permission_class=permission_class,
                    fresh_for=fresh_for,
                    retain_for=retain_for,
                )
                counts[record["status"]] += 1
                processed[alias] = record["source_hash"]
            except RagPolicyError as exc:
                counts["denied"] += 1
                processed[alias] = raw_hash
                denials.append({"source_path_alias": alias, "reason": str(exc)})

        checkpoint_hash = self._checkpoint(
            root_token=root_token, root_alias=root_alias, processed=processed, completed=complete
        )
        return {
            "root_alias": root_alias,
            "complete": complete,
            "checkpoint_hash": checkpoint_hash,
            "attempted": attempted,
            "counts": counts,
            "denials": denials[:20],
            "denials_omitted": max(0, len(denials) - 20),
        }

    @staticmethod
    def _lexical_score(query_tokens: Sequence[str], text: str) -> float:
        if not query_tokens:
            return 0.0
        text_tokens = _tokens(text)
        text_set = set(text_tokens)
        matched = sum(1 for token in set(query_tokens) if token in text_set)
        coverage = matched / len(set(query_tokens))
        phrase = " ".join(query_tokens) in " ".join(text_tokens)
        return min(1.0, coverage + (0.2 if phrase else 0.0))

    def retrieve(
        self,
        query: str,
        *,
        limit: int = 8,
        max_chars: int = 8_000,
        tags: Sequence[str] = (),
        permission_classes: Sequence[str] = ("private", "restricted"),
    ) -> dict[str, Any]:
        normalized_tags = self._validated_tags(tags)
        self._reject_benchmark_reference(tags=normalized_tags)
        self._ensure_enabled("retrieval")
        if not isinstance(query, str) or not query.strip() or len(query) > MAX_QUERY_CHARS:
            raise RagPolicyError(f"RAG query must be 1..{MAX_QUERY_CHARS} characters")
        if not 1 <= limit <= MAX_RETRIEVAL_RESULTS:
            raise RagPolicyError(f"RAG limit must be 1..{MAX_RETRIEVAL_RESULTS}")
        if not 128 <= max_chars <= MAX_RETRIEVAL_CHARS:
            raise RagPolicyError(f"RAG max_chars must be 128..{MAX_RETRIEVAL_CHARS}")
        permissions = tuple(sorted(set(permission_classes)))
        if not permissions or any(value not in PERMISSION_CLASSES for value in permissions):
            raise RagPolicyError("invalid retrieval permission classes")

        query_tokens = _tokens(query)[:24]
        if not query_tokens:
            raise RagPolicyError("RAG query contains no searchable tokens")
        query_vector = _semantic_vector(query)
        now = int(self.clock())
        candidates: dict[tuple[str, int], sqlite3.Row] = {}
        with self._conn() as db:
            if self._fts5:
                match = " AND ".join(f'"{token.replace(chr(34), chr(34) * 2)}"' for token in sorted(set(query_tokens)))
                try:
                    for row in db.execute(
                        "SELECT source_path_alias,source_hash,CAST(ordinal AS INTEGER) ordinal,chunk_hash,text FROM rag_fts WHERE rag_fts MATCH ? ORDER BY bm25(rag_fts),source_path_alias,ordinal LIMIT 256",
                        (match,),
                    ):
                        candidates[(row["source_path_alias"], int(row["ordinal"]))] = row
                except sqlite3.DatabaseError:
                    pass
            for row in db.execute(
                "SELECT source_path_alias,source_hash,ordinal,chunk_hash,text FROM rag_lexical ORDER BY source_path_alias,ordinal LIMIT ?",
                (MAX_SEMANTIC_CANDIDATES,),
            ):
                candidates[(row["source_path_alias"], int(row["ordinal"]))] = row

            scored: list[dict[str, Any]] = []
            for key in sorted(candidates):
                row = candidates[key]
                metadata = db.execute(
                    "SELECT * FROM rag_aliases WHERE source_path_alias=?", (row["source_path_alias"],)
                ).fetchone()
                if not metadata or metadata["retention_until"] < now or metadata["permission_class"] not in permissions:
                    continue
                alias_tags = [
                    item["tag"]
                    for item in db.execute(
                        "SELECT tag FROM rag_tags WHERE source_path_alias=? ORDER BY tag", (row["source_path_alias"],)
                    )
                ]
                if normalized_tags and not set(normalized_tags).issubset(alias_tags):
                    continue
                vector_row = db.execute(
                    "SELECT vector_json FROM rag_chunks WHERE chunk_hash=?", (row["chunk_hash"],)
                ).fetchone()
                lexical = self._lexical_score(query_tokens, row["text"])
                semantic = _cosine(query_vector, json.loads(vector_row["vector_json"]))
                if lexical <= 0.0 and semantic < 0.18:
                    continue
                fresh = metadata["freshness_until"] >= now
                score = min(1.0, lexical * 0.68 + semantic * 0.30 + (0.02 if fresh else 0.0))
                lines = db.execute(
                    "SELECT start_line,end_line FROM rag_source_chunks WHERE source_hash=? AND ordinal=?",
                    (row["source_hash"], row["ordinal"]),
                ).fetchone()
                scored.append(
                    {
                        "score": round(score, 6),
                        "lexical_score": round(lexical, 6),
                        "semantic_score": round(semantic, 6),
                        "text": row["text"],
                        "citation": {
                            "source_path_alias": row["source_path_alias"],
                            "source_hash": row["source_hash"],
                            "chunk_hash": row["chunk_hash"],
                            "start_line": lines["start_line"],
                            "end_line": lines["end_line"],
                            "mtime_ns": metadata["mtime_ns"],
                            "permission_class": metadata["permission_class"],
                            "freshness_until": metadata["freshness_until"],
                            "retention_until": metadata["retention_until"],
                            "fresh": fresh,
                            "tags": alias_tags,
                        },
                    }
                )

        scored.sort(
            key=lambda item: (
                -item["score"],
                item["citation"]["source_path_alias"],
                item["citation"]["start_line"],
                item["citation"]["chunk_hash"],
            )
        )
        selected: list[dict[str, Any]] = []
        used = 0
        for item in scored:
            if len(selected) >= limit or used >= max_chars:
                break
            remaining = max_chars - used
            excerpt = item["text"][:remaining]
            if not excerpt:
                break
            selected.append({**item, "text": excerpt, "excerpt_truncated": len(excerpt) < len(item["text"])})
            used += len(excerpt)
        response = {
            "query": query,
            "search": "fts5+deterministic-feature-hash" if self._fts5 else "exact-token-fallback+deterministic-feature-hash",
            "bounds": {"max_results": limit, "max_chars": max_chars, "used_chars": used},
            "results": selected,
            "omitted": max(0, len(scored) - len(selected)),
        }
        return {**response, "result_hash": digest(response)}

    def stats(self) -> dict[str, Any]:
        with self._conn() as db:
            return {
                "sources": db.execute("SELECT COUNT(*) FROM rag_sources").fetchone()[0],
                "aliases": db.execute("SELECT COUNT(*) FROM rag_aliases").fetchone()[0],
                "chunks": db.execute("SELECT COUNT(*) FROM rag_chunks").fetchone()[0],
                "predictions": db.execute("SELECT COUNT(*) FROM rag_predictions").fetchone()[0],
                "search": "fts5+deterministic-feature-hash" if self._fts5 else "exact-token-fallback+deterministic-feature-hash",
                "benchmark_firewall": self.benchmark_firewall,
            }


TASK_METADATA_FIELDS = frozenset(
    {"task_id", "objective", "current_step", "next_actions", "keywords", "allowed_tags", "permission_classes"}
)


class PredictiveRagQueue:
    """Short-lived context hypotheses derived only from explicit task fields."""

    def __init__(self, catalog: RagCatalog, *, minimum_confidence: float = 0.35):
        if not 0.0 <= minimum_confidence <= 1.0:
            raise RagPolicyError("prediction confidence threshold must be in 0..1")
        self.catalog = catalog
        self.minimum_confidence = minimum_confidence

    @staticmethod
    def _task_metadata(metadata: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(metadata, Mapping) or set(metadata) - TASK_METADATA_FIELDS:
            raise RagPolicyError("prediction metadata contains non-explicit fields")
        required = {"task_id", "objective"}
        if not required.issubset(metadata):
            raise RagPolicyError("prediction metadata requires task_id and objective")
        task_id = metadata["task_id"]
        objective = metadata["objective"]
        if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", task_id):
            raise RagPolicyError("invalid prediction task_id")
        if not isinstance(objective, str) or not 1 <= len(objective) <= MAX_QUERY_CHARS:
            raise RagPolicyError("invalid prediction objective")
        current_step = metadata.get("current_step", "")
        next_actions = metadata.get("next_actions", [])
        keywords = metadata.get("keywords", [])
        allowed_tags = metadata.get("allowed_tags", [])
        permissions = metadata.get("permission_classes", ["private", "restricted"])
        if not isinstance(current_step, str) or len(current_step) > MAX_QUERY_CHARS:
            raise RagPolicyError("invalid prediction current_step")
        for name, value, bound in (
            ("next_actions", next_actions, 8),
            ("keywords", keywords, 16),
            ("allowed_tags", allowed_tags, 16),
            ("permission_classes", permissions, 3),
        ):
            if not isinstance(value, list) or len(value) > bound or any(not isinstance(item, str) for item in value):
                raise RagPolicyError(f"invalid prediction {name}")
        if any(pattern.search(canonical(dict(metadata))) for pattern in SECRET_PATTERNS):
            raise RagPolicyError("prediction metadata appears to contain a secret/key/auth token")
        return {
            "task_id": task_id,
            "objective": objective,
            "current_step": current_step,
            "next_actions": next_actions,
            "keywords": keywords,
            "allowed_tags": allowed_tags,
            "permission_classes": permissions,
        }

    @staticmethod
    def _needs(metadata: Mapping[str, Any]) -> list[str]:
        values = [*metadata["next_actions"]]
        if metadata["current_step"]:
            values.append(metadata["current_step"])
        if metadata["keywords"]:
            values.append(" ".join(metadata["keywords"]))
        values.append(metadata["objective"])
        seen: set[str] = set()
        return [value for value in values if value.strip() and not (value.casefold() in seen or seen.add(value.casefold()))]

    @staticmethod
    def _record_without_payload(row: sqlite3.Row) -> dict[str, Any]:
        return json.loads(row["record_json"])

    @staticmethod
    def _validate_record(record: Mapping[str, Any], payload: Mapping[str, Any] | None = None) -> dict[str, Any]:
        fields = {
            "schema_version", "hypothesis_id", "task_id", "role", "information_need", "confidence",
            "source_hashes", "chunk_hashes", "context_hash", "created_at", "expires_at", "ttl_seconds",
            "budget", "status", "citations", "routing_envelope",
        }
        if not isinstance(record, Mapping) or set(record) != fields or record["schema_version"] != PREDICTION_SCHEMA:
            raise RagError("invalid predictive RAG record")
        if record["role"] != "scout" or record["status"] != "prefetched":
            raise RagError("predictive RAG role or status is contradictory")
        if not re.fullmatch(r"[0-9a-f]{32}", record["hypothesis_id"]) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", record["task_id"]):
            raise RagError("invalid predictive RAG identity")
        unsigned_record = {key: value for key, value in record.items() if key != "hypothesis_id"}
        if digest(unsigned_record)[:32] != record["hypothesis_id"]:
            raise RagError("predictive RAG record hash mismatch")
        if not isinstance(record["confidence"], (int, float)) or not 0.0 <= record["confidence"] <= 1.0:
            raise RagError("invalid predictive RAG confidence")
        for name in ("source_hashes", "chunk_hashes"):
            values = record[name]
            if not isinstance(values, list) or not values or values != sorted(set(values)) or any(not HEX64_RE.fullmatch(value) for value in values):
                raise RagError(f"invalid predictive RAG {name}")
        citation_fields = {
            "source_path_alias", "source_hash", "chunk_hash", "start_line", "end_line", "mtime_ns",
            "permission_class", "freshness_until", "retention_until", "fresh", "tags",
        }
        if (
            not isinstance(record["citations"], list)
            or not record["citations"]
            or any(not isinstance(item, Mapping) or set(item) != citation_fields for item in record["citations"])
            or sorted({item["source_hash"] for item in record["citations"]}) != record["source_hashes"]
            or sorted({item["chunk_hash"] for item in record["citations"]}) != record["chunk_hashes"]
        ):
            raise RagError("predictive RAG citations are invalid")
        if not HEX64_RE.fullmatch(record["context_hash"]):
            raise RagError("invalid predictive RAG context hash")
        if (
            not isinstance(record["created_at"], int)
            or not isinstance(record["ttl_seconds"], int)
            or not 30 <= record["ttl_seconds"] <= 86400
            or record["expires_at"] != record["created_at"] + record["ttl_seconds"]
        ):
            raise RagError("predictive RAG TTL is contradictory")
        if (
            not isinstance(record["budget"], Mapping)
            or set(record["budget"]) != {"max_chars", "used_chars"}
            or not isinstance(record["budget"]["max_chars"], int)
            or not isinstance(record["budget"]["used_chars"], int)
            or not 0 <= record["budget"]["used_chars"] <= record["budget"]["max_chars"]
        ):
            raise RagError("predictive RAG budget is contradictory")
        envelope = validate_routing_envelope(record["routing_envelope"])
        if (
            envelope["who"] != {"worker": "rag-scout", "role": "scout"}
            or envelope["what"] != {"task_id": record["task_id"], "artifact": "prefetched-context", "artifact_hash": record["context_hash"]}
            or envelope["when"]["timestamp"] != record["created_at"]
            or envelope["when"]["deadline"] != record["expires_at"]
            or envelope["why"]["evidence_hashes"] != record["source_hashes"]
            or envelope["how"]["allowlisted_tools"]
            or envelope["how"]["budget"]["maximum"] != record["budget"]["max_chars"]
            or envelope["how"]["budget"]["used"] != record["budget"]["used_chars"]
        ):
            raise RagError("predictive RAG routing envelope contradicts its record")
        if payload is not None:
            if not isinstance(payload, Mapping) or payload.get("result_hash") != record["context_hash"]:
                raise RagError("predictive RAG payload hash is missing")
            unsigned_payload = {key: value for key, value in payload.items() if key != "result_hash"}
            if digest(unsigned_payload) != record["context_hash"]:
                raise RagError("predictive RAG payload hash mismatch")
            results = payload.get("results")
            if not isinstance(results, list) or [item.get("citation") for item in results] != record["citations"]:
                raise RagError("predictive RAG citations contradict the prefetched payload")
        return dict(record)

    def prefetch(
        self,
        task_metadata: Mapping[str, Any],
        *,
        role: str = "scout",
        max_items: int = 3,
        ttl_seconds: int = 900,
        budget_chars: int = 4_000,
    ) -> list[dict[str, Any]]:
        require_worker_action(role, "prefetch")
        metadata = self._task_metadata(task_metadata)
        tags = self.catalog._validated_tags(metadata["allowed_tags"])
        self.catalog._reject_benchmark_reference(tags=tags)
        self.catalog._ensure_enabled("prediction")
        if not 1 <= max_items <= 8 or not 30 <= ttl_seconds <= 86400 or not 128 <= budget_chars <= 8000:
            raise RagPolicyError("prediction item, TTL, or character budget is outside its bound")
        now = int(self.catalog.clock())
        self.expire(now=now)
        created: list[dict[str, Any]] = []
        with self.catalog._conn() as db:
            sequence_base = db.execute("SELECT COUNT(*) FROM rag_predictions WHERE task_id=?", (metadata["task_id"],)).fetchone()[0]
        for need_index, need in enumerate(self._needs(metadata)):
            if len(created) >= max_items:
                break
            retrieved = self.catalog.retrieve(
                need,
                limit=3,
                max_chars=budget_chars,
                tags=tags,
                permission_classes=metadata["permission_classes"],
            )
            if not retrieved["results"]:
                continue
            top_score = retrieved["results"][0]["score"]
            confidence = round(min(0.99, 0.3 + top_score * 0.62 + max(0, 0.04 - need_index * 0.01)), 6)
            if confidence < self.minimum_confidence:
                continue
            source_hashes = sorted({item["citation"]["source_hash"] for item in retrieved["results"]})
            chunk_hashes = sorted({item["citation"]["chunk_hash"] for item in retrieved["results"]})
            context_hash = retrieved["result_hash"]
            sequence = sequence_base + len(created) + 1
            expires_at = now + ttl_seconds
            citations = [item["citation"] for item in retrieved["results"]]
            envelope = routing_envelope(
                worker="rag-scout", role="scout", task_id=metadata["task_id"],
                artifact="prefetched-context", artifact_hash=context_hash,
                source_silo="local-rag-catalog", destination_silo="disposable-prediction-queue",
                sequence=sequence, timestamp=now, ttl_seconds=ttl_seconds,
                policy="explicit-task-metadata-only", rationale=need,
                evidence_hashes=source_hashes, allowlisted_tools=[], budget_unit="characters",
                budget_maximum=budget_chars, budget_used=retrieved["bounds"]["used_chars"],
            )
            record_body = {
                "schema_version": PREDICTION_SCHEMA,
                "task_id": metadata["task_id"],
                "role": "scout",
                "information_need": need,
                "confidence": confidence,
                "source_hashes": source_hashes,
                "chunk_hashes": chunk_hashes,
                "context_hash": context_hash,
                "created_at": now,
                "expires_at": expires_at,
                "ttl_seconds": ttl_seconds,
                "budget": {"max_chars": budget_chars, "used_chars": retrieved["bounds"]["used_chars"]},
                "status": "prefetched",
                "citations": citations,
                "routing_envelope": envelope,
            }
            hypothesis_id = digest(record_body)[:32]
            record = {**record_body, "hypothesis_id": hypothesis_id}
            with self.catalog._conn() as db:
                db.execute(
                    "INSERT OR REPLACE INTO rag_predictions(hypothesis_id,task_id,confidence,created_at,expires_at,record_json,payload_json) VALUES(?,?,?,?,?,?,?)",
                    (
                        hypothesis_id,
                        metadata["task_id"],
                        confidence,
                        now,
                        expires_at,
                        canonical(record).decode("utf-8"),
                        canonical(retrieved).decode("utf-8"),
                    ),
                )
            created.append(record)
        return created

    def list(self, task_id: str) -> list[dict[str, Any]]:
        self.catalog._ensure_enabled("prediction listing")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", task_id):
            raise RagPolicyError("invalid prediction task_id")
        self.expire()
        with self.catalog._conn() as db:
            rows = db.execute(
                "SELECT * FROM rag_predictions WHERE task_id=? ORDER BY confidence DESC,created_at,hypothesis_id",
                (task_id,),
            ).fetchall()
        return [self._validate_record(self._record_without_payload(row)) for row in rows]

    def consume(self, task_id: str, hypothesis_id: str, *, role: str = "solver") -> dict[str, Any]:
        require_worker_action(role, "consume")
        self.catalog._ensure_enabled("prediction consumption")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", task_id) or not re.fullmatch(r"[0-9a-f]{32}", hypothesis_id):
            raise RagPolicyError("invalid prediction consumption identity")
        now = int(self.catalog.clock())
        with self.catalog._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM rag_predictions WHERE hypothesis_id=?", (hypothesis_id,)).fetchone()
            if not row or row["task_id"] != task_id:
                raise RagPolicyError("prediction must be explicitly consumed by its bound task")
            if row["expires_at"] <= now or row["confidence"] < self.minimum_confidence:
                db.execute("DELETE FROM rag_predictions WHERE hypothesis_id=?", (hypothesis_id,))
                raise RagPolicyError("prediction is stale or below the confidence threshold")
            record = json.loads(row["record_json"])
            payload = json.loads(row["payload_json"])
            self._validate_record(record, payload)
            if row["confidence"] != record["confidence"] or row["expires_at"] != record["expires_at"]:
                raise RagError("predictive RAG queue index contradicts its record")
            context = payload["results"]
            db.execute("DELETE FROM rag_predictions WHERE hypothesis_id=?", (hypothesis_id,))
        return {
            **record,
            "status": "consumed",
            "consumed_by": {"task_id": task_id, "role": "solver", "explicit": True, "consumed_at": now},
            "context": context,
        }

    def expire(self, *, now: int | None = None) -> dict[str, int]:
        timestamp = int(self.catalog.clock()) if now is None else int(now)
        with self.catalog._conn() as db:
            db.execute("BEGIN IMMEDIATE")
            stale = db.execute("DELETE FROM rag_predictions WHERE expires_at <= ?", (timestamp,)).rowcount
            low = db.execute("DELETE FROM rag_predictions WHERE confidence < ?", (self.minimum_confidence,)).rowcount
        return {"stale": stale, "low_confidence": low, "expired": stale + low}
