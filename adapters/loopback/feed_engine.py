"""Bounded public practice feed. No model calls, credentials, or evaluator inputs.

SPDX-License-Identifier: MIT
Own control code is MIT; upstream payloads retain their upstream licenses.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import datetime as dt
import email.utils
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import urllib.parse
import uuid

HERE = Path(__file__).resolve().parent
REPOS = ("tokio-rs/tokio", "golang/go", "ziglang/zig", "JuliaLang/julia", "python/cpython")
HEX = re.compile(r"[0-9a-f]{40}")
SOURCE_FILES = ("feed_engine.py", "feed_control.ps1", "schedule_feed.ps1")
MAX_REQUESTS = 16
MAX_BODY = 2 * 1024 * 1024
REQUEST_SECONDS = 15
CYCLE_SECONDS = 240
INTERVAL = 3600
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_PATCH = 4096
MAX_PROJECTED_FILES = 32
API_VERSION = "2022-11-28"
PUBLIC_CLASS = "practice-stream"
CREDENTIAL_SHAPES = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[A-Z0-9]{16}\b"),
    re.compile(r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token)[\"']?\s*[:=]\s*[\"'][A-Za-z0-9_./+=-]{20,}[\"']"),
)


class Refused(ValueError):
    pass


class Busy(Refused):
    pass


class Quota(Refused):
    pass


class ClockAnomaly(Refused):
    pass


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def utc(timestamp):
    return dt.datetime.fromtimestamp(timestamp, dt.timezone.utc).isoformat()


def read_json(path):
    return json.loads(Path(path).read_bytes())


def atomic_json(path, value):
    """Mutable C control snapshots only; archive files use exclusive sealing."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with tmp.open("xb") as stream:
        stream.write(encode(value)); stream.flush(); os.fsync(stream.fileno())
    tmp.replace(path)


def safe_relative(name):
    if not isinstance(name, str) or len(name) > 256 or not name or "\\" in name or ":" in name or "\x00" in name:
        raise Refused("relative path refused")
    parts = name.split("/")
    if any(not p or p in {".", ".."} or any(ord(c) < 32 for c in p) for p in parts):
        raise Refused("relative path components refused")
    return parts


def safe_child(root, name):
    root = Path(root)
    parts = safe_relative(name)
    child = root.joinpath(*parts)
    cursor = root
    for part in parts:
        cursor = cursor / part
        if cursor.is_symlink() or getattr(cursor, "is_junction", lambda: False)():
            raise Refused("linked feed path refused")
    if not child.resolve().is_relative_to(root.resolve()):
        raise Refused("feed path escaped its explicit root")
    return child


def source_pins():
    return {name: digest((HERE / name).read_bytes()) for name in SOURCE_FILES}


def default_config(control_root, archive_root, proton_root=None, google_root=None):
    return {"schema": "xnet.public-code-feed.config.v1", "control_root": str(Path(control_root).resolve()),
            "archive_root": str(Path(archive_root).resolve()),
            "mirrors": {name: str(Path(path).resolve()) for name,path in
                        (("proton",proton_root),("google",google_root)) if path is not None},
            "repos": list(REPOS), "source_pins": source_pins(),
            "limits": {"requests_per_hour": MAX_REQUESTS, "body_bytes": MAX_BODY,
                       "request_seconds": REQUEST_SECONDS, "cycle_seconds": CYCLE_SECONDS,
                       "interval_seconds": INTERVAL, "archive_bytes": MAX_ARCHIVE,
                       "patch_bytes": MAX_PATCH, "files_per_commit": MAX_PROJECTED_FILES}}


def validate_config(value, *, installed=True):
    expected = {"schema", "control_root", "archive_root", "mirrors", "repos", "source_pins", "limits"}
    if not isinstance(value, dict) or set(value) != expected or value["schema"] != "xnet.public-code-feed.config.v1":
        raise Refused("config schema differs")
    if value["repos"] != list(REPOS):
        raise Refused("anonymous public repository allowlist differs")
    limits = value["limits"]
    exact = {"requests_per_hour": MAX_REQUESTS, "body_bytes": MAX_BODY,
             "request_seconds": REQUEST_SECONDS, "cycle_seconds": CYCLE_SECONDS,
             "interval_seconds": INTERVAL, "archive_bytes": MAX_ARCHIVE,
             "patch_bytes": MAX_PATCH, "files_per_commit": MAX_PROJECTED_FILES}
    if limits != exact or any(type(v) is not int for v in limits.values()):
        raise Refused("fixed acquisition limits differ")
    if not isinstance(value["mirrors"], dict) or not set(value["mirrors"]).issubset({"proton", "google"}):
        raise Refused("only optional Proton/Google cloud tier names allowed")
    paths = [value["control_root"], value["archive_root"], *value["mirrors"].values()]
    if not all(isinstance(p, str) and Path(p).is_absolute() and not any(ord(c) < 32 for c in p) for p in paths):
        raise Refused("explicit absolute tier paths required")
    resolved = [Path(p).resolve() for p in paths]
    if any(a == b or a.is_relative_to(b) or b.is_relative_to(a) for i, a in enumerate(resolved) for b in resolved[i+1:]):
        raise Refused("feed tiers must be distinct nonnested roots")
    if installed:
        if value["source_pins"] != source_pins():
            raise Refused("feed source changed; make a new reviewed generation")
    return value


@contextmanager
def lease(path):
    """One writer; OS releases the lease on exit/crash. Never delete the inode."""
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as stream:
        # Windows locks prevent even reading the locked byte through a second
        # handle. Metadata size is sufficient to initialize a new lock file.
        if path.stat().st_size == 0:
            stream.write(b"0"); stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (OSError, BlockingIOError) as exc:
            raise Busy("another feed writer owns this control root") from exc
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_UN)


class Clock:
    def __init__(self, wall=time.time, mono=time.monotonic):
        self.wall, self.mono = wall, mono
        self.anchor_wall, self.anchor_mono = wall(), mono()

    def check(self):
        current_wall, current_mono = self.wall(), self.mono()
        if current_mono < self.anchor_mono or abs(current_wall - (self.anchor_wall + current_mono-self.anchor_mono)) > 5:
            raise ClockAnomaly("UTC/monotonic anchor changed; acquisition held")
        return current_wall, current_mono


def allowed_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.github.com" or parsed.port not in {None, 443} or \
            parsed.username or parsed.password or parsed.fragment:
        raise Refused("only anonymous HTTPS api.github.com is allowed")
    for repo in REPOS:
        base = "/repos/" + repo + "/commits"
        if parsed.path == base and parsed.query == "per_page=1":
            return
        if parsed.path.startswith(base+"/") and HEX.fullmatch(parsed.path[len(base)+1:]) and not parsed.query:
            return
    raise Refused("GitHub path or query not allowlisted")


def public_http(url, timeout, clock, deadline):
    """No environment proxy, token, cookie jar, authentication, or retry."""
    allowed_url(url)
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path + ("?" + parsed.query if parsed.query else "")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": API_VERSION,
               "User-Agent": "XNET-public-practice-feed-r01"}
    # http.client uses direct TLS and never reads proxy/auth environment variables.
    connection = http.client.HTTPSConnection("api.github.com", timeout=min(timeout, deadline-clock.mono()))
    try:
        connection.request("GET", path, headers=headers)
        socket = connection.sock
        socket.settimeout(max(.001, deadline-clock.mono()))
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise Refused("redirect refused; no host or credential forwarding")
        chunks, used = [], 0
        while True:
            clock.check()
            if clock.mono() >= deadline:
                raise TimeoutError("monotonic request deadline reached")
            socket.settimeout(max(.001, deadline-clock.mono()))
            block = response.read1(min(65536, MAX_BODY+1-used))
            if not block:
                break
            used += len(block)
            if used > MAX_BODY:
                raise Refused("public API body exceeds 2 MiB cap")
            chunks.append(block)
        filtered = {name.lower(): response.headers[name] for name in
            ("Retry-After", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Date", "ETag")
            if name in response.headers}
        return int(response.status), filtered, b"".join(chunks)
    finally:
        connection.close()


def language(path):
    return {".rs":"rust", ".go":"go", ".zig":"zig", ".jl":"julia", ".py":"python",
            ".c":"c", ".h":"c", ".cpp":"cpp", ".md":"markdown"}.get(Path(path).suffix.lower(), "text")


def clipped_utf8(text, cap):
    data = text.encode("utf-8")
    return data[:cap].decode("utf-8", "ignore").encode("utf-8"), len(data) > cap


def credential_shaped(body, parsed):
    # Conservative shapes, not a claim of perfect secret detection. No token
    # environment is read. False positives are held locally for human review.
    strings=[body.decode("utf-8","replace")]
    pending=[parsed]
    while pending:
        value=pending.pop()
        if isinstance(value,str): strings.append(value)
        elif isinstance(value,dict): pending.extend(value.values())
        elif isinstance(value,list): pending.extend(value)
    return any(pattern.search(text) for text in strings for pattern in CREDENTIAL_SHAPES)


@dataclass
class Feed:
    config: dict
    clock: Clock | None = None
    transport: object = public_http
    installed: bool = True

    def __post_init__(self):
        validate_config(self.config, installed=self.installed)
        self.clock = self.clock or Clock()
        self.control = Path(self.config["control_root"])
        self.archive = Path(self.config["archive_root"])
        self.control.mkdir(parents=True, exist_ok=True)
        # No drive/mount is created: an absent archive parent remains unavailable.
        if not self.archive.parent.is_dir():
            raise Refused("explicit D archive parent is unavailable")
        self.archive.mkdir(exist_ok=True)
        if self.archive.is_symlink() or getattr(self.archive,"is_junction",lambda:False)():
            raise Refused("archive root link refused")
        identity = {"schema":"xnet.public-code-feed.root.v1", "config_sha256":digest(encode(self.config)),
                    "provenance_class":PUBLIC_CLASS, "authority":"none", "source_pins":self.config["source_pins"]}
        marker = self.archive/"feed-root.json"
        if marker.exists():
            if marker.read_bytes() != encode(identity):
                raise Refused("archive identity differs; never overwrite another root")
        else:
            if any(self.archive.iterdir()):
                raise Refused("unidentified nonempty archive root refused")
            with marker.open("xb") as stream:
                stream.write(encode(identity)); stream.flush(); os.fsync(stream.fileno())
        self.db = sqlite3.connect(self.control/"feed-state.sqlite", timeout=2)
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS cursors(repo TEXT PRIMARY KEY,commit_sha TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,started REAL NOT NULL,url TEXT NOT NULL,outcome TEXT);
          CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY,sha256 TEXT NOT NULL,bytes INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY,previous TEXT NOT NULL,payload BLOB NOT NULL,hash TEXT NOT NULL UNIQUE);
          CREATE TABLE IF NOT EXISTS projections(source_id TEXT PRIMARY KEY,descriptor BLOB NOT NULL);
        """)
        self._set_once("config_sha256", digest(encode(self.config)))
        self._set_once("source_pins", self.config["source_pins"])
        # Count only this owned archive, including incomplete/orphan bytes.
        self.used = 0; self.physical = {}
        for path in self.archive.rglob("*"):
            if path.is_symlink() or getattr(path,"is_junction",lambda:False)():
                raise Refused("archive contains a link")
            if path.is_file():
                relative = path.relative_to(self.archive).as_posix(); self.physical[relative]=path.stat().st_size
                self.used += path.stat().st_size
            if len(self.physical)>100000:
                raise Quota("archive file count cap reached")
        if self.used > MAX_ARCHIVE:
            raise Quota("archive quota exceeded; no acquisition or automatic pruning")
        self._register_existing("feed-root.json", encode(identity))
        try:
            self.verify()
        except BaseException:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def _get(self, key, default=None):
        row=self.db.execute("SELECT value FROM state WHERE key=?",(key,)).fetchone()
        return json.loads(row[0]) if row else default

    def _set(self, key, value):
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO state VALUES (?,?)",(key,encode(value).decode()))

    def _set_once(self, key, value):
        old=self._get(key)
        if old is not None and old != value:
            raise Refused("C metadata source/config pin drift")
        self._set(key,value)

    def _register_existing(self, relative, data):
        h=digest(data); existing=self.db.execute("SELECT sha256,bytes FROM files WHERE path=?",(relative,)).fetchone()
        if existing and existing != (h,len(data)):
            raise Refused("sealed archive identity drift")
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO files VALUES (?,?,?)",(relative,h,len(data)))
        return h

    def seal(self, relative, data):
        if not isinstance(data,bytes): raise TypeError("seal requires exact bytes")
        path=safe_child(self.archive,relative); h=digest(data)
        if path.exists():
            if not path.is_file() or path.stat().st_size != len(data) or digest(path.read_bytes()) != h:
                raise Refused("existing sealed bytes differ; no overwrite/heal")
        else:
            if self.used+len(data)>MAX_ARCHIVE:
                raise Quota("archive quota reached; acquisition held")
            path.parent.mkdir(parents=True,exist_ok=True)
            with path.open("xb") as stream:
                stream.write(data); stream.flush(); os.fsync(stream.fileno())
            self.used += len(data); self.physical[relative]=len(data)
        return self._register_existing(relative,data)

    def event(self, kind, value):
        old=self.db.execute("SELECT seq,hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        seq,prev=(old[0]+1,old[1]) if old else (1,"0"*64)
        payload=encode({"kind":kind,"value":value})
        h=digest(encode({"seq":seq,"previous":prev,"payload_sha256":digest(payload)}))
        record={"schema":"xnet.public-code-feed.event.v1","seq":seq,"previous":prev,
                "payload":json.loads(payload),"hash":h}
        relative=f"receipts/events/{seq:08d}-{h}.json"
        self.seal(relative,encode(record))
        with self.db:
            self.db.execute("INSERT INTO events VALUES (?,?,?,?)",(seq,prev,payload,h))
        return h

    def verify(self):
        prev="0"*64; n=0
        for seq,previous,payload,h in self.db.execute("SELECT * FROM events ORDER BY seq"):
            n+=1
            if seq!=n or previous!=prev or h!=digest(encode({"seq":seq,"previous":prev,"payload_sha256":digest(payload)})):
                raise Refused("feed receipt hash chain differs")
            path=safe_child(self.archive,f"receipts/events/{seq:08d}-{h}.json")
            expected={"schema":"xnet.public-code-feed.event.v1","seq":seq,"previous":prev,
                      "payload":json.loads(payload),"hash":h}
            if not path.is_file() or path.read_bytes()!=encode(expected):
                raise Refused("archive event differs from C metadata chain")
            prev=h
        for relative,h,size in self.db.execute("SELECT * FROM files"):
            path=safe_child(self.archive,relative)
            if not path.is_file() or path.stat().st_size!=size or digest(path.read_bytes())!=h:
                raise Refused("owned archive bytes differ from sealed manifest")
        return {"events":n,"head":prev,"sealed_files":self.db.execute("SELECT COUNT(*) FROM files").fetchone()[0]}

    def _clock(self):
        try:
            wall,mono=self.clock.check()
            if wall < self._get("last_wall",wall)-5:
                raise ClockAnomaly("UTC precedes prior durable checkpoint; acquisition held")
            return wall,mono
        except ClockAnomaly as exc:
            self.event("clock-anomaly",{"utc_observed":utc(self.clock.wall()),"reason":str(exc),
                "acquisition":"held","time_authority":"local UTC plus monotonic anchor; not trusted consensus"})
            raise

    def request(self,url,cycle_deadline):
        allowed_url(url); wall,mono=self._clock()
        if mono>=cycle_deadline: raise TimeoutError("cycle monotonic deadline reached")
        hold=self._get("http_hold_until",0)
        if wall<hold: raise Refused("API rate/retry hold remains active")
        count=self.db.execute("SELECT COUNT(*) FROM requests WHERE started>?",(wall-INTERVAL,)).fetchone()[0]
        if count>=MAX_REQUESTS: raise Refused("16 requests per rolling UTC hour exhausted")
        with self.db:
            cur=self.db.execute("INSERT INTO requests(started,url) VALUES (?,?)",(wall,url)); request_id=cur.lastrowid
        deadline=min(cycle_deadline,mono+REQUEST_SECONDS)
        try:
            status,headers,body=self.transport(url,min(REQUEST_SECONDS,deadline-mono),self.clock,deadline)
            self._clock()
            if self.clock.mono()>deadline: raise TimeoutError("transport returned after monotonic deadline")
            if type(status)is not int or not isinstance(headers,dict) or not isinstance(body,bytes) or len(body)>MAX_BODY:
                raise Refused("API transport response shape/cap refused")
            # Only exact public JSON responses enter the archive.
            parsed=json.loads(body)
            if credential_shaped(body,parsed):
                blobsha=self.seal(f"quarantine/blobs/{digest(body)}.json",body)
                self.event("credential-shape-quarantined",{"request_id":request_id,"url":url,
                    "source_blob_sha256":blobsha,"bytes":len(body),"policy":"local-only; no projection or mirror",
                    "detector":"conservative credential shapes; human review required"})
                raise Refused("credential-shaped public response quarantined locally; not mirrored")
            blobsha=self.seal(f"blobs/{digest(body)}.json",body)
            filtered={k.lower():str(v)[:256] for k,v in headers.items() if k.lower() in
                {"retry-after","x-ratelimit-remaining","x-ratelimit-reset","date","etag"}}
            self.event("http-response",{"request_id":request_id,"url":url,"status":status,
                "source_blob_sha256":blobsha,"bytes":len(body),"headers":filtered,
                "utc":utc(wall),"provenance_class":PUBLIC_CLASS,"credentials":"none",
                "redirects":"refused","proxy":"disabled"})
            with self.db: self.db.execute("UPDATE requests SET outcome=? WHERE id=?",(str(status),request_id))
            if status in {403,429} or filtered.get("x-ratelimit-remaining")=="0":
                until=wall+INTERVAL
                reset=filtered.get("x-ratelimit-reset")
                if reset and re.fullmatch(r"\d{1,10}",reset): until=max(until,int(reset))
                retry=filtered.get("retry-after")
                if retry:
                    if re.fullmatch(r"\d{1,10}",retry): until=max(until,wall+int(retry))
                    else:
                        try: until=max(until,email.utils.parsedate_to_datetime(retry).timestamp())
                        except (TypeError,ValueError,OverflowError): pass
                self._set("http_hold_until",until)
                self.event("rate-hold",{"until_utc":utc(until),"status":status,"retry":"no automatic retry"})
            return status,parsed,blobsha
        except Exception as exc:
            with self.db: self.db.execute("UPDATE requests SET outcome=? WHERE id=?",("held:"+type(exc).__name__,request_id))
            self.event("http-failure",{"request_id":request_id,"url":url,"error_type":type(exc).__name__,
                "reason":str(exc)[:256],"automatic_retry":False})
            raise

    def ingest_commit(self,repo,sha,body,blobsha):
        if repo not in REPOS or not HEX.fullmatch(sha) or not isinstance(body,dict) or body.get("sha")!=sha:
            raise Refused("immutable commit identity differs")
        files=body.get("files",[])
        if not isinstance(files,list): raise Refused("public commit files shape refused")
        intake={"schema":"xnet.public-code-feed.intake.v1","repo":repo,"commit":sha,
                "source_url":f"https://api.github.com/repos/{repo}/commits/{sha}",
                "source_blob_sha256":blobsha,"provenance_class":PUBLIC_CLASS,"authority":"none",
                "upstream_license_retained":True,"license_notice":"Payloads retain upstream repository licenses; consult its LICENSE files.",
                "files_reported":len(files),"files_projection_cap":MAX_PROJECTED_FILES,
                "file_inventory_complete":False,"before_after_full_source":False}
        receipt_relative=f"receipts/intakes/{repo.replace('/','--')}-{sha}.json"
        receiptsha=self.seal(receipt_relative,encode(intake)); projected=[]; omitted=[]
        for row in files[:MAX_PROJECTED_FILES]:
            if not isinstance(row,dict) or not isinstance(row.get("filename"),str):
                omitted.append("invalid-file-metadata"); continue
            filename=row["filename"]
            try: safe_relative(filename)
            except Refused:
                omitted.append("unsafe-upstream-path"); continue
            patch=row.get("patch")
            if not isinstance(patch,str) or not patch:
                omitted.append("patch-not-supplied"); continue
            snippet,truncated=clipped_utf8(patch,MAX_PATCH)
            if not snippet: omitted.append("empty-snippet"); continue
            pathpin=digest(filename.encode())[:24]
            relative=f"snippets/{repo.replace('/','--')}/{sha}/{pathpin}.patch"
            sourcesha=self.seal(relative,snippet)
            source_id=f"github/{repo}/{sha}/{pathpin}"
            descriptor={"schema":"xnet.metadata-source.v1","scope_id":"practice-stream-r01",
                "task_id":"practice","source_id":source_id,"adapter":"archive-d",
                "relative_path":relative,"repo":repo,"revision":sha,"source_sha256":sourcesha,
                "source_bytes":len(snippet),"language":language(filename),"task_family":"public-code-change",
                "tags":sorted({"github","partial-patch",language(filename)}),
                "provenance":PUBLIC_CLASS,"upstream_receipt_sha256":receiptsha}
            # Descriptors have exactly the index API fields; extended provenance lives separately.
            provenance={"schema":"xnet.public-code-feed.patch-provenance.v1","descriptor":descriptor,
                "upstream_path":filename,"commit":sha,"repo":repo,
                "source_url":f"https://github.com/{repo}/commit/{sha}",
                "language":language(filename),"partial":True,"locally_truncated":truncated,
                "github_patch_completeness":"unknown","before_after_full_source":False,
                "upstream_license_retained":True,"provenance_class":PUBLIC_CLASS,"authority":"none",
                "model_training":False,"lesson_promotion":False,"evaluation_admission":False}
            self.seal(f"descriptors/{repo.replace('/','--')}-{sha}-{pathpin}.json",encode(provenance))
            with self.db:
                old=self.db.execute("SELECT descriptor FROM projections WHERE source_id=?",(source_id,)).fetchone()
                if old and old[0]!=encode(descriptor): raise Refused("descriptor source ID collision")
                self.db.execute("INSERT OR IGNORE INTO projections VALUES (?,?)",(source_id,encode(descriptor)))
            projected.append(descriptor)
        self.event("commit-admitted",{**intake,"intake_receipt_sha256":receiptsha,
            "projected":len(projected),"omitted_reasons":omitted,
            "remaining_file_rows":max(0,len(files)-MAX_PROJECTED_FILES)})
        with self.db: self.db.execute("INSERT OR REPLACE INTO cursors VALUES (?,?)",(repo,sha))
        return projected

    def sync(self):
        """Only this feed's sealed manifest; no existing vault scans or overwrite heals."""
        self.verify(); tiers=[]
        files=list(self.db.execute("SELECT path,sha256,bytes FROM files WHERE path NOT LIKE 'quarantine/%' ORDER BY CASE WHEN path='feed-root.json' THEN 0 ELSE 1 END,path"))
        for tier,path in self.config["mirrors"].items():
            root=Path(path); copied=identical=0; failures=[]
            if not root.parent.is_dir():
                tiers.append({"tier":tier,"status":"mount-unavailable","copied":0,"local_readback":False,
                              "remote_upload_verified":False}); continue
            if root.is_symlink() or getattr(root,"is_junction",lambda:False)():
                raise Refused("mirror root link refused")
            root.mkdir(exist_ok=True)
            # A differing marker means a different feed root, not permission to heal.
            marker=root/"feed-root.json"
            expected=(self.archive/"feed-root.json").read_bytes()
            if marker.exists() and marker.read_bytes()!=expected:
                tiers.append({"tier":tier,"status":"root-identity-conflict","copied":0,
                    "local_readback":False,"remote_upload_verified":False}); continue
            if not marker.exists() and any(root.iterdir()):
                tiers.append({"tier":tier,"status":"unidentified-nonempty-root","copied":0,
                    "local_readback":False,"remote_upload_verified":False}); continue
            for relative,h,size in files:
                source=safe_child(self.archive,relative); dest=safe_child(root,relative)
                if dest.exists():
                    if not dest.is_file() or dest.stat().st_size!=size or digest(dest.read_bytes())!=h:
                        failures.append({"path":relative,"reason":"digest-conflict-no-overwrite"}); continue
                    identical+=1; continue
                data=source.read_bytes()
                if len(data)!=size or digest(data)!=h: raise Refused("archive source changed during sync")
                dest.parent.mkdir(parents=True,exist_ok=True)
                try:
                    with dest.open("xb") as stream:
                        stream.write(data); stream.flush(); os.fsync(stream.fileno())
                except FileExistsError:
                    if dest.stat().st_size!=size or digest(dest.read_bytes())!=h:
                        failures.append({"path":relative,"reason":"concurrent-digest-conflict"}); continue
                if dest.stat().st_size!=size or digest(dest.read_bytes())!=h:
                    failures.append({"path":relative,"reason":"local-readback-differs"}); continue
                copied+=1
            tiers.append({"tier":tier,"status":"local-readback-passed" if not failures else "conflict",
                "copied":copied,"identical":identical,"failures":failures,"local_readback":not failures,
                "remote_upload_verified":False,"proof_scope":"desktop-client mount bytes only"})
        self.event("synchronization",{"utc":utc(self.clock.wall()),"tiers":tiers,
            "source":"this-feed-sealed-files-only","healing":"disabled","cloud_in_model_call":False})
        return tiers

    def projections(self,limit=160):
        return [json.loads(row[0]) for row in self.db.execute(
            "SELECT descriptor FROM projections ORDER BY source_id DESC LIMIT ?",(limit,))]

    def cycle(self, *, acquire=True):
        wall,mono=self._clock(); deadline=mono+CYCLE_SECONDS
        result={"schema":"xnet.public-code-feed.cycle.v1","utc_started":utc(wall),"acquisition":[],
            "provenance_class":PUBLIC_CLASS,"model_calls":0,"evaluation_inputs":0,
            "time_authority":"local UTC + monotonic deadline; not a consensus clock"}
        if acquire and wall>=self._get("next_acquire_utc",0) and wall>=self._get("http_hold_until",0):
            # Durable before network: failures never cause a blind rapid retry.
            self._set("next_acquire_utc",wall+INTERVAL)
            for repo in REPOS:
                if self.clock.mono()>=deadline: break
                try:
                    status,latest,_=self.request(f"https://api.github.com/repos/{repo}/commits?per_page=1",deadline)
                    if status!=200: raise Refused("latest commit HTTP status "+str(status))
                    if not isinstance(latest,list) or len(latest)!=1 or not isinstance(latest[0],dict) or not HEX.fullmatch(latest[0].get("sha","")):
                        raise Refused("latest commit identity response refused")
                    sha=latest[0]["sha"]
                    prior=self.db.execute("SELECT commit_sha FROM cursors WHERE repo=?",(repo,)).fetchone()
                    if prior and prior[0]==sha:
                        result["acquisition"].append({"repo":repo,"status":"unchanged","commit":sha}); continue
                    status,body,blobsha=self.request(f"https://api.github.com/repos/{repo}/commits/{sha}",deadline)
                    if status!=200: raise Refused("immutable commit HTTP status "+str(status))
                    projected=self.ingest_commit(repo,sha,body,blobsha)
                    result["acquisition"].append({"repo":repo,"status":"sealed","commit":sha,"projected":len(projected)})
                except (Refused,TimeoutError,OSError,json.JSONDecodeError) as exc:
                    result["acquisition"].append({"repo":repo,"status":"held","error_type":type(exc).__name__,"reason":str(exc)[:256]})
                    if isinstance(exc,(ClockAnomaly,Quota)) or self.clock.wall()<self._get("http_hold_until",0): break
        else:
            result["acquisition_deferred"]={"next_acquire_utc":self._get("next_acquire_utc",0),
                                           "http_hold_until":self._get("http_hold_until",0)}
        result["mirrors"]=self.sync()
        wall,_=self._clock(); self._set("last_wall",wall)
        result["utc_finished"]=utc(wall); result["elapsed_seconds"]=self.clock.mono()-mono
        result["integrity"]=self.verify(); result["archive_bytes"]=self.used
        result["status"]="ready" if all(x.get("status") in {"sealed","unchanged"} for x in result["acquisition"]) and \
            all(x["status"]=="local-readback-passed" for x in result["mirrors"]) else "attention"
        result["projected_descriptors"]=self.projections()
        atomic_json(self.control/"projected-descriptors.json",{"schema":"xnet.public-code-feed.projection-set.v1",
            "generation":uuid.uuid4().hex,"provenance_class":PUBLIC_CLASS,"authority":"none",
            "upstream_ledger_head":result["integrity"]["head"],"descriptors":result["projected_descriptors"]})
        atomic_json(self.control/"last-cycle.json",result)
        return result


def process_start_utc():
    if os.name!="nt": return None
    import ctypes
    from ctypes import wintypes
    class FILETIME(ctypes.Structure):
        _fields_=[("low",wintypes.DWORD),("high",wintypes.DWORD)]
    kernel=ctypes.WinDLL("kernel32",use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(FILETIME)]*4)]
    kernel.GetProcessTimes.restype=wintypes.BOOL
    creation,exit_,system,user=FILETIME(),FILETIME(),FILETIME(),FILETIME()
    if not kernel.GetProcessTimes(kernel.GetCurrentProcess(),creation,exit_,system,user):
        raise OSError(ctypes.get_last_error(),"GetProcessTimes failed")
    ticks=(creation.high<<32)|creation.low
    return utc(ticks/10_000_000-11644473600)


def paused(control):
    path=Path(control)/"paused.json"
    return path.exists() and read_json(path).get("paused") is True


def status(config):
    control=Path(config["control_root"])
    return {"schema":"xnet.public-code-feed.status.v1","utc":utc(time.time()),"paused":paused(control),
        "config_sha256":digest(encode(config)),"source_pins":source_pins(),
        "owner":read_json(control/"owner.json") if (control/"owner.json").exists() else None,
        "last_cycle":read_json(control/"last-cycle.json") if (control/"last-cycle.json").exists() else None,
        "process_liveness":"not inferred from stale metadata; lifecycle helper checks PID+start+exe+source",
        "remote_upload_verified":False,"model_calls":0}


def stop(config):
    control=Path(config["control_root"]); control.mkdir(parents=True,exist_ok=True)
    owner=read_json(control/"owner.json") if (control/"owner.json").exists() else {}
    atomic_json(control/"paused.json",{"paused":True,"utc":utc(time.time())})
    atomic_json(control/"stop.json",{"generation":owner.get("generation"),"utc":utc(time.time()),
        "policy":"cooperative; no process termination"})
    return {"status":"stop-requested","generation":owner.get("generation"),"automatic_restart":"paused"}


def execute(config,operation):
    control=Path(config["control_root"]); control.mkdir(parents=True,exist_ok=True)
    if operation in {"once","run"} and paused(control): return {"status":"paused","new_requests":0}
    with lease(control/"writer.lock"):
        feed=Feed(config)
        try:
            if operation=="verify": return feed.verify()
            if operation=="sync": return feed.cycle(acquire=False)
            if operation=="once": return feed.cycle()
            generation=uuid.uuid4().hex
            owner={"schema":"xnet.public-code-feed.owner.v1","generation":generation,"pid":os.getpid(),
                "process_start_utc":process_start_utc(),"python_executable":str(Path(sys.executable).resolve()),
                "python_sha256":digest(Path(sys.executable).read_bytes()),"script":str(Path(__file__).resolve()),
                "script_sha256":digest(Path(__file__).read_bytes()),"source_pins":source_pins(),
                "config_sha256":digest(encode(config)),"status":"running","utc":utc(time.time())}
            atomic_json(control/"owner.json",owner)
            try:
                while True:
                    stopfile=control/"stop.json"
                    if paused(control) or stopfile.exists() and read_json(stopfile).get("generation")==generation: break
                    feed.cycle()
                    # Stay cooperative and generate bounded mutable heartbeat metadata.
                    wait_until=time.monotonic()+INTERVAL
                    while time.monotonic()<wait_until:
                        if paused(control) or stopfile.exists() and read_json(stopfile).get("generation")==generation: break
                        atomic_json(control/"heartbeat.json",{"generation":generation,"pid":os.getpid(),
                            "utc":utc(time.time()),"monotonic":time.monotonic(),"next_cycle_seconds":max(0,wait_until-time.monotonic())})
                        time.sleep(min(2,max(0,wait_until-time.monotonic())))
            finally:
                atomic_json(control/"owner.json",{**owner,"status":"stopped","utc_stopped":utc(time.time())})
            return {"status":"stopped","generation":generation}
        finally:
            feed.close()


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation",choices=("init","once","run","sync","verify","status","stop"))
    parser.add_argument("--config",type=Path,required=True)
    parser.add_argument("--control",type=Path)
    parser.add_argument("--archive",type=Path)
    parser.add_argument("--proton",type=Path)
    parser.add_argument("--google",type=Path)
    args=parser.parse_args(argv)
    if args.operation=="init":
        if args.config.exists(): raise Refused("existing config is immutable; inspect before a new generation")
        if any(p is None for p in (args.control,args.archive)):
            raise Refused("init requires explicit control/archive roots; cloud mirrors are optional")
        config=validate_config(default_config(args.control,args.archive,args.proton,args.google))
        args.config.parent.mkdir(parents=True,exist_ok=True)
        with args.config.open("xb") as stream: stream.write(encode(config))
        result={"status":"configured","network_requests":0,"config_sha256":digest(args.config.read_bytes())}
    else:
        if any(p is not None for p in (args.control,args.archive,args.proton,args.google)):
            raise Refused("tier paths are immutable config fields after initialization")
        config=validate_config(read_json(args.config))
        result=status(config) if args.operation=="status" else stop(config) if args.operation=="stop" else execute(config,args.operation)
    print(json.dumps(result,sort_keys=True,ensure_ascii=False,allow_nan=False),flush=True)


if __name__=="__main__":
    main()
