"""Task-local practice source descriptors, prewarm receipts and verified CAS."""
from pathlib import Path
from frozen_integrations import adapter, metadata


class PracticeMetadata:
    def __init__(self, session, scope, cancelled, *, family="repository-repair"):
        self.session, self.scope, self.cancelled, self.family = session, scope, cancelled, family
        self.index = metadata.MetadataIndex(session.root / "preview-metadata",
            adapters={"public": metadata.ReadOnlyMount(session.workspace, tier="hot")},
            scope_id=scope, task_id=session.task["instance_id"], mode="practice",
            limits=metadata.Limits(max_sources=4096, max_events=8192, max_source_bytes=adapter.MAX_FILE,
                                  max_cas_bytes=32 * 1024 * 1024, chunk_bytes=768))
        self.records, self.revision, self.context = {}, None, None

    @staticmethod
    def trigger_view(trigger):
        # The shared metadata query API allows at most 512 UTF-8 bytes. This is
        # an exact prefix used for advisory retrieval, never an issue summary.
        if not isinstance(trigger, str): raise adapter.AdapterError("public retrieval trigger must be text")
        return trigger.encode("utf-8")[:512].decode("utf-8", "ignore") or "public source"

    def warm(self, trigger):
        # Intake is exact caller metadata; all byte reads/prefetch happen before
        # prompt packing. The prompt path below is hot-only.
        upstream = adapter.digest(adapter.canonical(self.session.metadata))
        self.revision = self.session.task["base_commit"] + ":" + adapter.digest(self.session.diff())
        paths = self.session._files()
        if len(paths) > 128: raise adapter.AdapterError("practice preview source count exceeds 128")
        self.records = {}
        for name in paths:
            if self.cancelled(): break
            if Path(name).name.casefold().startswith("readme") or Path(name).suffix not in {".py", ".js", ".ts", ".rs", ".go", ".c", ".h", ".cpp", ".java", ".toml", ".json"}:
                continue
            path = self.session._path(name)
            if path.stat().st_size > adapter.MAX_FILE: continue
            raw = path.read_bytes()
            if not raw: continue
            row = metadata.source_descriptor(scope_id=self.scope, task_id=self.session.task["instance_id"],
                source_id=name, adapter="public", relative_path=name, repo=self.session.task["repo"],
                revision=self.revision, source_sha256=adapter.digest(raw), source_bytes=len(raw),
                language=Path(name).suffix[1:], task_family=self.family, tags=("public-base", "source"),
                provenance="practice-stream", upstream_receipt_sha256=upstream)
            pin = metadata.digest(row)
            self.index.ingest(row, expected_metadata_sha256=pin)
            self.records[name] = {"metadata_sha256": pin, "source_sha256": row["source_sha256"]}
        trigger = self.trigger_view(trigger)
        proposal = self.index.propose_prefetch(trigger, repo=self.session.task["repo"], revision=self.revision,
                                              task_family=self.family, limit=3)
        fetched = self.index.prefetch(proposal, cancelled=self.cancelled, max_chunks_per_source=3)
        self.session.journal.append("preview-metadata-prewarm", {"revision": self.revision,
            "proposal": proposal, "fetch_receipts": fetched, "before_model_request": True})
        self.context = self.slices(trigger)
        return self.context

    def slices(self, trigger):
        return self.index.source_slices(self.trigger_view(trigger), repo=self.session.task["repo"], revision=self.revision,
            task_family=self.family, budget_bytes=2048, max_items=4)

    def current_source(self, path):
        row = self.records.get(path)
        if row is None: return None
        target = self.session._path(path)
        if target.stat().st_size > adapter.MAX_FILE:
            raise adapter.AdapterError("current source exceeds bounded cache identity check")
        raw = target.read_bytes()
        if adapter.digest(raw) != row["source_sha256"]:
            raise adapter.AdapterError("current source changed since prewarm; require a new observed revision")
        try:
            return self.index.fetch_verified_source(row["metadata_sha256"], expected_source_sha256=row["source_sha256"])
        except metadata.IndexErrorClosed as exc:
            if str(exc) == "source is not the exact receipted CAS object":
                return None  # ordinary counted read on a known unprefetched source
            raise adapter.AdapterError("verified source CAS integrity or current revision refused") from exc

    def close(self):
        self.index.close()
