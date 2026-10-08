import copy
import json
from pathlib import Path
import tempfile
import unittest

from adapters.loopback.stream_index import (MetadataIndex, ReadOnlyMount, Limits, IndexErrorClosed,
                          canonical, digest, sha256, source_descriptor,
                          source_byte_chunks)


class CounterMount(ReadOnlyMount):
    reads = 0
    def read(self, *args, **kwargs):
        self.reads += 1
        return super().read(*args, **kwargs)


class IndexTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.mount = self.base / "sources"
        self.mount.mkdir()
        self.clock = [100]
        self.adapter = CounterMount(self.mount)
        self.index = MetadataIndex(self.base / "index", adapters={"c": self.adapter}, scope_id="scope", task_id="task", clock=lambda: self.clock[0], limits=Limits(chunk_bytes=128, hot_bytes=512, hot_items=4))

    def tearDown(self):
        self.index.close()
        self.tmp.cleanup()

    def row(self, name="codec.py", text="def decode(value):\n    return value.split('|')\n", *, revision="r1", source_id=None, family="encoding", provenance="workspace-source"):
        raw = text.encode("utf-8")
        (self.mount / name).parent.mkdir(parents=True, exist_ok=True)
        (self.mount / name).write_bytes(raw)
        return source_descriptor(scope_id="scope", task_id="task", source_id=source_id or name, adapter="c", relative_path=name, repo="demo/repo", revision=revision, source_sha256=sha256(raw), source_bytes=len(raw), language="python", task_family=family, tags=[family, "python"], provenance=provenance, upstream_receipt_sha256="a" * 64)

    def intake(self, row):
        return self.index.ingest(row, expected_metadata_sha256=digest(row))

    def warm(self, row, trigger="decode encoding"):
        self.intake(row)
        proposal = self.index.propose_prefetch(trigger, repo=row["repo"], revision=row["revision"], task_family=row["task_family"])
        return self.index.prefetch(proposal, cancelled=lambda: False)

    def test_intake_reads_no_content(self):
        self.intake(self.row())
        self.assertEqual(self.adapter.reads, 0)
        self.assertEqual(self.index.status()["hot_bytes"], 0)

    def test_duplicate_does_not_increment_ledger(self):
        row = self.row()
        self.intake(row)
        before = self.index.status()["events"]
        self.assertEqual(self.intake(row)["status"], "duplicate")
        self.assertEqual(before, self.index.status()["events"])

    def test_mismatched_metadata_pin_refused(self):
        with self.assertRaises(IndexErrorClosed):
            self.index.ingest(self.row(), expected_metadata_sha256="b" * 64)

    def test_closed_schema_refused(self):
        row = self.row()
        row["answer"] = "pretend"
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_bool_byte_count_refused(self):
        row = self.row()
        row["source_bytes"] = True
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_secret_path_refused(self):
        row = self.row()
        row["relative_path"] = ".ssh/id_ed25519"
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_traversal_refused(self):
        row = self.row()
        row["relative_path"] = "../outside.py"
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_duplicate_json_keys_refused(self):
        from adapters.loopback.stream_index import strict_json
        with self.assertRaises(IndexErrorClosed):
            strict_json(b'{"one":1,"one":2}')

    def test_mode_isolates_practice_from_evaluation(self):
        row = self.row(provenance="practice-stream")
        self.index.close()
        self.index = MetadataIndex(self.base / "eval", adapters={"c": self.adapter}, scope_id="scope", task_id="task", mode="evaluation")
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_evaluation_source_bound_to_task_and_scope(self):
        row = self.row(provenance="evaluation-source")
        self.index.close()
        self.index = MetadataIndex(self.base / "eval", adapters={"c": self.adapter}, scope_id="scope", task_id="task", mode="evaluation")
        self.intake(row)
        row["task_id"] = "other"
        with self.assertRaises(IndexErrorClosed):
            self.intake(row)

    def test_evaluation_cannot_enter_practice(self):
        with self.assertRaises(IndexErrorClosed):
            self.intake(self.row(provenance="evaluation-source"))

    def test_metadata_query_needs_no_read_and_qr_is_locator(self):
        row = self.row()
        self.intake(row)
        found = self.index.query("codec", repo=row["repo"], revision="r1")
        self.assertEqual(found[0]["qr_locator"], "xnet://sha256/" + row["source_sha256"])
        self.assertTrue(found[0]["advisory_only"])
        self.assertEqual(self.adapter.reads, 0)

    def test_unmatched_query_returns_no_generated_answer(self):
        self.intake(self.row())
        self.assertEqual(self.index.query("flamingo", repo="demo/repo", revision="r1"), [])

    def test_family_match_locates_without_text_scan(self):
        row = self.row()
        self.intake(row)
        self.assertTrue(self.index.query("flamingo", repo="demo/repo", revision="r1", task_family="encoding")[0]["family_match"])
        self.assertEqual(self.adapter.reads, 0)

    def test_prefetch_and_hot_slice_exact_bytes(self):
        row = self.row()
        self.warm(row)
        found = self.index.source_slices("decode", repo="demo/repo", revision="r1", task_family="encoding", budget_bytes=512)
        piece = found["rows"][0]
        raw = (self.mount / row["relative_path"]).read_bytes()
        self.assertEqual(piece["text"].encode(), raw[piece["start_byte"]:piece["end_byte"]])
        self.assertEqual(piece["source_sha256"], row["source_sha256"])
        self.assertTrue(piece["complete_source"])
        self.assertTrue(found["accuracy_review_required"])
        self.assertEqual(found["remote_reads"], 0)

    def test_source_tamper_refused(self):
        row = self.row()
        self.intake(row)
        (self.mount / row["relative_path"]).write_text("tampered", encoding="utf-8")
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_cas_tamper_refused(self):
        row = self.row()
        self.warm(row)
        obj = self.index.root / "cas" / row["source_sha256"][:2] / row["source_sha256"]
        obj.write_bytes(b"tampered")
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_proposal_tampering_refused(self):
        self.intake(self.row())
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        proposal["trigger"] = "other"
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_proposal_stale_after_new_intake(self):
        self.intake(self.row())
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        self.intake(self.row("other.py"))
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_cancelled_prefetch_reads_no_content(self):
        self.intake(self.row())
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        self.assertEqual(self.index.prefetch(proposal, cancelled=lambda: True)[0]["status"], "cancelled")
        self.assertEqual(self.adapter.reads, 0)

    def test_hot_ttl_expires(self):
        self.warm(self.row())
        self.clock[0] += 301
        found = self.index.source_slices("decode", repo="demo/repo", revision="r1", task_family="encoding", budget_bytes=512)
        self.assertEqual(found["status"], "hot-miss")

    def test_hot_byte_and_item_limits(self):
        for number in range(5):
            self.warm(self.row(f"codec{number}.py", text=("# encoding data\n" * 30)), trigger="encoding")
        status = self.index.status()
        self.assertLessEqual(status["hot_bytes"], 512)
        self.assertLessEqual(status["hot_items"], 4)

    def test_revision_change_evicts_old_snapshot(self):
        row = self.row()
        self.warm(row)
        new = self.row(text="def decode(value):\n    return list(value)\n", revision="r2")
        self.intake(new)
        self.assertEqual(self.index.query("decode", repo="demo/repo", revision="r1", task_family="encoding"), [])
        self.assertEqual(self.index.status()["hot_items"], 0)

    def test_input_metadata_is_detached_from_caller(self):
        row = self.row()
        self.intake(row)
        before = self.index.index_pin()
        row["tags"].append("forged")
        self.assertEqual(self.index.index_pin(), before)

    def test_resume_pinned_ledger_and_durable_source(self):
        row = self.row()
        self.warm(row)
        head = self.index.status()["ledger_head_sha256"]
        self.index.close()
        (self.mount / row["relative_path"]).unlink()
        self.index = MetadataIndex(self.base / "index", adapters={"c": self.adapter}, scope_id="scope", task_id="task", clock=lambda: self.clock[0], limits=Limits(chunk_bytes=128, hot_bytes=512, hot_items=4), expected_head=head)
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        self.assertEqual(self.index.prefetch(proposal, cancelled=lambda: False)[0]["status"], "prefetched")

    def test_unreceipted_cas_is_not_admitted(self):
        row = self.row()
        self.intake(row)
        obj = self.index.root / "cas" / row["source_sha256"][:2] / row["source_sha256"]
        obj.parent.mkdir(parents=True)
        obj.write_bytes((self.mount / row["relative_path"]).read_bytes())
        proposal = self.index.propose_prefetch("decode", repo="demo/repo", revision="r1", task_family="encoding")
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_journal_edit_detected(self):
        self.intake(self.row())
        self.index._journal.write_bytes(b"forged\n")
        with self.assertRaises(IndexErrorClosed):
            self.index.status()

    def test_replay_tamper_detected(self):
        self.intake(self.row())
        root = self.index.root
        self.index.close()
        journal = root / "events.jsonl"
        value = json.loads(journal.read_text())
        value["payload"]["language"] = "zig"
        journal.write_bytes(canonical(value) + b"\n")
        with self.assertRaises(IndexErrorClosed):
            MetadataIndex(root, adapters={"c": self.adapter}, scope_id="scope", task_id="task", clock=lambda: self.clock[0], limits=Limits(chunk_bytes=128, hot_bytes=512, hot_items=4))

    def test_config_edit_detected(self):
        (self.index.root / "config.json").write_bytes(b"{}")
        with self.assertRaises(IndexErrorClosed):
            self.index.status()

    def test_exclusive_owner(self):
        with self.assertRaises(IndexErrorClosed):
            MetadataIndex(self.index.root, adapters={"c": self.adapter}, scope_id="scope", task_id="task")

    def test_unicode_and_crlf_partition_reconstructs_exactly(self):
        raw = ("λ中文 αβγ\r\n" * 40).encode()
        chunks = source_byte_chunks(raw, 64)
        self.assertEqual(b"".join(row["text"].encode() for row in chunks), raw)
        for row in chunks:
            self.assertEqual(sha256(raw[row["start_byte"]:row["end_byte"]]), row["chunk_sha256"])
            self.assertFalse(row["text"].endswith("\r"))

    def test_cloud_readiness_stays_unknown(self):
        adapter = ReadOnlyMount(self.mount, tier="cold")
        self.assertTrue(adapter.health()["local_root_present"])
        self.assertEqual(adapter.health()["remote_readiness"], "unknown")

    def test_feed_step_is_bounded(self):
        with self.assertRaises(IndexErrorClosed):
            self.index.step([self.row(), self.row("other.py")], max_records=1)

    def test_review_fetch_reads_exact_durable_source(self):
        row = self.row()
        self.warm(row)
        result = self.index.fetch_verified_source(digest(row), expected_source_sha256=row["source_sha256"])
        self.assertEqual(sha256(result["text"].encode()), row["source_sha256"])
        self.assertEqual(result["remote_reads"], 0)

    def test_review_fetch_refuses_superseded_source(self):
        old = self.row()
        self.warm(old)
        self.intake(self.row(revision="r2", text="# changed encoding source\n"))
        with self.assertRaises(IndexErrorClosed):
            self.index.fetch_verified_source(digest(old), expected_source_sha256=old["source_sha256"])

    def test_review_fetch_requires_exact_expected_pin(self):
        row = self.row()
        self.warm(row)
        with self.assertRaises(IndexErrorClosed):
            self.index.fetch_verified_source(digest(row), expected_source_sha256="f" * 64)

    def test_partial_long_line_is_labelled_incomplete(self):
        row = self.row(text="# encoding " + "x" * 300 + "\n")
        self.warm(row)
        found = self.index.source_slices("encoding", repo="demo/repo", revision="r1", task_family="encoding", budget_bytes=512)
        self.assertTrue(any(not piece["complete"] for piece in found["rows"]))
        self.assertTrue(all(not piece["complete_source"] for piece in found["rows"]))

    def test_source_credentials_refused_before_cas_write(self):
        row = self.row(text="password = 'example-secret-value'\n")
        self.intake(row)
        proposal = self.index.propose_prefetch("encoding", repo="demo/repo", revision="r1", task_family="encoding")
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)
        self.assertFalse((self.index.root / "cas").exists())

    def test_expired_proposal_refused(self):
        self.intake(self.row())
        proposal = self.index.propose_prefetch("encoding", repo="demo/repo", revision="r1", task_family="encoding")
        self.clock[0] += 301
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)

    def test_cancellation_after_read_never_exposes_hot_data(self):
        self.intake(self.row())
        proposal = self.index.propose_prefetch("encoding", repo="demo/repo", revision="r1", task_family="encoding")
        count = [0]
        def cancelled():
            count[0] += 1
            return count[0] >= 2
        self.assertEqual(self.index.prefetch(proposal, cancelled=cancelled)[0]["status"], "cancelled")
        self.assertEqual(self.index.status()["hot_items"], 0)

    def test_trusted_ledger_checkpoint_refuses_rewrite(self):
        self.intake(self.row())
        self.index.close()
        with self.assertRaises(IndexErrorClosed):
            MetadataIndex(self.base / "index", adapters={"c": self.adapter}, scope_id="scope", task_id="task", expected_head="f" * 64, clock=lambda: self.clock[0], limits=Limits(chunk_bytes=128, hot_bytes=512, hot_items=4))

    def test_receipt_failure_never_exposes_unreceipted_hot_data(self):
        row = self.row()
        self.intake(row)
        proposal = self.index.propose_prefetch("encoding", repo="demo/repo", revision="r1", task_family="encoding")
        old = self.index._append
        def fail(kind, payload):
            raise OSError("simulated disk failure")
        self.index._append = fail
        with self.assertRaises(OSError):
            self.index.prefetch(proposal, cancelled=lambda: False)
        self.index._append = old
        self.assertEqual(self.index.status()["hot_items"], 0)

    def test_full_ledger_refuses_before_source_dispatch(self):
        self.index.close()
        self.index = MetadataIndex(self.base / "short", adapters={"c": self.adapter}, scope_id="scope", task_id="task", limits=Limits(max_events=4, chunk_bytes=128, hot_bytes=512))
        row = self.row()
        self.intake(row)
        for number in range(3):
            self.index.checkpoint({"number": number})
        proposal = self.index.propose_prefetch("encoding", repo="demo/repo", revision="r1", task_family="encoding")
        with self.assertRaises(IndexErrorClosed):
            self.index.prefetch(proposal, cancelled=lambda: False)
        self.assertEqual(self.adapter.reads, 0)

    def test_identical_source_aliases_emit_bytes_once(self):
        one = self.row("codec1.py")
        two = self.row("codec2.py")
        self.intake(one)
        self.intake(two)
        proposal = self.index.propose_prefetch("encoding decode", repo="demo/repo", revision="r1", task_family="encoding")
        self.index.prefetch(proposal, cancelled=lambda: False)
        found = self.index.source_slices("decode", repo="demo/repo", revision="r1", task_family="encoding", budget_bytes=512)
        self.assertEqual(len(found["rows"]), 1)
        self.assertEqual(len(found["rows"][0]["source_aliases"]), 2)
        self.assertEqual(found["used_source_bytes"], one["source_bytes"])
        self.assertEqual(self.index.status()["cas_receipted_bytes"], one["source_bytes"])


if __name__ == "__main__":
    unittest.main()
