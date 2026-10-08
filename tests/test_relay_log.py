import json
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from xnet.protocol import ZERO_HASH, canonical, digest
from xnet.relay_log import CHUNK_MAX_BYTES, MAX_RECORD_BYTES, RelayLog, RelayLogError


class RelayLogTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "cold"
        self.log = RelayLog(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def test_ordered_hash_chain_and_reopen(self):
        first = self.log.append("user", " Keep this exactly.\r\n", timestamp=0)
        second = self.log.append("operator", "port=18082", kind="fact", owner="Qwen", timestamp=1)
        entries = RelayLog(self.root).entries()
        self.assertEqual([entry["seq"] for entry in entries], [1, 2])
        self.assertEqual(entries[0]["previous_sha256"], ZERO_HASH)
        self.assertEqual(entries[1]["previous_sha256"], first["head_sha256"])
        self.assertEqual(entries[1]["entry_sha256"], second["head_sha256"])
        self.assertEqual(entries[0]["text"], " Keep this exactly.\r\n")
        for entry in entries:
            self.assertEqual(entry["id"], "log-" + entry["entry_sha256"])
            body = {key: value for key, value in entry.items() if key not in {"id", "entry_sha256"}}
            self.assertEqual(digest(body), entry["entry_sha256"])
        self.assertEqual(self.log.path.read_bytes(), b"".join(canonical(entry) + b"\n" for entry in entries))

    def test_utf8_chunk_boundaries_preserve_every_character(self):
        text = "a" * 4095 + "💡" + "漢é\r\n\t" * 2000 + "  "
        receipt = self.log.append("tool", text, timestamp=0)
        entries = receipt["entries"]
        self.assertGreater(len(entries), 2)
        self.assertEqual("".join(entry["text"] for entry in entries), text)
        self.assertEqual(len(entries[0]["text"].encode("utf-8")), 4095)
        self.assertTrue(all(len(entry["text"].encode("utf-8")) <= CHUNK_MAX_BYTES for entry in entries))
        self.assertEqual(self.log.entries(), entries)

    def test_empty_text_is_preserved_as_an_entry(self):
        entry = self.log.append("log", "", timestamp=0)["entries"][0]
        self.assertEqual(self.log.fetch([entry["id"]], max_bytes=0)[0]["text"], "")

    def test_fetch_preserves_request_order_and_utf8_budget(self):
        entries = [self.log.append("qwen", value, timestamp=index)["entries"][0]
                   for index, value in enumerate(("é", "💡", "third"))]
        ids = [entries[1]["id"], entries[0]["id"]]
        self.assertEqual(self.log.fetch(ids, max_bytes=6), [entries[1], entries[0]])
        with self.assertRaises(RelayLogError):
            self.log.fetch(ids, max_bytes=5)
        self.assertEqual(self.log.fetch([], max_bytes=0), [])

    def test_fetch_rejects_unknown_ids_paths_duplicates_and_bad_budget(self):
        known = self.log.append("gpt", "data", timestamp=0)["entries"][0]["id"]
        for requested in (["log-" + "f" * 64], ["../relay-log.jsonl"], [known, known], known, [7]):
            with self.subTest(requested=requested), self.assertRaises(RelayLogError):
                self.log.fetch(requested)
        for budget in (-1, True, 1.5):
            with self.subTest(budget=budget), self.assertRaises(RelayLogError):
                self.log.fetch([known], max_bytes=budget)

    def test_tampered_content_and_chain_fail_closed(self):
        self.log.append("user", "first", timestamp=0)
        self.log.append("tool", "second", timestamp=1)
        original = self.log.path.read_bytes()
        entries = self.log.entries()
        changes = []
        changed = json.loads(json.dumps(entries))
        changed[0]["text"] = "edited"
        changes.append(changed)
        changed = json.loads(json.dumps(entries))
        changed[1]["previous_sha256"] = ZERO_HASH
        body = {key: value for key, value in changed[1].items() if key not in {"id", "entry_sha256"}}
        changed[1]["entry_sha256"] = digest(body)
        changed[1]["id"] = "log-" + changed[1]["entry_sha256"]
        changes.append(changed)
        changes.append(list(reversed(entries)))
        for changed in changes:
            with self.subTest(changed=changed):
                self.log.path.write_bytes(b"".join(canonical(entry) + b"\n" for entry in changed))
                with self.assertRaises(RelayLogError):
                    self.log.entries()
                with self.assertRaises(RelayLogError):
                    self.log.append("log", "must not append", timestamp=2)
        self.log.path.write_bytes(original)
        self.assertEqual(self.log.entries(), entries)

    def test_noncanonical_or_partial_records_fail_closed(self):
        entry = self.log.append("log", "data", timestamp=0)["entries"][0]
        for raw in (canonical(entry), b"\n", b"not-json\n", json.dumps(entry).encode("utf-8") + b"\n",
                    b" " * (MAX_RECORD_BYTES + 1) + b"\n"):
            with self.subTest(raw=raw):
                self.log.path.write_bytes(raw)
                with self.assertRaises(RelayLogError):
                    self.log.entries()

    def test_metadata_and_nonportable_unicode_rejected_before_writes(self):
        for kwargs in ({"stream": "other"}, {"kind": "answer"}, {"owner": "é" * 65},
                       {"owner": "a\nb"}, {"timestamp": -1}, {"timestamp": True}):
            request = {"stream": "user", "text": "data", "timestamp": 0, **kwargs}
            with self.subTest(request=request), self.assertRaises(RelayLogError):
                self.log.append(**request)
        for text in ("bad\ud800", "bad\u2028", "bad\u2029"):
            with self.subTest(text=repr(text)), self.assertRaises(RelayLogError):
                self.log.append("log", text, timestamp=0)
        self.assertFalse(self.log.path.exists())

    def test_simultaneous_append_keeps_chunks_contiguous(self):
        texts = [str(index) * 5000 for index in range(6)]
        def append(text):
            return RelayLog(self.root).append("tool", text, timestamp=0)
        with ThreadPoolExecutor(max_workers=6) as pool:
            receipts = list(pool.map(append, texts))
        entries = self.log.entries()
        self.assertEqual(len(entries), 12)
        self.assertEqual([entry["seq"] for entry in entries], list(range(1, 13)))
        for receipt, original in zip(receipts, texts):
            ids = [entry["id"] for entry in receipt["entries"]]
            fetched = self.log.fetch(ids)
            self.assertEqual("".join(entry["text"] for entry in fetched), original)
            self.assertEqual(fetched[1]["seq"], fetched[0]["seq"] + 1)

    def test_hardlinked_file_rejected(self):
        self.log.append("log", "data", timestamp=0)
        alias = Path(self.temp.name) / "alias.jsonl"
        try:
            os.link(self.log.path, alias)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"hard links unavailable: {exc}")
        with self.assertRaises(RelayLogError):
            self.log.entries()

    def test_symlink_root_and_log_rejected(self):
        target = Path(self.temp.name) / "actual"
        target.mkdir()
        link = Path(self.temp.name) / "linked"
        try:
            link.symlink_to(target, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symbolic links unavailable: {exc}")
        with self.assertRaises(RelayLogError):
            RelayLog(link)
        self.root.mkdir()
        target_file = target / "source.jsonl"
        target_file.write_bytes(b"")
        self.log.path.symlink_to(target_file)
        with self.assertRaises(RelayLogError):
            self.log.entries()


if __name__ == "__main__":
    unittest.main()
