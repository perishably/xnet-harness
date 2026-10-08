"""Exact feedback source/packing checks; authored Git and seeded public JSON.

No model, worker, repository test, network, grader or runtime is dispatched.
"""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from . import FeedbackPreviewLoop, adapter
from .feedback_preview import MAX_EXCERPT_UTF8_BYTES

canonical, digest, AdapterError = adapter.canonical, adapter.digest, adapter.AdapterError


class Counter:
    def __init__(self): self.messages = []
    def __call__(self, messages):
        self.messages.append(deepcopy(messages))
        self.last_messages_sha256 = digest(canonical(messages))
        self.last_rendered_sha256 = digest(b"offline fixture render\n" + canonical(messages))
        self.last_count = max(1, len(canonical(messages)) // 4)
        return self.last_count


class FeedbackPreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        repo = self.root / "authored-public"; repo.mkdir()
        (repo / "value.py").write_bytes(b"VALUE = 1\n")
        adapter.git(repo,"init","--quiet"); adapter.git(repo,"add","--all")
        adapter.git(repo,"-c","user.name=Offline feedback","-c","user.email=offline@invalid",
                    "commit","--quiet","--no-gpg-sign","-m","Authored public fixture")
        task = {"instance_id":"practice__feedback-1","repo":"practice/feedback",
            "base_commit":adapter.git(repo,"rev-parse","HEAD").decode().strip(),
            "version":"authored-practice","problem_statement":"Inspect the authored value source using public evidence."}
        self.session = adapter.RepositorySession.create(self.root / "sessions","feedback",task,repo)
        self.counter = Counter(); self.model_calls = self.worker_calls = 0
        self.profile_sha = digest(b"authored public profile")
        self.loop = FeedbackPreviewLoop(self.session,self.model,self.counter,bounded_public_worker=self.worker,
            public_profile="fixture-public",public_profile_sha256=self.profile_sha)
        self.loop._state = self.loop._load_state()
        self.session.edit([{"path":"value.py","before_sha256":digest(b"VALUE = 1\n"),"text":"VALUE = 2\n"}])

    def tearDown(self):
        self.loop.close(); self.session.journal.close(); self.temp.cleanup()

    def model(self, request):
        self.model_calls += 1; raise AssertionError("offline test must never call a model")

    def worker(self, request, *, remaining_seconds):
        self.worker_calls += 1; raise AssertionError("offline test must never call a worker")

    def binding(self):
        return {"instance_id":self.session.task["instance_id"],"snapshot_sha256":digest(canonical(self.session.metadata)),
            "patch_sha256":digest(self.session.diff()),"profile":self.loop.profile,"profile_sha256":self.profile_sha,
            "policy_sha256":digest(canonical(self.loop.reviewer.plan))}

    def seed(self, stdout="public output\n", stderr="Traceback: authored public failure\n", *, passing=False, outcome_change=None):
        binding = self.binding()
        outcome = {"schema":"xnet.public-review-outcome.v1","binding":binding,
            "status":"public-passed" if passing else "public-failed-or-incomplete","verified_public_pass":passing,
            "cached_same_patch_review":False,"new_worker_dispatches":1,
            "public_feedback":{"visibility":"public","profile":binding["profile"],
                "profile_hash":binding["profile_sha256"],"snapshot_hash":binding["snapshot_sha256"],
                "patch_hash":binding["patch_sha256"],"status":"passed" if passing else "failed",
                "stdout":stdout,"stderr":stderr}}
        if outcome_change: outcome_change(outcome)
        action_id = "review-" + digest(canonical(binding))
        # Seed only immutable public JSON, using real durable journal receipts.
        # This callback contains no worker, test or transport operation.
        self.session.journal.action(action_id,binding,lambda: outcome)
        self.loop._state["last_review"] = {key:outcome[key] for key in (
            "binding","status","verified_public_pass","cached_same_patch_review","new_worker_dispatches")}
        row = self.session.journal.db.execute("SELECT response_hash FROM actions WHERE id=?",(action_id,)).fetchone()
        return action_id,row[0],outcome

    def assert_no_dispatch(self):
        self.assertEqual((self.model_calls,self.worker_calls),(0,0))
        self.assertEqual(self.session.journal.db.execute("SELECT COUNT(*) FROM calls").fetchone()[0],0)

    def test_01_bound_packet_and_pointer_match_exact_completed_public_cas(self):
        action, pointer, outcome = self.seed()
        packet = self.loop.feedback_packet()
        self.assertTrue(packet["available"])
        self.assertEqual(packet["binding"],outcome["binding"])
        self.assertEqual(packet["review_action_id"],action)
        self.assertEqual(packet["source_cas_pointer"],pointer)
        self.assertEqual(digest(self.session.journal.get(pointer)),packet["source_outcome_sha256"])
        fetched = self.session.fetch_observation(packet["source_fetch_action"]["arguments"]["sha256"])
        self.assertEqual(fetched["public_feedback"]["stderr"],outcome["public_feedback"]["stderr"])
        self.assertEqual(packet["excerpts"]["stderr"]["text"],outcome["public_feedback"]["stderr"])
        self.assertFalse(packet["generated_conclusions"])
        self.assert_no_dispatch()

    def test_02_stale_patch_cannot_show_an_old_trace_as_current(self):
        self.seed()
        self.session.edit([{"path":"value.py","before_sha256":digest(b"VALUE = 2\n"),"text":"VALUE = 3\n"}])
        packet = self.loop.feedback_packet()
        self.assertFalse(packet["available"])
        self.assertEqual(packet["reason"],"review-binding-is-not-current-candidate")
        self.assertNotIn("excerpts",packet)
        self.assert_no_dispatch()

    def test_03_wrong_profile_in_completed_packet_is_refused(self):
        self.seed(outcome_change=lambda outcome:outcome["public_feedback"].update(profile_hash="0"*64))
        with self.assertRaises(AdapterError): self.loop.feedback_packet()
        self.assert_no_dispatch()

    def test_04_corrupt_cas_is_refused_without_source_fallback(self):
        _,pointer,_ = self.seed()
        (self.session.journal.cas / pointer).write_bytes(b"offline corrupted receipt")
        with self.assertRaises(AdapterError): self.loop.feedback_packet()
        self.assert_no_dispatch()

    def test_05_changed_sql_pointer_cannot_replace_the_durable_review_receipt(self):
        action,_,outcome = self.seed()
        changed = deepcopy(outcome); changed["public_feedback"]["stderr"] = "unreceipted replacement"
        other = self.session.journal.put(canonical(changed))
        with self.session.journal.db:
            self.session.journal.db.execute("UPDATE actions SET response_hash=? WHERE id=?",(other,action))
        with self.assertRaises(AdapterError): self.loop.feedback_packet()
        self.assert_no_dispatch()

    def test_06_multibyte_total_cap_and_exact_original_offsets(self):
        stdout = "α🙂 output\n"*600; stderr = "trace λ🙂\n"*600 + "LAST PUBLIC ERROR\n"
        self.seed(stdout,stderr)
        packet = self.loop.feedback_packet()
        total = 0
        for key,original_text in (("stdout",stdout),("stderr",stderr)):
            item = packet["excerpts"][key]; original = original_text.encode("utf-8"); text = item["text"].encode("utf-8")
            total += len(text)
            self.assertEqual(original[item["start_byte"]:item["end_byte"]],text)
            self.assertEqual(item["original_sha256"],digest(original))
            self.assertEqual(item["original_utf8_bytes"],len(original))
            self.assertEqual(item["excerpt_sha256"],digest(text))
        self.assertLessEqual(total,MAX_EXCERPT_UTF8_BYTES)
        self.assertEqual(total,packet["used_excerpt_utf8_bytes"])
        self.assertTrue(packet["excerpts"]["stdout"]["omitted_after"])
        self.assertTrue(packet["excerpts"]["stderr"]["omitted_before"])
        self.assertTrue(packet["excerpts"]["stderr"]["text"].endswith("LAST PUBLIC ERROR\n"))
        self.assert_no_dispatch()

    def test_07_unknown_review_provides_no_excerpt_and_no_retry_or_promotion(self):
        binding = self.binding(); action = "review-"+digest(canonical(binding))
        def interrupted(): raise RuntimeError("offline lost acknowledgement fixture")
        with self.assertRaises(RuntimeError): self.session.journal.action(action,binding,interrupted)
        self.loop._state["last_review"] = {"binding":binding,"status":"public-failed-or-incomplete","verified_public_pass":False}
        before = self.session.journal.verify()
        packet = self.loop.feedback_packet()
        self.assertEqual(packet["reason"],"review-action-not-completed")
        self.assertFalse(packet["available"])
        self.assertEqual(before,self.session.journal.verify())
        with self.assertRaises(adapter.UncertainCall): self.loop.run("offline-unused-model")
        self.assertEqual(self.counter.messages,[])
        self.assert_no_dispatch()

    def test_08_exact_status_and_existing_policy_are_not_changed(self):
        self.seed(passing=True)
        before = deepcopy(self.loop._state); action_count = self.session.journal.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0]
        packet = self.loop.feedback_packet()
        self.assertEqual(packet["review_status"],"public-passed")
        self.assertIs(packet["verified_public_pass"],True)
        self.assertEqual(before,self.loop._state)
        self.assertEqual(action_count,self.session.journal.db.execute("SELECT COUNT(*) FROM actions").fetchone()[0])
        self.assertEqual((self.loop.max_calls,self.loop.max_output,self.loop.max_seconds,self.loop.pin),(24,30000,900,6400))
        self.assertEqual(self.loop.reviewer.cap,4)
        self.assert_no_dispatch()

    def test_09_rotated_feedback_is_measured_in_base_context_before_generation(self):
        self.seed(stderr="exact authored failure\n"*300 + "LAST ERROR\n")
        self.loop.metadata.warm("value")
        observed = self.session._observe("offline-long-observation",{}, {"text":"rotatable public fixture "*2000})
        self.loop._state["observations"] = [{"hash":observed["observation_hash"],"call_id":"offline-observation"}]
        counter = self.loop.token_counter
        messages,count = self.loop._pack()
        self.assertIs(self.loop.token_counter,counter)
        self.assertGreater(self.loop._state["rotations"],0)
        payload = json.loads(messages[1]["content"].split("\n",1)[1])
        packet = payload["latest_public_review_feedback"]
        self.assertTrue(packet["available"])
        self.assertTrue(packet["excerpts"]["stderr"]["text"].endswith("LAST ERROR\n"))
        self.assertLessEqual(count,6400)
        self.assertEqual(self.counter.last_messages_sha256,digest(canonical(messages)))
        self.assertEqual(self.counter.last_count,count)
        self.assertTrue(all("latest_public_review_feedback" in sample[1]["content"] for sample in self.counter.messages))
        self.assert_no_dispatch()

    def test_10_plan_and_extension_source_pin_drift_are_refused(self):
        self.seed()
        original = self.loop.feedback_plan_path.read_bytes()
        self.loop.feedback_plan_path.write_bytes(b"{}")
        with self.assertRaises(AdapterError): self.loop.feedback_packet()
        self.loop.feedback_plan_path.write_bytes(original)
        self.loop.feedback_source_sha256 = "0"*64
        with self.assertRaises(AdapterError): self.loop.feedback_packet()
        self.assert_no_dispatch()


if __name__ == "__main__": unittest.main(verbosity=2)
