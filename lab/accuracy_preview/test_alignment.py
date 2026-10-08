"""Offline alignment checks: authored public Git, fake measured/model/worker I/O.

No service, repository test, private oracle or official task is invoked.
"""
from dataclasses import asdict, replace
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from controller import PreviewLoop, QualityPolicy, AdapterError, UncertainCall, adapter, canonical, digest
from frozen_integrations import halo, metadata
from halo_binding import HaloBinding
import frozen_integrations
import preview_cli


class FakeMeasuredCounter:
    def __init__(self): self.calls = 0
    def __call__(self, messages):
        self.calls += 1
        raw = canonical(messages)
        self.last_messages_sha256 = digest(raw)
        self.last_rendered_sha256 = digest(b"offline fake template only\n" + raw)
        self.last_count = max(1, len(raw) // 4)
        return self.last_count


class AlignmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.repo = self.root / "source"; self.repo.mkdir()
        (self.repo / "value.py").write_bytes(b"VALUE = 1\n")
        (self.repo / "helper.py").write_bytes(b"HELPER = 1\n")
        (self.repo / "test_public.py").write_bytes(b"# Read-only public fixture, never executed.\n")
        (self.repo / "README.md").write_bytes(b"duplicate contract should not enter source prefill\n")
        (self.repo / "long.py").write_text("\n".join(f"LINE_{i} = '{'x' * 75}'" for i in range(210)) + "\n", encoding="utf-8")
        adapter.git(self.repo, "init", "--quiet"); adapter.git(self.repo, "add", "--all")
        adapter.git(self.repo, "-c", "user.name=Offline preview", "-c", "user.email=offline@invalid",
            "commit", "--quiet", "--no-gpg-sign", "-m", "Authored public fixture")
        self.task = {"instance_id": "practice__alignment-1", "repo": "practice/alignment",
            "base_commit": adapter.git(self.repo, "rev-parse", "HEAD").decode().strip(),
            "problem_statement": "Inspect value.py and helper.py using public source and the public fixture profile.",
            "version": "authored-practice"}
        self.session = self.new_session("quality")
        self.sessions, self.loops = [self.session], []
        self.requests, self.worker_calls = [], []
        self.counter = FakeMeasuredCounter()
        self.profile_hash = digest(b"authored offline public profile")
        self.worker_status = {"status": "passed", "exit_code": 0, "cleanup": {"absence_confirmed": True},
            "timed_out": False, "output_limited": False}

    def new_session(self, arm, task=None):
        return adapter.RepositorySession.create(self.root / "sessions", arm, task or self.task, self.repo)

    def tearDown(self):
        for loop in self.loops: loop.close()
        for session in self.sessions: session.journal.close()
        self.temp.cleanup()

    def events(self, session=None):
        return [json.loads(p) for p, in (session or self.session).journal.db.execute("SELECT payload FROM events ORDER BY seq")]

    def worker(self, request, *, remaining_seconds):
        self.assertGreater(remaining_seconds, 0); self.assertLessEqual(remaining_seconds, 900)
        self.assertEqual(set(request), {"schema", "instance_id", "base_commit", "snapshot_hash", "patch_hash", "patch", "profile"})
        self.worker_calls.append((request, remaining_seconds))
        return {"visibility": "public", "profile": request["profile"], "profile_hash": self.profile_hash,
            "patch_hash": request["patch_hash"], "snapshot_hash": request["snapshot_hash"], **self.worker_status}

    def edit_action(self, session=None, value=2, multifile=False):
        session = session or self.session
        names = ("value.py", "helper.py") if multifile else ("value.py",)
        return {"action": "edit", "arguments": {"operations": [{"path": name,
            "before_sha256": digest(session._path(name).read_bytes()),
            "text": ("VALUE" if name == "value.py" else "HELPER") + f" = {value}\n"} for name in names]}}

    def loop(self, actions=None, *, session=None, worker=None, policy=None, halo_binding=None, cancelled=None, tokens=10):
        chosen_session = session or self.session
        if callable(actions): choose = actions
        else:
            sequence = iter(actions or [{"action": "finish", "arguments": {}}])
            choose = lambda _: next(sequence, {"action": "finish", "arguments": {}})
        def model(request):
            self.requests.append(request)
            self.assertEqual(request["rendered_tokens"], self.counter.last_count)
            self.assertEqual(digest(canonical(request["messages"])), self.counter.last_messages_sha256)
            self.assertLessEqual(request["rendered_tokens"], 6400)
            self.assertGreater(request["remaining_active_seconds"], 0)
            return {"content": canonical(choose(request)).decode(), "usage": {"completion_tokens": min(tokens, request["max_tokens"])}}
        loop = PreviewLoop(chosen_session, model, self.counter, bounded_public_worker=worker or self.worker,
            public_profile="fixture-public", public_profile_sha256=self.profile_hash,
            policy=policy, halo_binding=halo_binding, cancelled=cancelled)
        self.loops.append(loop)
        return loop

    def test_01_source_prewarm_is_receipted_before_model_and_source_first(self):
        loop = self.loop([self.edit_action(multifile=True)])
        loop.run("offline-fake-model")
        events = self.events()
        first_model = next(i for i,e in enumerate(events) if e["kind"] == "request-reserved")
        warm = next(e for e in events[:first_model] if e["kind"] == "preview-metadata-prewarm")
        self.assertTrue(warm["value"]["before_model_request"])
        payload = json.loads(self.requests[0]["messages"][1]["content"].split("\n",1)[1])
        ctx = payload["public_source_context"]
        self.assertEqual(ctx["remote_reads"], 0)
        self.assertLessEqual(ctx["used_source_bytes"], 2048)
        self.assertTrue(ctx["rows"])
        self.assertFalse(any(row["relative_path"].startswith("README") for row in ctx["rows"]))
        self.assertEqual(loop.metadata.index.status()["mode"], "practice")
        self.assertEqual(loop.metadata.index.status()["task_id"], self.task["instance_id"])
        self.assertTrue(all(row["source_sha256"] for row in ctx["rows"]))
        self.assertEqual(len(self.worker_calls), 1)

    def test_02_explicit_covered_read_returns_exact_text_and_new_revision(self):
        loop = self.loop(); loop._state = loop._load_state()
        loop.metadata.warm("value helper")
        first = loop._read("value.py", 1, 1)
        second = loop._read("value.py", 1, 1)
        self.assertTrue(first["cached_source"]); self.assertTrue(second["cached_source"])
        self.assertEqual(second["text"], "1: VALUE = 1")
        self.assertTrue(second["complete_file"])
        old = loop.metadata.records["value.py"].copy()
        self.session.edit(self.edit_action()["arguments"]["operations"])
        with self.assertRaises(AdapterError): loop._read("value.py", 1, 1)
        loop.metadata.warm("value helper")
        current = loop._read("value.py", 1, 1)
        self.assertEqual(current["text"], "1: VALUE = 2")
        self.assertNotEqual(current["source_sha256"], first["source_sha256"])
        with self.assertRaises(metadata.IndexErrorClosed):
            loop.metadata.index.fetch_verified_source(old["metadata_sha256"], expected_source_sha256=old["source_sha256"])
        stale = [{"path":"value.py", "before_sha256":first["source_sha256"], "text":"VALUE = 3\n"}]
        with self.assertRaises(AdapterError): self.session.edit(stale)
        bounded = loop._read("long.py", 1, 200)
        self.assertEqual(bounded["end_line"], 64)
        self.assertEqual(bounded["next_line"], 65)
        self.assertTrue(bounded["omitted_after"])

    def test_03_changed_candidate_pass_then_same_patch_replay_zero_new_tests(self):
        loop = self.loop([self.edit_action(multifile=True), {"action":"public-test", "arguments":{"profile":"fixture-public"}}])
        loop.run("offline-fake-model")
        self.assertEqual(len(self.worker_calls), 1)
        self.assertEqual(len(self.requests), 5)
        outcome = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertTrue(outcome["verified_public_accept"])
        reviews = [e for e in self.events() if e["kind"] == "public-review-outcome"]
        self.assertEqual(len(reviews), 1)
        self.assertEqual(reviews[0]["value"]["binding"]["patch_sha256"], digest(self.session.diff()))
        self.assertEqual(loop._state["last_review"]["new_worker_dispatches"], 0)

    def test_04_failed_or_boolean_public_feedback_never_accepts(self):
        self.worker_status.update(status="passed", exit_code=False)
        loop = self.loop([self.edit_action()]); loop.run("offline-fake-model")
        self.assertFalse(json.loads((self.session.root / "preview-outcome.json").read_bytes())["verified_public_accept"])
        self.assertFalse(loop._state["last_review"]["verified_public_pass"])
        self.assertEqual(len(self.worker_calls), 1)
        original_test = self.session._path("test_public.py").read_bytes()
        with self.assertRaises(AdapterError):
            self.session.edit([{"path":"test_public.py", "before_sha256":digest(original_test), "text":"changed\n"}])
        self.assertEqual(self.session._path("test_public.py").read_bytes(), original_test)

    def test_05_worker_uncertainty_holds_before_counter_and_never_repeats(self):
        def uncertain(request, *, remaining_seconds):
            self.worker_calls.append(request)
            raise ConnectionResetError("offline lost acknowledgement")
        loop = self.loop([self.edit_action()], worker=uncertain)
        with self.assertRaises(UncertainCall): loop.run("offline-fake-model")
        counts = len(self.requests), self.counter.calls, len(self.worker_calls)
        with self.assertRaises(UncertainCall): loop.run("offline-fake-model")
        self.assertEqual(counts, (len(self.requests), self.counter.calls, len(self.worker_calls)))
        self.assertEqual(counts[0], 1); self.assertEqual(counts[2], 1)
        self.assertFalse((self.session.root / "prediction.json").exists())
        self.assertTrue(self.session.journal.db.execute("SELECT 1 FROM actions WHERE id LIKE 'review-%' AND status='uncertain'").fetchone())

    def test_06_rotating_fetch_retains_exact_original_observation(self):
        retrieved = []
        def choose(request):
            n = len(self.requests)
            if n <= 6: return {"action":"read", "arguments":{"path":"long.py", "start":1, "end":64}}
            if n == 7:
                pin = loop._state["archived"][0]["hash"]
                retrieved.append(pin)
                return {"action":"fetch", "arguments":{"sha256":pin}}
            if n == 8: return self.edit_action()
            return {"action":"finish", "arguments":{}}
        loop = self.loop(choose); loop.run("offline-fake-model")
        self.assertGreater(loop._state["rotations"], 0)
        self.assertTrue(retrieved)
        original = json.loads(self.session.journal.get(retrieved[0]))
        self.assertIn("1: LINE_0", original["text"])
        fetches = [e for e in self.events() if e["kind"] == "tool-observation" and e["value"]["operation"] == "fetch"]
        self.assertEqual(len(fetches), 1)
        fetched = json.loads(self.session.journal.get(fetches[0]["value"]["observation_hash"]))
        self.assertEqual(fetched["text"], original["text"])

    def halo_fixture(self):
        profile = halo.EngineProfile("offline-fixture", *[digest(str(i).encode()) for i in range(5)], 8192, 1300)
        proposal = halo.ContextPinProposal(profile.sha256, 6400, 6791, (digest(b"offline recall fixture"),))
        binding = {"instance_id":"offline-runtime", "process_id":77, "process_started_at_utc":"2000-01-01T00:00:00Z",
            "actual_command_sha256":digest(b"offline declared launch"), "profile_sha256":profile.sha256,
            "runtime_bundle_sha256":profile.runner_bundle_sha256}
        receipt = {"profile":asdict(profile), "profile_sha256":profile.sha256, "proposal":asdict(proposal),
            "runtime_process_binding":binding}
        path = self.root / "halo-proposal.json"; path.write_bytes(canonical(receipt))
        observed = {"artifact_pins_verified":True, "attestation_kind":"actual-current-profile-and-process",
            "profile":asdict(profile), "runtime_process_binding":dict(binding)}
        return path, observed

    def test_07_actual_profile_and_launch_drift_block_before_any_model(self):
        path, observed = self.halo_fixture()
        gate = HaloBinding(path, mode="active", observer=lambda: observed)
        loop = self.loop(halo_binding=gate)
        observed["runtime_process_binding"]["process_id"] = 78
        with self.assertRaises(AdapterError): loop.run("offline-fake-model")
        self.assertEqual(self.requests, []); self.assertEqual(self.counter.calls, 0)
        observed["runtime_process_binding"]["process_id"] = 77
        observed["profile"]["template_sha256"] = digest(b"other template")
        with self.assertRaises(AdapterError): loop.run("offline-fake-model")
        self.assertEqual(self.requests, [])
        staged = HaloBinding(path)
        self.assertFalse(staged.plan()["active"])
        self.assertEqual(staged.advise(6000, None)["mode"], "staged-only")

    def test_08_cancellation_has_no_model_prefetch_or_worker_dispatch(self):
        loop = self.loop(cancelled=lambda: True)
        loop.run("offline-fake-model")
        self.assertEqual(self.requests, []); self.assertEqual(self.worker_calls, [])
        self.assertEqual(self.counter.calls, 0)
        self.assertFalse(any(e["kind"] == "preview-metadata-prewarm" for e in self.events()))
        report = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertTrue(report["cancelled"]); self.assertFalse(report["verified_public_accept"])

    def test_09_schedule_hypothesis_changes_only_order_not_tools_or_quotas(self):
        first = self.loop([self.edit_action()]); first.run("offline-fake-model")
        normal = [r["xnet_phase"] for r in self.requests]
        alternate_session = self.new_session("alternative"); self.sessions.append(alternate_session)
        self.requests = []
        second = self.loop([self.edit_action(alternate_session)], session=alternate_session,
            policy=replace(QualityPolicy(), schedule=("Breaker","Builder","Arbiter")))
        second.run("offline-fake-model")
        alternative = [r["xnet_phase"] for r in self.requests]
        self.assertEqual(normal, ["Builder","Builder","Breaker","Arbiter"])
        self.assertEqual(alternative, ["Breaker","Breaker","Builder","Arbiter"])
        self.assertEqual(second.policy.quota("Builder"), 12)
        self.assertEqual(second.policy.quota("Breaker"), 6)
        self.assertEqual(second.policy.quota("Arbiter"), 6)
        self.assertEqual(first.plan["conventions_sha256"], second.plan["conventions_sha256"])
        self.assertEqual(first.public_profiles, second.public_profiles)

    def test_10_calls_outputs_pin_and_empty_builder_progress_are_hard_bounded(self):
        loop = self.loop(lambda _: {"action":"read", "arguments":{"path":"value.py","start":1,"end":1}}, tokens=1300)
        loop.run("offline-fake-model")
        self.assertEqual(len(self.requests), 24)
        self.assertEqual([r["xnet_phase"] for r in self.requests], ["Builder"]*12 + ["Breaker"]*6 + ["Arbiter"]*6)
        self.assertEqual(self.session.journal.db.execute("SELECT SUM(output_tokens) FROM calls").fetchone()[0], 30000)
        self.assertEqual(self.requests[-1]["max_tokens"], 100)
        self.assertTrue(all(0 < r["remaining_active_seconds"] <= 900 for r in self.requests))
        self.assertEqual(self.worker_calls, [])
        with self.assertRaises(AdapterError): replace(QualityPolicy(), max_calls=25).validate()
        with self.assertRaises(AdapterError): replace(QualityPolicy(), max_active_seconds=True).validate()

    def test_11_review_dispatch_cap_is_four_even_for_five_changed_candidates(self):
        def choose(request):
            n = len(self.requests)
            return self.edit_action(value=n+1) if n <= 5 else {"action":"finish","arguments":{}}
        loop = self.loop(choose); loop.run("offline-fake-model")
        self.assertEqual(len(self.worker_calls), 4)
        self.assertFalse(json.loads((self.session.root / "preview-outcome.json").read_bytes())["verified_public_accept"])
        self.assertEqual(loop._state["last_review"]["status"], "not-reviewed")

    def test_12_late_actual_public_pass_keeps_feedback_without_budget_acceptance(self):
        def late(request, *, remaining_seconds):
            result = self.worker(request, remaining_seconds=remaining_seconds)
            loop._state["active_seconds"] = 901.0
            return result
        loop = self.loop([self.edit_action()], worker=late); loop.run("offline-fake-model")
        outcome = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertFalse(outcome["verified_public_accept"])
        reviews = [e["value"] for e in self.events() if e["kind"] == "public-review-outcome"]
        self.assertEqual(reviews[0]["public_feedback"]["status"], "passed")
        self.assertFalse(reviews[0]["public_verification_within_active_budget"])
        self.assertEqual(len(self.requests), 1); self.assertEqual(len(self.worker_calls), 1)

    def test_13_original_large_issue_is_exact_and_pageable_under_measured_pin(self):
        task = {**self.task, "instance_id":"practice__large-issue-1", "problem_statement":"αβ fixture\n" * 20000}
        session = self.new_session("largeissue", task); self.sessions.append(session)
        loop = self.loop([self.edit_action(session)], session=session); loop.run("offline-fake-model")
        first = json.loads(self.requests[0]["messages"][1]["content"].split("\n",1)[1])
        self.assertTrue(first["issue_view"]["full_original_preserved"])
        self.assertFalse(first["issue_view"]["summary_used"])
        self.assertEqual(first["task"]["problem_statement"], task["problem_statement"][:first["issue_view"]["char_end"]])
        page = session.issue(3000, 4000)
        self.assertEqual(page["text"], task["problem_statement"][3000:4000])
        self.assertEqual(page["source_sha256"], digest(task["problem_statement"].encode()))

    def test_14_model_uncertainty_reservation_blocks_all_reentry(self):
        loop = self.loop()
        def broken(request):
            self.requests.append(request)
            raise ConnectionResetError("offline model transport acknowledgement absent")
        loop.callback = broken
        with self.assertRaises(UncertainCall): loop.run("offline-fake-model")
        measured = self.counter.calls
        with self.assertRaises(UncertainCall): loop.run("offline-fake-model")
        self.assertEqual(len(self.requests), 1); self.assertEqual(self.counter.calls, measured)
        self.assertFalse((self.session.root / "prediction.json").exists())

    def test_15_incomplete_final_timing_hold_prevents_zero_cost_reentry(self):
        loop = self.loop()
        self.session.journal.append("preview-final-stage-started", {"reason":"offline crash fixture"})
        with self.assertRaises(UncertainCall): loop.run("offline-fake-model")
        self.assertEqual(self.requests, []); self.assertEqual(self.counter.calls, 0)

    def test_16_operator_dry_plan_never_imports_factory_or_creates_namespace(self):
        task_file = self.root / "task.json"; task_file.write_bytes(canonical(self.task))
        sentinel = self.root / "factory-imported"
        factory = self.root / "factory.py"
        factory.write_text("from pathlib import Path\nPath(" + repr(str(sentinel)) + ").write_text('unexpected')\n", encoding="utf-8")
        config = {"schema":preview_cli.SCHEMA, "task_file":str(task_file), "source_repo":str(self.repo),
            "namespace_root":str(self.root / "unused"), "arm":"preview", "scope":"practice-preview",
            "task_origin":"operator-approved-public-practice", "model_name":"caller-four-billion-model",
            "public_profile":"fixture-public", "public_profile_sha256":self.profile_hash,
            "schedule":["Builder","Breaker","Arbiter"], "halo":{"mode":"staged","proposal_file":None},
            "runtime_factory":{"path":str(factory),"sha256":digest(factory.read_bytes())}}
        config_file = self.root / "operator.json"; config_file.write_bytes(canonical(config))
        loaded, task, policy, receipt = preview_cli.load_config(config_file)
        plan = preview_cli.inspect_plan(loaded, task, policy, receipt)
        self.assertEqual(plan["operations"], {"model":0,"worker":0,"remote_fetch":0,"lifecycle":0})
        self.assertFalse(sentinel.exists()); self.assertFalse((self.root / "unused").exists())
        factory.write_text("raise RuntimeError('mutated factory')", encoding="utf-8")
        with self.assertRaises(AdapterError): preview_cli.load_config(config_file)
        config["task_origin"] = "official-selected-task"; config_file.write_bytes(canonical(config))
        with self.assertRaises(AdapterError): preview_cli.load_config(config_file)

    def test_17_portable_six_source_layout_imports_without_work_adjacency(self):
        target = self.root / "portable"; target.mkdir()
        own = Path(__file__).resolve().parent
        for name in ("controller.py","metadata_bridge.py","halo_binding.py","frozen_integrations.py","preview_cli.py"):
            shutil.copyfile(own / name, target / name)
        for name, path in frozen_integrations.PATHS.items():
            destination = target / "dependencies" / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        code = "import controller; print(len(controller.source_pins())); print(controller.integrations.BUNDLED.is_dir())"
        result = subprocess.run([sys.executable,"-B","-c",code], cwd=target, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr.decode()[:2000])
        self.assertEqual(result.stdout.decode().splitlines(), ["11","True"])
        changed = target / "dependencies" / "stream_index.py"
        changed.write_bytes(changed.read_bytes() + b"\n# drift\n")
        refused = subprocess.run([sys.executable,"-B","-c",code], cwd=target, capture_output=True, timeout=20)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("approved integration source drift", refused.stderr.decode())

    def test_18_active_halo_uses_actual_latest_render_receipt_not_message_hash(self):
        path, observed = self.halo_fixture()
        gate = HaloBinding(path, mode="active", observer=lambda: observed)
        loop = self.loop(halo_binding=gate); loop._state = loop._load_state()
        loop.metadata.warm("value helper")
        loop.token_counter = lambda _: 1
        with self.assertRaises(AdapterError): loop._pack()
        self.assertEqual(self.requests, [])
        loop.token_counter = self.counter
        messages, count = loop._pack()
        advice = [e["value"] for e in self.events() if e["kind"] == "preview-halo-advice"][-1]
        self.assertEqual(advice["rendered_prompt_sha256"], self.counter.last_rendered_sha256)
        self.assertNotEqual(advice["rendered_prompt_sha256"], digest(canonical(messages)))
        self.assertEqual(advice["measured_prompt_tokens"], count)

    def test_19_actual_public_failure_retains_feedback_and_patch_without_accepting(self):
        self.worker_status.update(status="failed", exit_code=1, stderr="authored public fixture failure")
        loop = self.loop([self.edit_action()]); prediction = loop.run("offline-fake-model")
        self.assertTrue(prediction["model_patch"])
        report = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertFalse(report["verified_public_accept"])
        result = [e["value"] for e in self.events() if e["kind"] == "public-review-outcome"][0]
        self.assertEqual(result["public_feedback"]["stderr"], "authored public fixture failure")
        self.assertEqual(result["public_feedback"]["status"], "failed")

    def test_20_final_freeze_cost_crossing_deadline_revokes_cached_pass_acceptance(self):
        loop = self.loop([self.edit_action()])
        original = self.session.finalize
        def slow_freeze(model_name):
            prediction = original(model_name)
            loop._state["active_seconds"] = 901.0
            return prediction
        self.session.finalize = slow_freeze
        loop.run("offline-fake-model")
        report = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertFalse(report["verified_public_accept"])
        self.assertFalse(report["active_budget_remaining"])
        self.assertTrue(loop._state["last_review"]["verified_public_pass"])
        self.assertEqual(len(self.worker_calls), 1)

    def test_21_builder_empty_finish_is_held_and_patch_progress_can_follow_four_calls(self):
        actions = [{"action":"finish","arguments":{}}, {"action":"list","arguments":{}},
            {"action":"read","arguments":{"path":"value.py","start":1,"end":1}},
            {"action":"list","arguments":{}}, self.edit_action()]
        loop = self.loop(actions); loop.run("offline-fake-model")
        self.assertEqual([r["xnet_phase"] for r in self.requests], ["Builder"]*6 + ["Breaker","Arbiter"])
        first_action = json.loads(self.session.journal.get(self.session.journal.db.execute(
            "SELECT response_hash FROM actions WHERE id='call-0001'").fetchone()[0]))
        self.assertTrue(first_action["finish_requested"])
        first_observation = json.loads(self.session.journal.get([e["value"] for e in self.events()
            if e["kind"] == "agent-iteration-completed"][0]["state_hash"]))["observations"][0]
        self.assertTrue(json.loads(self.session.journal.get(first_observation["hash"]))["finish_held"])
        self.assertEqual(len(self.worker_calls), 1)

    def interrupted_terminal_save(self, loop):
        original = loop._save
        crash = [True]
        def after_save(call_id):
            original(call_id)
            if crash[0] and loop._state.get("terminal_phase_complete") is True:
                crash[0] = False
                raise RuntimeError("offline interruption after durable terminal iteration")
        loop._save = after_save
        with self.assertRaises(RuntimeError): loop.run("offline-fake-model")
        counters = len(self.requests), self.counter.calls, len(self.worker_calls)
        state = loop._load_state()
        self.assertTrue(state["terminal_phase_complete"])
        self.assertFalse((self.session.root / "prediction.json").exists())
        loop.run("offline-fake-model")
        self.assertEqual(counters, (len(self.requests), self.counter.calls, len(self.worker_calls)))
        self.assertTrue((self.session.root / "prediction.json").exists())
        return state

    def test_22_final_quota_crash_after_save_never_dispatches_seventh_arbiter(self):
        def choose(request):
            n = len(self.requests)
            if n == 1: return self.edit_action()
            if n <= 3: return {"action":"finish","arguments":{}}
            return {"action":"read","arguments":{"path":"value.py","start":1,"end":1}}
        loop = self.loop(choose)
        state = self.interrupted_terminal_save(loop)
        self.assertEqual(state["terminal_phase_reason"], "role-quota")
        self.assertEqual(state["role_calls"], 6)
        self.assertEqual(len(self.requests), 9)
        self.assertEqual(sum(r["xnet_phase"] == "Arbiter" for r in self.requests), 6)

    def test_23_early_final_finish_crash_after_save_never_dispatches_again(self):
        loop = self.loop([self.edit_action()])
        state = self.interrupted_terminal_save(loop)
        self.assertEqual(state["terminal_phase_reason"], "finish")
        self.assertEqual(state["role_calls"], 1)
        self.assertEqual(len(self.requests), 4)

    def test_24_cancellation_after_final_review_revokes_current_acceptance(self):
        flag = [False]
        loop = self.loop([self.edit_action()], cancelled=lambda: flag[0])
        real_review = loop.reviewer.review
        def cancel_after_review(reason):
            result = real_review(reason)
            if reason == "before-finish": flag[0] = True
            return result
        loop.reviewer.review = cancel_after_review
        loop.run("offline-fake-model")
        report = json.loads((self.session.root / "preview-outcome.json").read_bytes())
        self.assertTrue(report["cancelled"])
        self.assertFalse(report["verified_public_accept"])
        self.assertTrue(loop._state["last_review"]["verified_public_pass"])
        self.assertEqual(len(self.worker_calls), 1)

    def test_25_corrupt_receipted_cache_never_becomes_an_unmarked_read_fallback(self):
        loop = self.loop(); loop._state = loop._load_state(); loop.metadata.warm("value helper")
        observed = loop._read("value.py", 1, 1)
        self.assertTrue(observed["cached_source"])
        source = observed["source_sha256"]
        path = loop.metadata.index.root / "cas" / source[:2] / source
        path.write_bytes(b"tampered offline CAS fixture\n")
        with self.assertRaises(AdapterError): loop._read("value.py", 1, 1)


if __name__ == "__main__": unittest.main(verbosity=2)
