"""Durable exclusions and before-callback exposure; no model or network."""
import copy
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from xnet.dojo_curriculum import build_dojo_curriculum, private_selection
from xnet.dojo_exposure import CurriculumExhausted, DojoExposure, DojoExposureError
from xnet.learning_dataset import verify_learning_dataset
from xnet.learning_epoch import LearningEpoch
from xnet.ledger import Ledger
from xnet.protocol import canonical, digest, sha256


class DojoExposureControls(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "exposure"
        self.catalog = build_dojo_curriculum()
        self.rows = {row["task_id"]: row for row in self.catalog["rows"]}
        self.ledger = self.open()

    def tearDown(self):
        self.tmp.cleanup()

    def open(self):
        return DojoExposure(self.root, self.catalog, curriculum_sha256=self.catalog["curriculum_sha256"])

    def mark(self, plan, split, task_id, *, suffix="raw-1"):
        request = {"task": copy.deepcopy(self.rows[task_id]["public_task"]), "route": suffix}
        return self.ledger.expose_request(plan["epoch_id"], request,
            reservation_id=plan["epoch_id"] + "-" + task_id + "-" + suffix, purpose=split)

    def complete(self, plan):
        for split, task_ids in plan["selection"]["splits"].items():
            for task_id in task_ids:
                self.mark(plan, split, task_id)
        return self.ledger.retire_holdouts(plan["epoch_id"], evaluation_sha256=digest({"fixture-report": plan["epoch_id"]}))

    def test_plan_is_durable_detached_compatible_and_never_blindly_reallocated(self):
        plan = self.ledger.plan_epoch("epoch-1")
        self.assertEqual(verify_learning_dataset(plan["dataset"], expected_sha256=plan["dataset_sha256"]), plan["dataset"])
        private = private_selection(plan["selection"])
        self.assertEqual(len(private["tasks"]), 6)
        status = self.ledger.status()
        self.assertEqual(self.open().plan_epoch("epoch-1"), plan)
        self.assertEqual(self.open().status(), status)
        plan["selection"]["splits"]["practice"][0] = "edited-copy"
        self.assertNotEqual(self.ledger.plan_epoch("epoch-1"), plan)
        with self.assertRaises(DojoExposureError):
            self.ledger.plan_epoch("epoch-1", practice_count=4)

    def test_before_callback_failed_or_uncertain_call_stays_exposed_on_restart(self):
        plan = self.ledger.plan_epoch("epoch-1")
        task_id = plan["selection"]["splits"]["practice"][0]
        calls = []
        receipt = self.mark(plan, "practice", task_id)
        def failing_callback():
            self.assertEqual(self.open().status()["exposure_count"], 1)
            calls.append("inert fixture callback")
            raise RuntimeError("uncertain fixture reply")
        with self.assertRaises(RuntimeError):
            failing_callback()
        head = self.ledger.status()["head_sha256"]
        self.assertEqual(self.mark(plan, "practice", task_id), receipt)
        self.assertEqual(self.open().status(expected_head_sha256=head)["exposure_count"], 1)
        self.assertEqual(len(calls), 1)
        self.assertFalse(receipt["redispatch_authorized"])
        self.assertEqual(self.ledger.status()["callbacks_invoked"], 0)

    def test_matched_arms_and_retries_allowed_only_inside_exact_frozen_epoch(self):
        plan = self.ledger.plan_epoch("epoch-1")
        task_id = plan["selection"]["splits"]["unseen"][0]
        receipts = [self.mark(plan, "unseen", task_id, suffix=arm)
                    for arm in ("raw-1", "fixed-1", "learned-1", "learned-2")]
        self.assertEqual(len({row["receipt_sha256"] for row in receipts}), 4)
        with self.assertRaises(DojoExposureError):
            self.ledger.expose("epoch-1", task_id, reservation_id=receipts[0]["reservation_id"],
                request_sha256="a" * 64, purpose="unseen")
        with self.assertRaises(DojoExposureError):
            self.mark(plan, "practice", task_id, suffix="wrong-split")

    def test_exact_public_request_and_stable_id_required(self):
        plan = self.ledger.plan_epoch("epoch-1")
        task_id = plan["selection"]["splits"]["validation"][0]
        for field, value in (("task_id", "new-id-same-problem"), ("issue", "changed-public-task"), ("hidden_cases", [])):
            request = {"task": copy.deepcopy(self.rows[task_id]["public_task"])}
            request["task"][field] = value
            with self.subTest(field=field), self.assertRaises(DojoExposureError):
                self.ledger.expose_request("epoch-1", request, reservation_id="bad-" + field, purpose="validation")
        self.assertEqual(self.ledger.status()["exposure_count"], 0)

    def test_retry_bundle_identity_is_distinct_from_original_novelty(self):
        plan = self.ledger.plan_epoch("epoch-1")
        task_id = plan["selection"]["splits"]["practice"][0]
        current = copy.deepcopy(self.rows[task_id]["public_task"])
        current["files"]["helpers.py"] += "\n"
        request = {"task": current, "base_files": copy.deepcopy(current["files"]), "attempt": 2}
        receipt = self.ledger.expose_request("epoch-1", request, reservation_id="bounded-retry", purpose="practice")
        self.assertEqual(receipt["original_content_sha256"], self.rows[task_id]["content_sha256"])
        self.assertEqual(receipt["request_task_sha256"], digest(current))
        self.assertNotEqual(receipt["request_task_sha256"], self.rows[task_id]["public_task_sha256"])
        for change in (lambda value: value.update(attempt=1),
                       lambda value: value.update(attempt=True),
                       lambda value: value.update(base_files={}),
                       lambda value: value["task"]["files"].update(extra_py="source"),
                       lambda value: value["task"]["files"].update({"helpers.py": "x" * 8193})):
            bad = copy.deepcopy(request)
            change(bad)
            with self.assertRaises(DojoExposureError):
                self.ledger.expose_request("epoch-1", bad, reservation_id="refused-retry", purpose="practice")

    def proposal(self, request):
        # Enum-only authored fixture coach. No model inference is represented.
        return {"text": json.dumps({"scaffold_id": "fixture-checklist", "steps": ["inspect-contract", "trace-state"]}),
                "usage": {"prompt_tokens": 30, "completion_tokens": 12}}

    def generate(self, request):
        task_id = request["task"]["task_id"]
        purpose = next(split for split, ids in self.fixture_plan["selection"]["splits"].items() if task_id in ids)
        receipt = self.ledger.expose_request("epoch-real", request, reservation_id=request["nonce"], purpose=purpose)
        self.fixture_requests.append((copy.deepcopy(request), receipt))
        # A valid but still faulty candidate forces a real changed-base retry.
        files = copy.deepcopy(request["base_files"] if request["attempt"] == 1 else self.fixture_refs[task_id])
        if request["attempt"] == 1:
            files["helpers.py"] = files["helpers.py"].replace("return ", "return 0 + ", 1)
        return {"model_id": "inert-fixture", "model_sha256": self.fixture_model["sha256"],
                "text": json.dumps({"files": files}), "usage": {"prompt_tokens": 100, "completion_tokens": 20}}

    def boundary(self, loop, model_id, task_id):
        body = {"schema": "xnet.scaffold-boundary-observation.v1",
            "repair_manifest_sha256": loop.manifest["receipt_sha256"], "model_id": model_id,
            "task_id": task_id, "attempt_receipts": [row["receipt_sha256"] for row in loop._rows(model_id, task_id)],
            "violation": False}
        return self.fixture_memory.put_evidence(canonical(body), source="authored-fixture-host-observer",
            scope_id="temporary-fixture", metadata={"control_only": True})

    def test_real_learning_epoch_accepts_curriculum_and_exposes_changed_base_retries(self):
        self.fixture_plan = self.ledger.plan_epoch("epoch-real")
        private = private_selection(self.fixture_plan["selection"])
        self.fixture_refs, self.fixture_requests = private["references"], []
        def artifact(name):
            path = Path(self.tmp.name) / name
            path.write_bytes(("authored inert fixture " + name).encode())
            return {"path": str(path.absolute()), "sha256": sha256(path.read_bytes())}
        self.fixture_model = artifact("weights.fixture")
        runner, adapter = artifact("runner.fixture"), artifact("adapter.fixture")
        models = {"inert-fixture": {"model_sha256": self.fixture_model["sha256"], "runner_sha256": runner["sha256"]}}
        identity = {"schema": "xnet.repair-run-identity.v1", "adapter": adapter,
            "runner": {"source_revision": "authored-fixture-only", "artifacts": [runner]},
            "models": {"inert-fixture": {"decoding": {"temperature": 0}, "transport": {"kind": "no-inference-fixture"},
                "tokenizer": {"id": "fixture", "sha256": None}, "template": {"id": "fixture", "sha256": None}}}, "native": None}
        self.fixture_memory = Ledger(Path(self.tmp.name) / "private-memory")
        source = Path(__file__).absolute()
        epoch = LearningEpoch(self.fixture_memory, Path(self.tmp.name) / "epoch-real", epoch_id="epoch-real",
            scope_id="temporary-fixture", dataset=self.fixture_plan["dataset"], dataset_sha256=self.fixture_plan["dataset_sha256"],
            **private, model_id="inert-fixture", models=models, run_identity=identity, model_artifacts=[self.fixture_model],
            callback_artifacts=[{"path": str(source), "sha256": sha256(source.read_bytes())}],
            generate=self.generate, propose=self.proposal, boundary_observer=self.boundary)
        self.assertEqual(epoch.run()["status"], "completed")
        self.assertEqual(len(self.fixture_requests), 12)
        retries = [(request, receipt) for request, receipt in self.fixture_requests if request["attempt"] == 2]
        self.assertEqual(len(retries), 6)
        self.assertTrue(all(request["task"]["files"] != self.rows[request["task"]["task_id"]]["public_task"]["files"]
                            for request, _ in retries))
        self.assertEqual(self.open().status()["exposure_count"], 12)
        self.assertEqual(epoch.run()["status"], "completed")
        self.assertEqual(len(self.fixture_requests), 12)

    def test_retirement_requires_exposure_then_enables_practice_only(self):
        first = self.ledger.plan_epoch("epoch-1")
        with self.assertRaises(DojoExposureError):
            self.ledger.retire_holdouts("epoch-1", evaluation_sha256="a" * 64)
        retired = self.complete(first)
        self.assertFalse(retired["evaluation_authenticity_proven"])
        self.assertEqual(self.open().retire_holdouts("epoch-1", evaluation_sha256=retired["evaluation_sha256"]), retired)
        with self.assertRaises(DojoExposureError):
            self.ledger.retire_holdouts("epoch-1", evaluation_sha256="b" * 64)
        with self.assertRaises(DojoExposureError):
            self.mark(first, "unseen", first["selection"]["splits"]["unseen"][0], suffix="new-after-grading")
        second = self.ledger.plan_epoch("epoch-2")
        self.assertEqual(second["selection"]["splits"]["practice"], first["selection"]["splits"]["validation"])
        prior_groups = {self.rows[tid]["near_duplicate_id"] for ids in first["selection"]["splits"].values() for tid in ids}
        current_holdouts = {self.rows[tid]["near_duplicate_id"] for split in ("validation", "unseen") for tid in second["selection"]["splits"][split]}
        self.assertFalse(prior_groups & current_holdouts)
        self.assertTrue(prior_groups <= set(second["dataset"]["denied_cluster_ids"]))

    def test_unexposed_reservations_remain_excluded_and_cannot_become_practice(self):
        first = self.ledger.plan_epoch("epoch-1")
        second = self.open().plan_epoch("epoch-2")
        first_ids = {tid for values in first["selection"]["splits"].values() for tid in values}
        second_ids = {tid for values in second["selection"]["splits"].values() for tid in values}
        self.assertFalse(first_ids & second_ids)
        self.assertEqual(self.ledger.status()["exposure_count"], 0)

    def test_concurrent_plans_serialize_and_cannot_share_reserved_families(self):
        with ThreadPoolExecutor(max_workers=2) as executor:
            plans = list(executor.map(self.ledger.plan_epoch, ("epoch-parallel-a", "epoch-parallel-b")))
        groups = [{self.rows[tid]["near_duplicate_id"] for ids in plan["selection"]["splits"].values() for tid in ids}
                  for plan in plans]
        self.assertFalse(groups[0] & groups[1])
        self.assertEqual(self.open().status()["epoch_count"], 2)

    def test_finite_family_exhaustion_is_durable_and_new_epoch_ids_do_not_help(self):
        completed = 0
        while True:
            try:
                plan = self.ledger.plan_epoch("epoch-" + str(completed + 1))
            except CurriculumExhausted:
                break
            self.complete(plan)
            completed += 1
            self.assertLessEqual(completed, 6)
        self.assertEqual(completed, 5)
        status = self.ledger.status()
        self.assertTrue(status["exhausted"])
        with self.assertRaises(CurriculumExhausted):
            self.open().plan_epoch("fresh-id-cannot-reset-novelty")
        self.assertEqual(self.open().status(), status)
        self.assertEqual(self.open().plan_epoch("epoch-1"), self.ledger.plan_epoch("epoch-1"))

    def test_edit_and_externally_retained_head_detect_tamper_and_rollback(self):
        plan = self.ledger.plan_epoch("epoch-1")
        self.mark(plan, "practice", plan["selection"]["splits"]["practice"][0])
        retained = self.ledger.status()["head_sha256"]
        connection = sqlite3.connect(self.ledger.path)
        try:
            connection.execute("DELETE FROM events WHERE seq=2")
            connection.commit()
            with self.assertRaises(DojoExposureError):
                self.ledger.status(expected_head_sha256=retained)
            connection.execute("UPDATE events SET body=? WHERE seq=1", ('{}',))
            connection.commit()
        finally:
            connection.close()
        with self.assertRaises(DojoExposureError):
            self.open()

    def test_strict_labels_budget_types_and_curriculum_binding(self):
        for changes in ({"practice_count": True}, {"unseen_count": 1}, {"validation_count": 51}):
            with self.subTest(changes=changes), self.assertRaises(DojoExposureError):
                self.ledger.plan_epoch("epoch", **changes)
        for label in (True, "../outside", "", "a" * 129):
            with self.subTest(label=label), self.assertRaises(DojoExposureError):
                self.ledger.plan_epoch(label)
        changed = copy.deepcopy(self.catalog)
        changed["rows"][0]["near_duplicate_id"] = "fresh-label"
        with self.assertRaises(ValueError):
            DojoExposure(self.root, changed, curriculum_sha256=self.catalog["curriculum_sha256"])


if __name__ == "__main__":
    unittest.main()
