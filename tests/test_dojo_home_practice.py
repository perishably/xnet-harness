"""Fixed fictional home practice; independent keys, no model/network calls."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from xnet.dojo_home_practice import (HomePracticeError, answer_schema, grade,
    home_catalog, render, retrieve, source_identity)
from xnet.protocol import canonical, digest, sha256


# Independently retained test expectations; none are supplied to the renderer.
EXPECTED = {
    "cat-breakfast": "07:15", "spare-key": "blue tin on the hallway shelf", "recycling-day": "Friday",
    "wifi-guest-name": "Alder-Guest", "library-return": "2026-11-12", "visitor-cup": "striped ceramic mug",
    "seed-box": ["basil", "radish"], "school-bag": "lower coat-cupboard hook",
    "quiet-hours": {"start": "22:00", "end": "07:00"}, "dog-walker-days": ["Monday", "Thursday"],
    "cloud-room": 200 - 146, "copy-or-sync": "copy", "disk-fit": 70 - 18 - 21 - 9 - 4,
    "retention-count": 11 - 4, "upload-time": 900 // 15, "public-link": "named-recipients-only",
    "offline-folders": ["Tickets", "Maps"], "duplicate-savings": (3 - 1) * 120,
    "restore-order": ["verify-checksum", "copy-to-staging", "replace-current"], "photo-growth": 40 + 5 * 3,
    "washer-program": "Cotton-40", "dishwasher-count": 4, "plant-dose": 250 + 400, "filter-month": "2026-11",
    "thermostat-target": 17, "trash-liner": 30, "vacuum-zone": "nursery",
    "laundry-order": ["sort-colors", "check-pockets", "choose-program"], "shelf-limit": 20 - 6 - 4 - 3,
    "key-hook": "H2", "grocery-total": 2 * 250 + 180 + 3 * 60, "basket-change": 2000 - 1375,
    "unit-price": min(600 // 4, 780 // 6), "coupon-total": 2400 - 350,
    "weekly-meal-cost": 3 * 420 + 2 * 510, "restock-packs": (15 - 3 + 4 - 1) // 4,
    "delivery-threshold": "yes", "split-payment": 3600 // 4, "return-credit": 1850 - 425 + 300,
    "missing-ingredients": ["beans", "tomatoes"], "collection-correction": "Saturday",
    "appointment-moved": "11:30", "budget-revised": 2500 - 1800, "key-relocated": "green box in the study",
    "backup-frequency": 7, "cloud-selection": "Plan-C", "shopping-remove": ["tea", "oats"],
    "trip-quantity": 5, "three-revisions": 21, "delivery-address-label": "Desk-B",
}
MULTI = {"disk-fit", "basket-change", "missing-ingredients"}


class HomePracticeControls(unittest.TestCase):
    def setUp(self):
        self.tasks = home_catalog()
        self.by_id = {task["task_id"]: task for task in self.tasks}

    def envelope(self, task):
        slug = task["task_id"].removeprefix("home--")
        current = retrieve(task)
        if slug in MULTI:
            sources = [document["source_id"] for document in current]
        elif slug == "budget-revised":
            sources = [document["source_id"] for document in current]
        elif task["family_id"] == "home-corrections":
            sources = [max(current, key=lambda document: document["revision"])["source_id"]]
        else:
            sources = [task["documents"][0]["source_id"]]
        return {"answer": copy.deepcopy(EXPECTED[slug]), "source_ids": sources}

    def test_exactly_fifty_distinct_public_fictional_cases_with_detached_data(self):
        self.assertEqual(len(self.tasks), 50)
        self.assertEqual(len(EXPECTED), 50)
        self.assertEqual(len(self.by_id), 50)
        self.assertEqual(len({task["content_sha256"] for task in self.tasks}), 50)
        self.assertEqual(len({task["question"] for task in self.tasks}), 50)
        self.assertEqual({family: sum(task["family_id"] == family for task in self.tasks)
                          for family in {task["family_id"] for task in self.tasks}},
                         {"home-memory": 10, "home-storage": 10, "home-household": 10,
                          "home-shopping": 10, "home-corrections": 10})
        def public_only(value):
            if type(value) is dict:
                self.assertFalse(set(value) & {"expected", "references", "gold", "solution", "hidden_cases"})
                for item in value.values(): public_only(item)
            elif type(value) is list:
                for item in value: public_only(item)
        for task in self.tasks:
            public_only(task)
            self.assertTrue(task["practice_only"] and task["fictional_user_data"])
            self.assertFalse(task["benchmark"] or task["semantic_novelty_proven"] or task["weights_updated"])
        self.tasks[0]["documents"][0]["text"] = "changed detached copy"
        self.assertNotEqual(self.tasks[0], home_catalog()[0])

    def test_all_independent_expected_answers_and_source_sets_pass_fixed_grade(self):
        for task in self.tasks:
            with self.subTest(task=task["task_id"]):
                envelope = self.envelope(task)
                result = grade(task["task_id"], envelope)
                self.assertTrue(result["correct"])
                self.assertEqual((result["passed"], result["total"]), (2, 2))
                self.assertEqual(result["public_feedback"]["reasons"], ["correct"])
                self.assertEqual(grade(task["task_id"], json.dumps(envelope)), result)
                self.assertEqual(result["public_feedback_sha256"], digest(result["public_feedback"]))

    def test_retrieved_sources_have_exact_hashes_pointers_and_no_stale_versions(self):
        for task in self.tasks:
            sources = retrieve(task)
            self.assertTrue(1 <= len(sources) <= 3)
            self.assertEqual(retrieve(task), sources)
            retired = {source_id for doc in task["documents"] for source_id in doc["supersedes"]}
            self.assertFalse({doc["source_id"] for doc in sources} & retired)
            for source in sources:
                self.assertEqual(source["source_sha256"], sha256(source["text"].encode()))
                self.assertEqual(source["document_sha256"], digest({key: value for key, value in source.items() if key != "document_sha256"}))
                self.assertTrue(source["pointer"].startswith("dojo-home-practice://"))
                self.assertEqual(source["classification"], "public")
            sources[0]["text"] = "edited returned copy"
            self.assertNotEqual(sources, retrieve(task))
        latest = retrieve(self.by_id["home--three-revisions"])
        self.assertEqual(len(latest), 1)
        self.assertEqual(latest[0]["revision"], 3)

    def test_stale_answer_or_extra_citation_never_gets_full_credit(self):
        task = self.by_id["home--budget-revised"]
        correct = self.envelope(task)
        wrong = copy.deepcopy(correct)
        wrong["answer"] = 3000 - 1800
        result = grade(task["task_id"], wrong)
        self.assertFalse(result["correct"])
        self.assertEqual(result["passed"], 1)
        self.assertTrue(result["sources_correct"])
        wrong = copy.deepcopy(correct)
        wrong["source_ids"] = [task["documents"][0]["source_id"], task["documents"][2]["source_id"]]
        result = grade(task["task_id"], wrong)
        self.assertFalse(result["correct"])
        self.assertTrue(result["answer_correct"])
        self.assertFalse(result["sources_correct"])
        task = self.by_id["home--cat-breakfast"]
        wrong = self.envelope(task)
        wrong["source_ids"].append(task["documents"][1]["source_id"])
        self.assertFalse(grade(task["task_id"], wrong)["correct"])

    def test_renderer_admits_only_fixed_guidance_and_same_task_public_feedback(self):
        max_bytes = 0
        steps = ["inspect-contract", "check-edge-cases", "trace-state", "verify-change", "inspect-feedback", "preserve-interfaces"]
        for task in self.tasks:
            feedback = grade(task["task_id"], {"answer": "wrong", "source_ids": ["wrong"]})["public_feedback"]
            messages = render(task, feedback, steps)
            self.assertEqual([row["role"] for row in messages], ["system", "user"])
            payload = json.loads(messages[1]["content"])
            self.assertEqual(payload["public_practice_feedback"], feedback)
            self.assertEqual(len(payload["guidance"]), 6)
            self.assertEqual({doc["source_id"] for doc in payload["sources"]}, {doc["source_id"] for doc in retrieve(task)})
            self.assertNotIn("expected", payload)
            max_bytes = max(max_bytes, len(canonical(messages)))
        self.assertLess(max_bytes, 6000)  # Bytes only, never a tokenizer claim.
        task = self.tasks[0]
        for bad in (["do household work"], ["inspect-contract"] * 2, [True], "inspect-contract"):
            with self.subTest(bad=bad), self.assertRaises(HomePracticeError):
                render(task, scaffold_steps=bad)
        feedback = grade(self.tasks[1]["task_id"], self.envelope(self.tasks[1]))["public_feedback"]
        with self.assertRaises(HomePracticeError): render(task, feedback)
        feedback = grade(task["task_id"], self.envelope(task))["public_feedback"]
        feedback["expected"] = "answer injection"
        with self.assertRaises(HomePracticeError): render(task, feedback)

    def test_malformed_and_executable_looking_answers_are_inert_rejections(self):
        task = self.by_id["home--dishwasher-count"]
        valid = self.envelope(task)
        for answer in ("not JSON", '{"answer":4,"answer":4,"source_ids":[]}',
                       '{"answer":NaN,"source_ids":[]}', {"answer": True, "source_ids": valid["source_ids"]},
                       {"answer": 4.0, "source_ids": valid["source_ids"]},
                       {"answer": 4, "source_ids": valid["source_ids"] * 2},
                       {"answer": 4, "source_ids": [], "self_pass": True},
                       {"answer": "__import__('os').system('forbidden')", "source_ids": valid["source_ids"]},
                       {"answer": "x" * 4097, "source_ids": valid["source_ids"]}):
            with self.subTest(answer=repr(answer)[:80]), patch("builtins.eval", side_effect=AssertionError("no eval")), patch("builtins.exec", side_effect=AssertionError("no exec")):
                self.assertFalse(grade(task["task_id"], answer)["correct"])
        with self.assertRaises(HomePracticeError): grade("fresh-id-same-question", valid)

    def test_changed_sources_and_fresh_ids_are_not_accepted_as_new_tasks(self):
        for change in (lambda task: task.update(task_id="fresh-task-id"),
                       lambda task: task.update(content_sha256="a" * 64),
                       lambda task: task["documents"][0].update(text="different facts"),
                       lambda task: task["documents"][0].update(source_id="fresh-source-id")):
            task = copy.deepcopy(self.tasks[0])
            change(task)
            with self.assertRaises(HomePracticeError): retrieve(task)
            with self.assertRaises(HomePracticeError): render(task)

    def test_public_feedback_does_not_disclose_fixed_expected_values(self):
        task = self.tasks[0]
        result = grade(task["task_id"], {"answer": "wrong", "source_ids": ["wrong"]})
        feedback = result["public_feedback"]
        self.assertEqual(feedback["reasons"], ["incorrect_answer", "incorrect_sources"])
        self.assertNotIn(EXPECTED["cat-breakfast"], canonical(feedback).decode())
        for key in ("answer", "expected", "source_ids", "correct_source_ids"):
            self.assertNotIn(key, feedback)

    def test_output_schemas_and_source_identity_are_bounded_detached_declarations(self):
        for task in self.tasks:
            schema = answer_schema(task["task_id"])
            self.assertEqual(schema["required"], ["answer", "source_ids"])
            self.assertFalse(schema["additionalProperties"])
            self.assertLess(len(canonical(schema)), 8192)
            self.assertNotIn("enum", schema["properties"]["answer"])
        identity = source_identity()
        self.assertEqual(identity["cases"], 50)
        self.assertEqual(identity["catalog_sha256"], digest(home_catalog()))
        self.assertEqual(identity["sha256"], sha256(Path(identity["path"]).read_bytes()))
        schema = answer_schema(self.tasks[0]["task_id"])
        schema["properties"]["source_ids"]["maxItems"] = 999
        self.assertEqual(answer_schema(self.tasks[0]["task_id"])["properties"]["source_ids"]["maxItems"], 3)


if __name__ == "__main__":
    unittest.main()
