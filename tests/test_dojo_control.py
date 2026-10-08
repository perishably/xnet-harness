"""Owned loopback controls: fixed actions, admission and truthful stop states."""
import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from adapters.dojo.control import DojoController, DojoError, DojoTools, make_server
from xnet.scope import ScopeAuthority, ScopeError

class OwnedWorker:
    def __init__(self):
        self.starts = 0
        self.stops = 0
        self.value = {"state": "idle", "active": False, "accepting": False,
                      "completed_tasks": 0, "pending_tasks": 0,
                      "completed_epochs": 0, "max_epochs": 3, "wall_seconds": 0.0,
                      "home_completed": 0, "home_total": 50,
                      "home_first_correct": 0, "home_final_correct": 0}

    def status(self):
        return dict(self.value)

    def start(self):
        self.starts += 1
        self.value.update(state="running", active=True, accepting=True, worker_pid=123)
        return self.status()

    def stop(self):
        self.stops += 1
        self.value.update(state="draining" if self.value["active"] else "stopped", accepting=False)
        return self.status()

    def next_dispatch(self):
        return self.value["accepting"]

class DojoControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xnet-dojo-control-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.audit = self.root / "private-audit"
        self.authority = ScopeAuthority(self.root / "private-authority")
        self.scope = self.authority.create(program="owned Dojo loopback fixture", policy_url="",
            policy_capture=b"fixed loopback control fixture", allowed_assets=["path:" + str(self.audit)],
            methods=list(DojoTools.METHODS), fixture=True, requests_per_minute=600)
        self.worker = OwnedWorker()
        self.control = DojoController(start=self.worker.start, stop=self.worker.stop,
            status=self.worker.status, authority=self.authority, scope_id=self.scope["scope_id"], audit_dir=self.audit)
        self.server = make_server(self.control)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, route, *, method="POST", body="{}", headers=None):
        fields = {"Origin": self.origin, "Authorization": "Bearer " + self.server.token,
                  "Content-Type": "application/json"}
        fields.update(headers or {})
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, route, body=body if method == "POST" else None, headers=fields)
            response = connection.getresponse()
            raw = response.read()
            return response.status, raw, dict(response.getheaders())
        finally:
            connection.close()

    def test_authenticated_start_stop_and_independent_pending_status(self):
        code, raw, _ = self.request("/api/start")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["status"]["state"], "running")
        self.assertEqual(json.loads(raw)["status"]["home_total"], 50)
        self.assertTrue(self.worker.next_dispatch())
        code, raw, _ = self.request("/api/stop")
        self.assertEqual(code, 200)
        returned = json.loads(raw)["status"]
        self.assertEqual(returned["state"], "draining")
        self.assertTrue(returned["active"])
        self.assertFalse(returned["accepting"])
        self.assertFalse(self.worker.next_dispatch())
        self.worker.value.update(state="pending", active=False, pending_tasks=1)
        code, raw, _ = self.request("/api/status")
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(raw)["status"]["pending_tasks"], 1)
        self.assertEqual((self.worker.starts, self.worker.stops), (1, 1))
        self.assertEqual(self.control.ledger.verify_chain()["events"], 6)

    def test_host_origin_token_and_cross_site_rejected_before_callbacks(self):
        for headers, expected in (({"Host": "localhost:" + str(self.server.server_port)}, 403),
                                  ({"Origin": "https://example.test"}, 403),
                                  ({"Authorization": "Bearer " + "0" * 64}, 401),
                                  ({"Authorization": "Bearer \u00a3"}, 401),
                                  ({"Sec-Fetch-Site": "cross-site"}, 403)):
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/api/start", headers=headers)[0], expected)
        self.assertEqual(self.worker.starts, 0)
        self.assertEqual(self.control.ledger.verify_chain()["events"], 0)

    def test_duplicate_origin_and_authorization_rejected(self):
        for field, values, expected in (("Origin", [self.origin, self.origin], 403),
            ("Authorization", ["Bearer " + self.server.token] * 2, 401)):
            connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
            try:
                connection.putrequest("POST", "/api/start")
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", "2")
                if field != "Origin":
                    connection.putheader("Origin", self.origin)
                if field != "Authorization":
                    connection.putheader("Authorization", "Bearer " + self.server.token)
                for value in values:
                    connection.putheader(field, value)
                connection.endheaders(b"{}")
                response = connection.getresponse()
                self.assertEqual(response.status, expected)
                response.read()
            finally:
                connection.close()
        self.assertEqual(self.worker.starts, 0)

    def test_arbitrary_commands_oversize_unknown_routes_and_chunking_rejected(self):
        for route, body, headers, expected in (("/api/start", '{"command":"anything"}', {}, 400),
            ("/api/start", " " * 257, {}, 400), ("/api/launch", "{}", {}, 404),
            ("/api/start?command=x", "{}", {}, 404),
            ("/api/start", "{}", {"Transfer-Encoding": "chunked"}, 400)):
            with self.subTest(route=route, body_bytes=len(body), headers=headers):
                self.assertEqual(self.request(route, body=body, headers=headers)[0], expected)
        self.assertEqual(self.worker.starts, 0)

    def test_assets_use_fixed_paths_csp_and_no_embedded_token(self):
        for route in ("/", "/style.css", "/app.js"):
            code, raw, headers = self.request(route, method="GET")
            self.assertEqual(code, 200)
            self.assertNotIn(self.server.token.encode(), raw)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertEqual(self.request("/../control.py", method="GET")[0], 404)
        self.assertEqual(self.request("/api/status", method="GET")[0], 404)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")
        self.assertIn("/#token=", self.server.dashboard_url)

    def test_scope_tampering_prevents_callbacks(self):
        path = self.authority.scope_dir / (self.scope["scope_id"] + ".json")
        value = json.loads(path.read_text())
        value["methods"].remove("dojo_start")
        path.write_text(json.dumps(value))
        self.assertEqual(self.request("/api/start")[0], 403)
        self.assertEqual(self.worker.starts, 0)
        self.assertEqual(self.request("/api/status")[0], 403)

    def test_stop_callback_cannot_claim_dispatch_remains_open(self):
        self.worker.start()
        self.control.callbacks["stop"] = self.worker.status
        self.assertEqual(self.request("/api/stop")[0], 400)
        self.assertEqual(self.control.ledger.events()[-1]["kind"], "dojo.control.failed")

    def test_scope_rate_budget_and_status_contract_fail_closed(self):
        scope = self.authority.create(program="owned rate fixture", policy_url="",
            policy_capture=b"rate test", allowed_assets=["path:" + str(self.audit)],
            methods=list(DojoTools.METHODS), fixture=True, requests_per_minute=1)
        self.control.scope_id = scope["scope_id"]
        self.assertEqual(self.request("/api/status")[0], 200)
        self.assertEqual(self.request("/api/start")[0], 429)
        self.assertEqual(self.worker.starts, 0)
        self.control.scope_id = self.scope["scope_id"]
        self.worker.value["command"] = "not accepted"
        self.assertEqual(self.request("/api/status")[0], 400)

    def test_mutations_are_serial_and_stop_closes_next_dispatch(self):
        entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
        def start():
            entered.set()
            release.wait(timeout=2)
            return self.worker.start()
        def stop():
            result = self.worker.stop()
            stopped.set()
            return result
        self.control.callbacks.update(start=start, stop=stop)
        errors = []
        def call(action):
            try:
                self.control.call(action)
            except Exception as error:
                errors.append(error)
        first = threading.Thread(target=call, args=("start",))
        second = threading.Thread(target=call, args=("stop",))
        first.start()
        self.assertTrue(entered.wait(timeout=1))
        second.start()
        self.assertFalse(stopped.wait(timeout=0.05))
        release.set()
        first.join(timeout=2)
        second.join(timeout=2)
        self.assertFalse(errors)
        self.assertTrue(stopped.is_set())
        self.assertFalse(self.worker.next_dispatch())

    def test_unknown_control_and_weak_tokens_are_rejected(self):
        with self.assertRaises(DojoError):
            self.control.call("command")
        with self.assertRaises(DojoError):
            make_server(self.control, token="short")
        with self.assertRaises(DojoError):
            make_server(self.control, port=-1)

if __name__ == "__main__":
    unittest.main()
