"""Offline fake API, disposable mounts and clocks only. No model or service."""
from __future__ import annotations
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from adapters.loopback import feed_engine as e


class FakeClock:
    def __init__(self):
        self.wall=1_800_000_000.0; self.mono=1000.0
        self.clock=e.Clock(lambda:self.wall,lambda:self.mono)
    def advance(self,seconds): self.wall+=seconds; self.mono+=seconds


class FakeAPI:
    def __init__(self): self.calls=[]; self.sha="1"*40; self.patch="@@ -1 +1 @@\n-old\n+new\n"; self.custom=None
    def __call__(self,url,timeout,clock,deadline):
        e.allowed_url(url); self.calls.append((url,timeout,deadline))
        if self.custom: return self.custom(url)
        body=[{"sha":self.sha}] if url.endswith("?per_page=1") else {
            "sha":self.sha,"files":[{"filename":"src/example.py","patch":self.patch}]}
        return 200,{},e.encode(body)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name)
        for name in ("hot","archive-parent","proton-parent","google-parent"): (self.root/name).mkdir()
        self.config=e.default_config(self.root/"hot/control",self.root/"archive-parent/feed",
            self.root/"proton-parent/feed",self.root/"google-parent/feed")
        self.time=FakeClock(); self.api=FakeAPI(); self.feeds=[]
    def tearDown(self):
        for f in self.feeds: f.close()
        self.temp.cleanup()
    def feed(self,**kwargs):
        obj=e.Feed(self.config,clock=self.time.clock,transport=self.api,installed=False,**kwargs)
        self.feeds.append(obj); return obj

    def test_defaults_are_explicit_portable_paths(self):
        self.assertEqual(self.config["control_root"],str((self.root/"hot/control").resolve()))
        self.assertNotIn("C:/Users/felix",Path(e.__file__).read_text("utf-8"))

    def test_config_rejects_unknown_keys_repo_and_budget(self):
        for change in ({"secret":"ignored"},{"repos":["private/repo"]},{"limits":{}}):
            bad={**self.config,**change}
            with self.assertRaises(e.Refused): e.validate_config(bad,installed=False)

    def test_config_rejects_nested_tiers(self):
        bad=copy.deepcopy(self.config); bad["mirrors"]["proton"]=str(Path(bad["archive_root"])/"proton")
        with self.assertRaises(e.Refused): e.validate_config(bad,installed=False)

    def test_source_pin_drift_refused_before_installed_operation(self):
        bad=copy.deepcopy(self.config); bad["source_pins"]["feed_engine.py"]="0"*64
        with self.assertRaises(e.Refused): e.validate_config(bad)

    def test_url_allowlist_rejects_injection_auth_other_hosts_and_extra_query(self):
        for url in ("https://evil.test/repos/golang/go/commits?per_page=1",
            "https://token@api.github.com/repos/golang/go/commits?per_page=1",
            "https://api.github.com/repos/other/repo/commits?per_page=1",
            "https://api.github.com/repos/golang/go/commits?per_page=1&token=x",
            "http://api.github.com/repos/golang/go/commits?per_page=1",
            "https://api.github.com/repos/golang/go/commits/"+"../x"):
            with self.assertRaises(e.Refused): e.allowed_url(url)
        e.allowed_url("https://api.github.com/repos/golang/go/commits/"+"a"*40)

    def test_ten_requests_first_hour_and_five_when_unchanged(self):
        f=self.feed(); first=f.cycle()
        self.assertEqual(len(self.api.calls),10); self.assertEqual(len(first["projected_descriptors"]),5)
        self.time.advance(e.INTERVAL+1); second=f.cycle()
        self.assertEqual(len(self.api.calls),15)
        self.assertTrue(all(r["status"]=="unchanged" for r in second["acquisition"]))

    def test_no_blind_second_cycle_requests(self):
        f=self.feed(); f.cycle(); f.cycle()
        self.assertEqual(len(self.api.calls),10)

    def test_rolling_request_limit_counts_failures(self):
        f=self.feed(); url="https://api.github.com/repos/golang/go/commits?per_page=1"
        self.api.custom=lambda _: (500,{},e.encode({"message":"temporary"}))
        for _ in range(16): f.request(url,self.time.mono+240)
        with self.assertRaises(e.Refused): f.request(url,self.time.mono+240)
        self.assertEqual(len(self.api.calls),16)

    def test_rate_hold_honors_retry_without_retry(self):
        f=self.feed(); self.api.custom=lambda _: (429,{"Retry-After":"7200","Authorization":"discard"},e.encode({"message":"rate"}))
        result=f.cycle(); self.assertEqual(len(self.api.calls),1)
        self.assertGreaterEqual(f._get("http_hold_until"),self.time.wall+7200)
        f.cycle(); self.assertEqual(len(self.api.calls),1)
        self.assertNotIn("Authorization",json.dumps(result))

    def test_transport_body_cap_and_invalid_json_do_not_advance_cursor(self):
        for payload in (b"x"*(e.MAX_BODY+1),b"not-json"):
            f=self.feed(); self.api.custom=lambda _,payload=payload:(200,{},payload)
            with self.assertRaises((e.Refused,json.JSONDecodeError)):
                f.request("https://api.github.com/repos/golang/go/commits?per_page=1",self.time.mono+240)
            self.assertEqual(f.db.execute("SELECT COUNT(*) FROM cursors").fetchone()[0],0)

    def test_immutable_commit_sha_mismatch_refuses_cursor(self):
        f=self.feed(); raw=e.encode({"sha":"2"*40,"files":[]}); blob=f.seal("blobs/"+e.digest(raw)+".json",raw)
        with self.assertRaises(e.Refused): f.ingest_commit("golang/go","1"*40,json.loads(raw),blob)
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM cursors").fetchone()[0],0)

    def test_exact_json_blob_and_partial_utf8_projection(self):
        f=self.feed(); self.api.patch="汉"*6000; result=f.cycle()
        desc=result["projected_descriptors"][0]; data=(f.archive/desc["relative_path"]).read_bytes()
        self.assertLessEqual(len(data),e.MAX_PATCH); data.decode("utf-8")
        self.assertEqual(e.digest(data),desc["source_sha256"])
        self.assertEqual(desc["provenance"],"practice-stream")
        records=[e.read_json(p) for p in (f.archive/"descriptors").glob("*.json")]
        self.assertTrue(all(p["partial"] and p["locally_truncated"] and p["upstream_license_retained"] for p in records))
        self.assertTrue(all(not p["evaluation_admission"] and not p["lesson_promotion"] for p in records))

    def test_descriptor_exact_index_schema(self):
        f=self.feed(); result=f.cycle(); desc=result["projected_descriptors"][0]
        self.assertEqual(set(desc),{"schema","scope_id","task_id","source_id","adapter","relative_path",
            "repo","revision","source_sha256","source_bytes","language","task_family","tags",
            "provenance","upstream_receipt_sha256"})

    def test_optional_local_only_and_single_cloud_configs(self):
        for names in ((),("proton",)):
            config=copy.deepcopy(self.config); config["mirrors"]={k:v for k,v in config["mirrors"].items() if k in names}
            e.validate_config(config,installed=False)
        self.config["mirrors"]={}; f=self.feed(); result=f.cycle()
        self.assertEqual(result["mirrors"],[]); self.assertEqual(result["status"],"ready")

    def test_credential_shapes_quarantined_locally_never_mirrored(self):
        f=self.feed(); marker="github_pat_"+"A"*40
        self.api.custom=lambda _: (200,{},e.encode({"message":marker}))
        result=f.cycle(); quarantined=list((f.archive/"quarantine/blobs").glob("*.json"))
        self.assertEqual(len(quarantined),1); self.assertIn(marker,quarantined[0].read_text())
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM projections").fetchone()[0],0)
        for path in self.config["mirrors"].values():
            self.assertFalse((Path(path)/"quarantine").exists())
            self.assertTrue(all(marker not in file.read_text() for file in Path(path).rglob("*.json")))

    def test_projection_cap_unsafe_paths_and_missing_patches(self):
        f=self.feed(); files=[{"filename":"../escape","patch":"x"},{"filename":"safe","patch":None}]+[
            {"filename":f"src/{i}.rs","patch":"x"} for i in range(100)]
        raw=e.encode({"sha":"1"*40,"files":files}); h=f.seal("blobs/"+e.digest(raw)+".json",raw)
        projected=f.ingest_commit("golang/go","1"*40,json.loads(raw),h)
        self.assertEqual(len(projected),30); self.assertFalse((self.root/"escape").exists())

    def test_per_repo_cursors_do_not_collide(self):
        f=self.feed(); f.cycle()
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM cursors").fetchone()[0],5)
        self.assertEqual(f.db.execute("SELECT COUNT(*) FROM projections").fetchone()[0],5)

    def test_reopen_deduplicates_and_verifies_cursor(self):
        f=self.feed(); f.cycle(); before=f.verify(); f.close(); self.feeds.remove(f)
        other=self.feed(); self.assertEqual(other.verify(),before); other.cycle()
        self.assertEqual(len(self.api.calls),10)

    def test_mount_absence_does_not_create_parent(self):
        missing=self.root/"unmounted"/"feed"; self.config["mirrors"]["google"]=str(missing)
        f=self.feed(); result=f.cycle()
        self.assertEqual(result["mirrors"][1]["status"],"mount-unavailable")
        self.assertFalse(missing.parent.exists()); self.assertEqual(result["status"],"attention")

    def test_sync_is_idempotent_and_not_remote_upload_proof(self):
        f=self.feed(); f.cycle(); first=f.sync(); second=f.sync()
        self.assertTrue(all(t["status"]=="local-readback-passed" and not t["remote_upload_verified"] for t in first))
        self.assertLessEqual(max(t["copied"] for t in second),1) # Previous sync receipt only.

    def test_cloud_digest_conflict_is_never_overwritten(self):
        f=self.feed(); result=f.cycle(); desc=result["projected_descriptors"][0]
        dest=Path(self.config["mirrors"]["proton"])/desc["relative_path"]
        dest.write_bytes(b"corrupt"); result=f.sync()
        self.assertEqual(dest.read_bytes(),b"corrupt"); self.assertEqual(result[0]["status"],"conflict")

    def test_archive_digest_corruption_holds(self):
        f=self.feed(); f.cycle(); (f.archive/"feed-root.json").write_bytes(b"corrupt")
        with self.assertRaises(e.Refused): f.verify()

    def test_existing_unidentified_root_refused(self):
        root=Path(self.config["archive_root"]); root.mkdir(); (root/"someone-else").write_text("x")
        with self.assertRaises(e.Refused): self.feed()

    def test_seal_no_overwrite_and_quota_fail_closed(self):
        f=self.feed(); f.seal("blobs/test.txt",b"a")
        with self.assertRaises(e.Refused): f.seal("blobs/test.txt",b"b")
        f.used=e.MAX_ARCHIVE
        with self.assertRaises(e.Quota): f.seal("blobs/other.txt",b"a")
        self.assertFalse((f.archive/"blobs/other.txt").exists())

    def test_hash_chain_tamper_refused(self):
        f=self.feed(); f.event("fixture",{"x":1})
        with f.db: f.db.execute("UPDATE events SET hash=? WHERE seq=1",("0"*64,))
        with self.assertRaises(e.Refused): f.verify()

    def test_monotonic_rollback_records_clock_anomaly_without_api(self):
        f=self.feed(); self.time.mono-=10
        with self.assertRaises(e.ClockAnomaly): f.cycle()
        self.assertEqual(self.api.calls,[])
        self.assertIn(b"clock-anomaly",f.db.execute("SELECT payload FROM events").fetchone()[0])

    def test_utc_rollback_across_checkpoint_holds(self):
        f=self.feed(); f._set("last_wall",self.time.wall+100)
        with self.assertRaises(e.ClockAnomaly): f.cycle()
        self.assertEqual(self.api.calls,[])

    def test_transport_return_after_deadline_refused(self):
        f=self.feed()
        def late(url,*_): self.time.advance(16); return 200,{},e.encode([{"sha":"1"*40}])
        f.transport=late
        with self.assertRaises(TimeoutError): f.request("https://api.github.com/repos/golang/go/commits?per_page=1",self.time.mono+240)

    def test_environment_secret_proxy_and_auth_not_used(self):
        f=self.feed()
        with patch.dict(os.environ,{"GITHUB_TOKEN":"DO_NOT_READ","HTTPS_PROXY":"http://secret.invalid"}):
            result=f.cycle()
        joined="".join(p.read_text("utf-8") for p in f.archive.rglob("*.json"))
        self.assertNotIn("DO_NOT_READ",joined); self.assertNotIn("secret.invalid",joined)
        self.assertEqual(len(self.api.calls),10)

    def test_cooperative_stop_is_generation_specific_and_pauses(self):
        control=Path(self.config["control_root"]); control.mkdir(parents=True)
        e.atomic_json(control/"owner.json",{"generation":"fixture-generation","pid":999999})
        result=e.stop(self.config)
        self.assertEqual(result["generation"],"fixture-generation")
        self.assertTrue(e.paused(control)); self.assertEqual(e.execute(self.config,"run")["status"],"paused")

    def test_lease_blocks_second_writer(self):
        path=self.root/"lease/lock"
        with e.lease(path):
            with self.assertRaises(e.Busy):
                with e.lease(path): pass


class TransportTests(unittest.TestCase):
    def test_direct_tls_transport_has_no_auth_proxy_redirect(self):
        observed={}
        class Socket:
            def settimeout(self,value): observed.setdefault("timeouts",[]).append(value)
        class Response:
            status=200; headers={}
            def read1(self,_):
                if observed.get("read"): return b""
                observed["read"]=True; return b"{}"
        class Connection:
            def __init__(self,host,timeout): observed["host"]=host; self.sock=Socket()
            def request(self,method,path,headers): observed.update(method=method,path=path,headers=headers)
            def getresponse(self): return Response()
            def close(self): observed["closed"]=True
        clock=FakeClock()
        with patch.object(e.http.client,"HTTPSConnection",Connection),patch.dict(os.environ,{"GITHUB_TOKEN":"secret","HTTPS_PROXY":"proxy"}):
            result=e.public_http("https://api.github.com/repos/golang/go/commits?per_page=1",15,clock.clock,1015)
        self.assertEqual(result[0],200); self.assertEqual(observed["host"],"api.github.com")
        self.assertNotIn("Authorization",observed["headers"]); self.assertNotIn("Cookie",observed["headers"])
        self.assertTrue(observed["closed"])

    def test_redirect_does_not_follow(self):
        class Socket:
            def settimeout(self,_): pass
        class Connection:
            def __init__(self,*_,**__): self.sock=Socket()
            def request(self,*_,**__): pass
            def getresponse(self): return type("Response",(),{"status":302})()
            def close(self): pass
        clock=FakeClock()
        with patch.object(e.http.client,"HTTPSConnection",Connection):
            with self.assertRaises(e.Refused): e.public_http("https://api.github.com/repos/golang/go/commits?per_page=1",15,clock.clock,1015)


if __name__=="__main__": unittest.main()
