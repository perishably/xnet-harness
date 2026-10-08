//! XNET owns only its root, CAS and audit stream. Clients retain their own lifecycles.
use std::{collections::{BTreeMap,BTreeSet},path::{Path,PathBuf}};
use xnet_fabric::{Operation,ContextRecord,MAX_OBJECT};
use xnet_ledger::{Ledger,Actor,Kind};
use xnet_cas::Cas;
use xnet_gates::Gate;
use serde_json::{json,Value};
mod context_history;

pub struct Runtime { root: PathBuf, cas: Cas, ledger: Ledger, stopped: bool, poisoned: bool }
pub fn checked_path(path: &Path) -> Result<(),String> {
    for p in path.ancestors() {
        if let Ok(m)=std::fs::symlink_metadata(p) {
            if m.file_type().is_symlink() { return Err("linked_storage_path".into()); }
            #[cfg(windows)] { use std::os::windows::fs::MetadataExt; if m.file_attributes() & 0x400 != 0 { return Err("reparse_storage_path".into()); } }
        }
    }
    Ok(())
}
impl Runtime {
    pub fn open(root: &Path) -> Result<Self,String> {
        if !root.is_absolute() || root.components().any(|c|c==std::path::Component::ParentDir) { return Err("absolute_root_required".into()); }
        checked_path(root)?;
        std::fs::create_dir_all(root).map_err(|_|"root_create_failed")?;
        let root=root.canonicalize().map_err(|_|"root_resolve_failed")?;
        checked_path(&root.join("cas"))?; checked_path(&root.join("audit.jsonl"))?;
        let cas=Cas::open(root.join("cas")).map_err(|_|"cas_open_failed")?;
        let ledger=Ledger::open(root.join("audit.jsonl")).map_err(|error| match error {
            xnet_ledger::LedgerError::WriterLeasePresent => "writer_lease_present",
            _ => "ledger_open_failed",
        })?;
        let runtime=Self {root,cas,ledger,stopped:false,poisoned:false};
        context_history::validate(&runtime)?;
        Ok(runtime)
    }
    pub fn stopped(&self)->bool {self.stopped}
    fn seal(&mut self, bytes:&[u8], event:&str)->Result<Value,String> {
        if bytes.len()>MAX_OBJECT {return Err("object_too_large".into());}
        let h=self.cas.put(bytes).map_err(|_|"cas_write_failed")?;
        let mut detail=BTreeMap::new(); detail.insert("event".into(),event.into()); detail.insert("bytes".into(),bytes.len().into());
        let receipt=match self.ledger.append(Kind::Seal,Actor::System,now(),h,detail) {
            Ok(r)=>r, Err(_)=>{self.poisoned=true; return Err("audit_append_failed".into());}
        };
        Ok(json!({"digest":xnet_ledger::hex(h),"bytes":bytes.len(),"receipt_seq":receipt.seq,"receipt_hash":xnet_ledger::hex(receipt.receipt_hash)}))
    }
    pub fn execute(&mut self, op:Operation)->Result<Value,String> {
        if self.stopped {return Err("runtime_stopped".into());}
        if self.poisoned && !matches!(&op,Operation::Shutdown) {return Err("runtime_poisoned".into());}
        // Recheck chain and path before every request; no implicit repair or foreign migration.
        checked_path(&self.root.join("cas"))?; checked_path(&self.root.join("audit.jsonl"))?;
        let (count,head)=Ledger::verify_head(self.root.join("audit.jsonl")).map_err(|_|"audit_integrity_failed")?;
        if count!=self.ledger.next_seq() || head!=self.ledger.tip() {self.poisoned=true; return Err("audit_changed_under_writer".into());}
        match op {
            Operation::Health=>Ok(json!({"service":"xnet","version":env!("CARGO_PKG_VERSION"),"api":xnet_fabric::API,"lifecycle":"running","authority":"local_cas_and_audit_only","model_required":false,"jcode_required":false,"receipt_count":self.ledger.next_seq(),"head":self.ledger.tip().map(xnet_ledger::hex)})),
            Operation::Sets=>Ok(json!({"sets":["ledger","cas","gates","context","router","replay"],"protocol":"xnet.fabric.v1","external_plugins":["zig-kernel","go-medusa","julia-metrics"],"adapter_lifecycle":"separate"})),
            Operation::Seal{text}=>self.seal(text.as_bytes(),"object-seal"),
            Operation::Fetch{digest}=>{
                let h=xnet_ledger::unhex(&digest).ok_or("invalid_digest")?;
                let bytes=self.cas.get(&h).map_err(|_|"object_missing_or_corrupt")?;
                if bytes.len()>MAX_OBJECT {return Err("object_too_large".into());}
                xnet_replay::verify_output_digest(&self.cas,&digest).map_err(|_|"replay_mismatch")?;
                let text=String::from_utf8(bytes).map_err(|_|"object_not_utf8")?;
                Ok(json!({"digest":digest,"text":text}))
            },
            Operation::Verify=>{
                let count=Ledger::verify(self.root.join("audit.jsonl")).map_err(|_|"audit_integrity_failed")?;
                let receipts=xnet_replay::receipts_in_range(&self.root.join("audit.jsonl"),0,u64::MAX).map_err(|_|"replay_failed")?;
                let mut objects=0;
                for r in receipts { if r["kind"]=="seal" { let h=r["payload_hash"].as_str().ok_or("invalid_seal")?; xnet_replay::verify_output_digest(&self.cas,h).map_err(|_|"sealed_object_corrupt")?; objects+=1; } }
                Ok(json!({"ok":true,"receipt_count":count,"sealed_objects_checked":objects,"head":self.ledger.tip().map(xnet_ledger::hex),"external_checkpoint_verified":false}))
            },
            Operation::PackContext{records,max_bytes}=>{
                let pack=pack_context(records.clone(),max_bytes)?;
                // Cold source retention precedes the capsule seal. Omitted notes remain fetchable.
                let mut sources=Vec::new();
                for record in &records {sources.push(self.seal(record.text.as_bytes(),"context-source")?);}
                let bytes=serde_json::to_vec(&pack).map_err(|_|"pack_encode_failed")?;
                let seal=self.seal(&bytes,"context-pack")?;
                Ok(json!({"pack":pack,"seal":seal,"source_seals":sources,"work_performed":false,"authority":"none"}))
            },
            Operation::ContextDepth{used,window}=>{
                if window==0 || used>window {return Err("invalid_occupancy".into());}
                Ok(json!({"used":used,"window":window,"depth":xnet_context::Depth::from_occupancy(used,window),"basis":"caller_reported_current_occupancy","generation":false}))
            },
            Operation::RankRoutes{observations,candidates,now_utc}=>{
                if observations.len()>2048 || candidates.len()>128 || candidates.iter().any(|s|s.is_empty()||s.len()>128) || observations.iter().any(|o|o.route.is_empty()||o.route.len()>128||o.time_utc>now_utc) {return Err("invalid_routing_input".into());}
                let mut router=xnet_router::Router::new(Default::default());
                for o in observations {router.observe(&o.route,o.ok,o.latency_ms as f64,o.time_utc);}
                let cs:Vec<&str>=candidates.iter().map(String::as_str).collect();
                Ok(json!({"route":router.pick(&cs,now_utc),"authority":"ranking_only","fallback_performed":false}))
            },
            Operation::StorageAdmission{tier,digest,quarantined,degraded}=>{
                if tier.len()>32 || digest.len()>128 || quarantined.len()>128 || quarantined.iter().any(|s|s.len()>128) {return Err("invalid_gate_input".into());}
                let op=xnet_gates::Op::StorageRead{tier,digest};
                let ctx=xnet_gates::Ctx{quarantined,degraded,..Default::default()};
                let storage=xnet_gates::StoragePathGate.admit(&op,&ctx);
                let quarantine=xnet_gates::QuarantineGate.admit(&op,&ctx);
                let verdict=if matches!(&storage,xnet_gates::Verdict::Halt{..}) {storage} else if !matches!(&quarantine,xnet_gates::Verdict::Allow) {quarantine} else {storage};
                let body=json!({"verdict":verdict,"authority":"storage_advice_only","target_permission":false});
                let bytes=serde_json::to_vec(&body).map_err(|_|"gate_encode_failed")?;
                let seal=self.seal(&bytes,"storage-admission")?;
                Ok(json!({"admission":body,"seal":seal}))
            },
            context @ (Operation::ContextAppend{..}|Operation::ContextHistory{..}|Operation::ContextBind{..}
                |Operation::ContextOccupancy{..}|Operation::ContextPrepare{..}|Operation::ContextAcknowledge{..}
                |Operation::ContextState{..})=>context_history::execute(self,context),
            Operation::Shutdown=>{self.stopped=true;Ok(json!({"lifecycle":"stopped"}))}
        }
    }
}
fn now()->i64 {std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs().min(i64::MAX as u64) as i64}
pub fn pack_context(records:Vec<ContextRecord>,max_bytes:usize)->Result<Value,String> {
    if !(128..=32768).contains(&max_bytes) || records.len()>256 {return Err("invalid_pack_budget".into());}
    let mut ids=BTreeSet::new();
    for r in &records {
        if r.text.len()>MAX_OBJECT || r.id!=xnet_fabric::digest(r.text.as_bytes()) || !ids.insert(r.id.clone()) || !["fact","decision","open-item","raw"].contains(&r.kind.as_str()) {return Err("invalid_context_source".into());}
    }
    let mut selected=Vec::new();
    let mut omitted:Vec<String>=records.iter().map(|r|r.id.clone()).collect();
    // Reserve every omission pointer and all fixed fields before admitting text.
    let empty=json!({"records":selected,"omitted":omitted,"lossy":!omitted.is_empty(),"context_only":true});
    if serde_json::to_vec(&empty).map_err(|_|"pack_encode_failed")?.len()>max_bytes {return Err("omission_index_exceeds_budget".into());}
    for r in records {
        let mut proposal=selected.clone(); proposal.push(r.clone());
        let remainder:Vec<String>=omitted.iter().filter(|h|*h!=&r.id).cloned().collect();
        let v=json!({"records":proposal,"omitted":remainder,"lossy":!remainder.is_empty(),"context_only":true});
        if serde_json::to_vec(&v).map_err(|_|"pack_encode_failed")?.len()<=max_bytes {selected.push(r); omitted=remainder;}
    }
    let pack=json!({"records":selected,"omitted":omitted,"lossy":!omitted.is_empty(),"context_only":true});
    Ok(pack)
}
#[cfg(test)] mod tests {
    use super::*;
    fn root()->PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        loop {
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("xnet-runtime-{}-{stamp}-{nonce}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot allocate test directory: {error}"),
            }
        }
    }
    #[test] fn separate_lifecycle_durable_integrity() {
        let p=root(); let mut r=Runtime::open(&p).unwrap(); assert!(Runtime::open(&p).is_err());
        let s=r.execute(Operation::Seal{text:"exact\r\ncontext".into()}).unwrap(); let h=s["digest"].as_str().unwrap();
        assert_eq!(r.execute(Operation::Fetch{digest:h.into()}).unwrap()["text"],"exact\r\ncontext");
        assert_eq!(r.execute(Operation::Verify).unwrap()["sealed_objects_checked"],1);
        r.execute(Operation::Shutdown).unwrap(); assert!(r.execute(Operation::Health).is_err()); drop(r);
        let mut r=Runtime::open(&p).unwrap(); assert_eq!(r.execute(Operation::Health).unwrap()["receipt_count"],1); drop(r);
        std::fs::write(p.join("cas").join(&h[..2]).join(h),b"corrupt").unwrap();
        let mut r=Runtime::open(&p).unwrap(); assert!(r.execute(Operation::Verify).is_err()); drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test] fn source_bound_context_and_no_generation() {
        let text="retain the exact note"; let rec=ContextRecord{id:xnet_fabric::digest(text.as_bytes()),kind:"fact".into(),text:text.into()};
        let pack=pack_context(vec![rec.clone()],512).unwrap(); assert_eq!(pack["records"][0]["text"],text); assert_eq!(pack["context_only"],true);
        let mut bad=rec.clone(); bad.text="invented".into(); assert!(pack_context(vec![bad],512).is_err()); assert!(pack_context(vec![rec.clone(),rec],512).is_err());
    }
    #[test] fn degraded_does_not_bypass_halt_and_routing_skips_quarantine() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let a=r.execute(Operation::StorageAdmission{tier:"cold".into(),digest:"h".into(),quarantined:vec![],degraded:true}).unwrap(); assert!(a["admission"]["verdict"]["Halt"].is_object());
        let observations=vec![xnet_fabric::Observation{route:"bad".into(),ok:false,latency_ms:1,time_utc:0};3];
        assert_eq!(r.execute(Operation::RankRoutes{observations,candidates:vec!["bad".into(),"good".into()],now_utc:1}).unwrap()["route"],"good"); drop(r); std::fs::remove_dir_all(p).unwrap();
    }
}
