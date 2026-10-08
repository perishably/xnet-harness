//! Task-bound recorded context. The audit is the commit log; callers own sessions.
use super::{pack_context, Runtime};
use std::collections::{BTreeMap, BTreeSet};
use serde_json::{json, Value};
use xnet_fabric::{ContextRecord, Operation, MAX_OBJECT};

const SCHEMA: &str = "xnet.oroboros.event.v1";
const MAX_TASKS: usize = 64;
const MAX_EVENTS: usize = 2048;
const MAX_SELECTED: usize = 256;

#[derive(Clone)]
struct Event { seq: u64, event_id: String, peer: String, kind: String, source_digest: String, event_digest: String }
impl Event {
    fn value(&self) -> Value { json!({"seq":self.seq,"event_id":self.event_id,"peer":self.peer,"kind":self.kind,"source_digest":self.source_digest,"event_digest":self.event_digest}) }
}
#[derive(Clone)]
struct Session {
    peer: String, session_id: String, model_sha256: String, runner_sha256: String,
    window: u64, reserve: u64, used: Option<u64>, prompt_sha256: Option<String>, revision: u64,
}
impl Session {
    fn value(&self) -> Value {
        json!({"peer":self.peer,"session_id":self.session_id,"model_sha256":self.model_sha256,
            "runner_sha256":self.runner_sha256,"window":self.window,"reserve":self.reserve,
            "used":self.used,"prompt_sha256":self.prompt_sha256,"revision":self.revision,
            "depth":self.used.map(|u|xnet_context::Depth::from_occupancy(u,self.window)),
            "occupancy_basis":"caller_reported_current_snapshot"})
    }
}
#[derive(Clone)]
struct Pending { request: Value, plan: Value }
#[derive(Default)]
struct Task {
    events: Vec<Event>, session: Option<Session>, session_ids: BTreeSet<String>, pending: Option<Pending>,
    acknowledged: BTreeMap<String, (Value, Value)>,
}
impl Task {
    fn head(&self) -> Option<String> { self.events.last().map(|e|e.event_digest.clone()) }
    fn state(&self, task_id: &str) -> Value {
        json!({"schema":"xnet.oroboros.state.v1","task_id":task_id,"history_head":self.head(),
            "history_count":self.events.len(),"session":self.session.as_ref().map(Session::value),
            "pending":self.pending.as_ref().map(|p|p.plan.clone())})
    }
}
#[derive(Default)]
struct History { tasks: BTreeMap<String, Task>, seals: BTreeMap<u64, Value> }

fn fail<T>(message: &str) -> Result<T,String> { Err(message.into()) }
fn id(value: &str) -> Result<(),String> {
    if value.is_empty() || value.len()>128 || !value.bytes().all(|b|b.is_ascii_alphanumeric() || b==b'_' || b==b'-') { return fail("invalid_context_id"); }
    Ok(())
}
fn peer(value: &str) -> Result<(),String> {
    if !["operator","assistant","peer"].contains(&value) {return fail("invalid_context_peer");} Ok(())
}
fn pin(value: &str) -> Result<(),String> {
    if value.len()!=64 || !value.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {return fail("invalid_context_digest");} Ok(())
}
fn head_pin(value: &Option<String>) -> Result<(),String> { if let Some(v)=value {pin(v)?;} Ok(()) }
fn bytes(value: &Value) -> Result<Vec<u8>,String> {serde_json::to_vec(value).map_err(|_|"context_encode_failed".into())}
fn hash(value: &Value) -> Result<String,String> {Ok(xnet_fabric::digest(&bytes(value)?))}
fn fields(value: &Value, names: &[&str]) -> Result<(),String> {
    let map=value.as_object().ok_or("invalid_context_event")?;
    if map.len()!=names.len() || map.keys().any(|k|!names.contains(&k.as_str())) {return fail("invalid_context_event_fields");} Ok(())
}
fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str,String> {value[field].as_str().ok_or_else(||"invalid_context_event".into())}
fn raw(runtime: &Runtime, digest: &str) -> Result<Vec<u8>,String> {
    pin(digest)?;
    let h=xnet_ledger::unhex(digest).ok_or("invalid_context_digest")?;
    runtime.cas.get(&h).map_err(|_|"context_object_missing_or_corrupt".into())
}
fn raw_text(runtime: &Runtime, digest: &str) -> Result<String,String> {
    String::from_utf8(raw(runtime,digest)?).map_err(|_|"context_source_not_utf8".into())
}
fn capacity(db: &History, task_id: &str) -> Result<(),String> {
    if !db.tasks.contains_key(task_id) && db.tasks.len()>=MAX_TASKS {return fail("context_task_capacity");} Ok(())
}
fn task<'a>(db: &'a History, task_id: &str) -> Result<&'a Task,String> {db.tasks.get(task_id).ok_or_else(||"context_task_missing".into())}
fn session<'a>(task: &'a Task, owner: &str, session_id: &str) -> Result<&'a Session,String> {
    peer(owner)?; id(session_id)?;
    let s=task.session.as_ref().ok_or("context_session_missing")?;
    if s.peer!=owner || s.session_id!=session_id {return fail("context_session_owner_mismatch");} Ok(s)
}
fn room(used: u64, reserve: u64, window: u64) -> Result<(),String> {
    if window==0 || reserve>=window || used.checked_add(reserve).map_or(true,|n|n>window) {return fail("context_window_exceeded");} Ok(())
}
fn is_run(used: u64, window: u64) -> bool {u128::from(used)*100>=u128::from(window)*80}
// Depth remains percentage-based. A measured snapshot also needs a handoff
// when the caller's completion reservation no longer fits; exact fit is legal.
fn rotation_due(used: u64, reserve: u64, window: u64) -> bool {
    is_run(used,window) || used.checked_add(reserve).map_or(true,|needed|needed>window)
}
fn request_value(op: &Operation) -> Result<Value,String> {serde_json::to_value(op).map_err(|_|"context_encode_failed".into())}

/// Read only CAS events committed by the existing audit, never orphan objects.
fn load(runtime: &Runtime) -> Result<History,String> {
    let rows=xnet_replay::receipts_in_range(&runtime.root.join("audit.jsonl"),0,u64::MAX).map_err(|_|"context_audit_invalid")?;
    let mut db=History::default();
    for row in rows {
        if row["kind"]!="seal" {continue;}
        if row["detail"]["event"]=="oroboros-event" {
            let digest=text(&row,"payload_hash")?;
            let encoded=raw(runtime,digest)?;
            let event:Value=serde_json::from_slice(&encoded).map_err(|_|"invalid_context_event")?;
            // Canonical bytes also rule out duplicate fields in persisted JSON.
            if bytes(&event)?!=encoded {return fail("noncanonical_context_event");}
            apply(runtime,&mut db,&event,digest)?;
        }
        db.seals.insert(row["seq"].as_u64().ok_or("invalid_context_receipt")?,row);
    }
    Ok(db)
}
pub(super) fn validate(runtime: &Runtime) -> Result<(),String> {load(runtime).map(|_|())}

fn append_check(db:&History, task_id:&str, owner:&str, event_id:&str, kind:&str, source:&str,
                expected_head:&Option<String>) -> Result<Option<Value>,String> {
    id(task_id)?; peer(owner)?; id(event_id)?; pin(source)?; head_pin(expected_head)?; capacity(db,task_id)?;
    if !["fact","decision","open-item","raw"].contains(&kind) {return fail("invalid_context_kind");}
    if let Some(t)=db.tasks.get(task_id) {
        if let Some(e)=t.events.iter().find(|e|e.event_id==event_id) {
            if e.peer!=owner || e.kind!=kind || e.source_digest!=source {return fail("context_event_id_conflict");}
            return Ok(Some(json!({"event":e.value(),"history_head":t.head(),"duplicate":true})));
        }
        if t.pending.is_some() {return fail("context_handoff_pending");}
        if t.events.len()>=MAX_EVENTS {return fail("context_history_capacity");}
        if &t.head()!=expected_head {return fail("context_head_mismatch");}
    } else if expected_head.is_some() {return fail("context_head_mismatch");}
    Ok(None)
}
fn bind_check(db:&History, task_id:&str, s:&Session) -> Result<bool,String> {
    id(task_id)?; peer(&s.peer)?; id(&s.session_id)?; pin(&s.model_sha256)?; pin(&s.runner_sha256)?;
    room(0,s.reserve,s.window)?; capacity(db,task_id)?;
    if let Some(t)=db.tasks.get(task_id) {
        if let Some(old)=&t.session {
            if old.peer==s.peer && old.session_id==s.session_id && old.model_sha256==s.model_sha256
                && old.runner_sha256==s.runner_sha256 && old.window==s.window && old.reserve==s.reserve {return Ok(true);}
            return fail("context_session_already_bound");
        }
        if t.session_ids.contains(&s.session_id) {return fail("context_session_id_reused");}
    }
    Ok(false)
}
fn occupancy_check(db:&History, task_id:&str, owner:&str, session_id:&str, revision:u64,
                   used:u64, prompt:&str) -> Result<bool,String> {
    id(task_id)?; pin(prompt)?;
    let t=task(db,task_id)?; let s=session(t,owner,session_id)?;
    if t.pending.is_some() {return fail("context_handoff_pending");}
    // Report the current absolute snapshot even when no completion reserve remains.
    // Reserve fit is a condition for a fresh ACK, not for observing a full session.
    if s.window==0 || used>s.window {return fail("context_window_exceeded");}
    if revision==0 {return fail("context_revision_invalid");}
    if revision==s.revision {
        if s.used==Some(used) && s.prompt_sha256.as_deref()==Some(prompt) {return Ok(true);}
        return fail("context_revision_conflict");
    }
    if revision<s.revision {return fail("context_revision_stale");} Ok(false)
}
fn prepare_check(db:&History, op:&Operation) -> Result<Option<Value>,String> {
    let Operation::ContextPrepare{task_id,peer:owner,session_id,expected_head,required_ids,max_bytes}=op else {return fail("invalid_context_operation");};
    id(task_id)?; head_pin(expected_head)?;
    let t=task(db,task_id)?; let s=session(t,owner,session_id)?;
    if let Some(p)=&t.pending {
        if p.request==request_value(op)? {return Ok(Some(p.plan.clone()));}
        return fail("context_handoff_pending");
    }
    if &t.head()!=expected_head {return fail("context_head_mismatch");}
    let used=s.used.ok_or("context_occupancy_unknown")?;
    if !rotation_due(used,s.reserve,s.window) {return fail("context_run_threshold_required");}
    if !(128..=32768).contains(max_bytes) || required_ids.len()>MAX_SELECTED {return fail("invalid_context_plan_budget");}
    let mut seen=BTreeSet::new();
    for required in required_ids {
        id(required)?;
        if !seen.insert(required) {return fail("duplicate_context_required_id");}
        if !t.events.iter().any(|e|&e.event_id==required) {return fail("context_required_event_missing");}
    }
    Ok(None)
}
fn records(runtime:&Runtime, t:&Task, task_id:&str, required_ids:&[String]) -> Result<Vec<ContextRecord>,String> {
    let mut selected=Vec::new(); let mut seen=BTreeSet::new();
    for required in required_ids {
        let e=t.events.iter().find(|e|&e.event_id==required).ok_or("context_required_event_missing")?;
        selected.push(e); seen.insert(e.event_id.clone());
    }
    for e in t.events.iter().rev() {
        if selected.len()==MAX_SELECTED {break;}
        if seen.insert(e.event_id.clone()) {selected.push(e);}
    }
    selected.into_iter().map(|e| {
        let source=raw_text(runtime,&e.source_digest)?;
        let envelope=json!({"task_id":task_id,"seq":e.seq,"peer":e.peer,"event_id":e.event_id,
            "kind":e.kind,"source_digest":e.source_digest,"text":source});
        let encoded=bytes(&envelope)?;
        if encoded.len()>MAX_OBJECT {return fail("context_occurrence_too_large");}
        Ok(ContextRecord{id:xnet_fabric::digest(&encoded),kind:e.kind.clone(),text:String::from_utf8(encoded).map_err(|_|"context_encode_failed")?})
    }).collect()
}
fn checked_pack(records:&[ContextRecord], required:usize, max_bytes:usize) -> Result<Value,String> {
    let pack=pack_context(records.to_vec(),max_bytes)?;
    let included:BTreeSet<&str>=pack["records"].as_array().ok_or("invalid_context_pack")?.iter().filter_map(|r|r["id"].as_str()).collect();
    if records.iter().take(required).any(|r|!included.contains(r.id.as_str())) {return fail("mandatory_context_exceeds_budget");}
    Ok(pack)
}
fn seal_check(runtime:&Runtime, db:&History, seal:&Value, digest:&str, event:&str) -> Result<(),String> {
    fields(seal,&["digest","bytes","receipt_seq","receipt_hash"])?;
    let row=db.seals.get(&seal["receipt_seq"].as_u64().ok_or("invalid_context_seal")?).ok_or("uncommitted_context_seal")?;
    if seal["digest"]!=digest || row["payload_hash"]!=digest || row["receipt_hash"]!=seal["receipt_hash"]
        || row["detail"]["event"]!=event || row["detail"]["bytes"]!=seal["bytes"]
        || seal["bytes"].as_u64()!=Some(raw(runtime,digest)?.len() as u64) {return fail("context_seal_binding_failed");}
    Ok(())
}
fn plan_body(t:&Task, task_id:&str, packet:Value) -> Result<Value,String> {
    let s=t.session.as_ref().ok_or("context_session_missing")?;
    Ok(json!({"task_id":task_id,"peer":s.peer,"old_session_id":s.session_id,"model_sha256":s.model_sha256,
        "runner_sha256":s.runner_sha256,"window":s.window,"reserve":s.reserve,"history_head":t.head(),
        "occupancy_revision":s.revision,"prompt_sha256":s.prompt_sha256,"capsule":packet}))
}
fn verify_plan(runtime:&Runtime, db:&History, op:&Operation, plan:&Value) -> Result<(),String> {
    let Operation::ContextPrepare{task_id,required_ids,max_bytes,..}=op else {return fail("invalid_context_operation");};
    fields(plan,&["plan_id","task_id","peer","old_session_id","model_sha256","runner_sha256","window","reserve","history_head","occupancy_revision","prompt_sha256","capsule"])?;
    let packet=&plan["capsule"];
    fields(packet,&["pack","seal","source_seals","work_performed","authority"])?;
    if packet["work_performed"]!=false || packet["authority"]!="none" {return fail("invalid_context_packet_authority");}
    let t=task(db,task_id)?;
    let sources=records(runtime,t,task_id,required_ids)?;
    if packet["pack"]!=checked_pack(&sources,required_ids.len(),*max_bytes)? {return fail("context_pack_mismatch");}
    let seals=packet["source_seals"].as_array().ok_or("invalid_context_source_seals")?;
    if seals.len()!=sources.len() {return fail("invalid_context_source_seals");}
    for (source,seal) in sources.iter().zip(seals) {
        seal_check(runtime,db,seal,&source.id,"context-source")?;
        if raw(runtime,&source.id)?!=source.text.as_bytes() {return fail("context_occurrence_mismatch");}
    }
    let capsule_digest=hash(&packet["pack"])?;
    seal_check(runtime,db,&packet["seal"],&capsule_digest,"context-pack")?;
    if raw(runtime,&capsule_digest)?!=bytes(&packet["pack"])? {return fail("context_capsule_mismatch");}
    let mut expected=plan_body(t,task_id,packet.clone())?;
    let plan_id=hash(&expected)?; expected["plan_id"]=plan_id.into();
    if &expected!=plan {return fail("context_plan_binding_failed");} Ok(())
}
fn ack_check(db:&History, op:&Operation) -> Result<Option<Value>,String> {
    let Operation::ContextAcknowledge{task_id,peer:owner,plan_id,new_session_id,capsule_digest,prompt_sha256,used}=op else {return fail("invalid_context_operation");};
    id(task_id)?; peer(owner)?; id(new_session_id)?; pin(plan_id)?; pin(capsule_digest)?; pin(prompt_sha256)?;
    let t=task(db,task_id)?;
    if let Some((request,response))=t.acknowledged.get(plan_id) {
        if request==&request_value(op)? {return Ok(Some(response.clone()));}
        return fail("context_acknowledgment_conflict");
    }
    let p=t.pending.as_ref().ok_or("context_handoff_missing")?;
    let s=t.session.as_ref().ok_or("context_session_missing")?;
    if s.peer!=*owner || p.plan["plan_id"]!=*plan_id || p.plan["capsule"]["seal"]["digest"]!=*capsule_digest {return fail("context_acknowledgment_mismatch");}
    if t.session_ids.contains(new_session_id) {return fail("context_session_id_reused");}
    room(*used,s.reserve,s.window)?;
    let pack=&p.plan["capsule"]["pack"];
    let nonempty=!pack["records"].as_array().ok_or("invalid_context_pack")?.is_empty()
        || !pack["omitted"].as_array().ok_or("invalid_context_pack")?.is_empty();
    if (nonempty && *used==0) || is_run(*used,s.window) {return fail("context_fresh_capacity_required");}
    Ok(None)
}

/// Validate and apply one committed event to an in-memory projection only.
fn apply(runtime:&Runtime, db:&mut History, event:&Value, event_digest:&str) -> Result<Value,String> {
    if event["schema"]!=SCHEMA {return fail("invalid_context_event_schema");}
    let mut request=event["request"].clone();
    if request["op"]=="context_append" {
        fields(event,&["schema","request","source_digest"])?;
        if request.get("text").is_some() {return fail("invalid_context_source_request");}
        let source=text(event,"source_digest")?;
        if !db.seals.values().any(|r|r["payload_hash"]==source && r["detail"]["event"]=="oroboros-source") {return fail("uncommitted_context_source");}
        request["text"]=raw_text(runtime,source)?.into();
    } else if request["op"]=="context_prepare" {fields(event,&["schema","request","plan"])?;}
    else {fields(event,&["schema","request"])?;}
    let envelope=json!({"api":xnet_fabric::API,"id":"context-replay","request":request});
    let op=xnet_fabric::parse_request(&bytes(&envelope)?)?.request;
    match &op {
        Operation::ContextAppend{task_id,peer,event_id,kind,text,expected_head}=>{
            let source=xnet_fabric::digest(text.as_bytes());
            if event["source_digest"]!=source || append_check(db,task_id,peer,event_id,kind,&source,expected_head)?.is_some() {return fail("duplicate_or_invalid_committed_context_event");}
            let t=db.tasks.entry(task_id.clone()).or_default();
            let e=Event{seq:t.events.len() as u64,event_id:event_id.clone(),peer:peer.clone(),kind:kind.clone(),source_digest:source,event_digest:event_digest.into()};
            let result=json!({"event":e.value(),"history_head":event_digest,"duplicate":false});
            t.events.push(e); Ok(result)
        },
        Operation::ContextBind{task_id,peer,session_id,model_sha256,runner_sha256,window,reserve}=>{
            let s=Session{peer:peer.clone(),session_id:session_id.clone(),model_sha256:model_sha256.clone(),runner_sha256:runner_sha256.clone(),window:*window,reserve:*reserve,used:None,prompt_sha256:None,revision:0};
            if bind_check(db,task_id,&s)? {return fail("duplicate_committed_context_bind");}
            let t=db.tasks.entry(task_id.clone()).or_default(); t.session_ids.insert(session_id.clone()); t.session=Some(s); Ok(t.state(task_id))
        },
        Operation::ContextOccupancy{task_id,peer,session_id,revision,used,prompt_sha256}=>{
            if occupancy_check(db,task_id,peer,session_id,*revision,*used,prompt_sha256)? {return fail("duplicate_committed_context_occupancy");}
            let t=db.tasks.get_mut(task_id).ok_or("context_task_missing")?;
            let s=t.session.as_mut().ok_or("context_session_missing")?; s.used=Some(*used); s.prompt_sha256=Some(prompt_sha256.clone()); s.revision=*revision; Ok(t.state(task_id))
        },
        Operation::ContextPrepare{task_id,..}=>{
            if prepare_check(db,&op)?.is_some() {return fail("duplicate_committed_context_plan");}
            verify_plan(runtime,db,&op,&event["plan"])?;
            db.tasks.get_mut(task_id).ok_or("context_task_missing")?.pending=Some(Pending{request:request_value(&op)?,plan:event["plan"].clone()}); Ok(event["plan"].clone())
        },
        Operation::ContextAcknowledge{task_id,plan_id,new_session_id,used,prompt_sha256,..}=>{
            if ack_check(db,&op)?.is_some() {return fail("duplicate_committed_context_acknowledgment");}
            let t=db.tasks.get_mut(task_id).ok_or("context_task_missing")?;
            let s=t.session.as_mut().ok_or("context_session_missing")?;
            s.session_id=new_session_id.clone(); s.used=Some(*used); s.prompt_sha256=Some(prompt_sha256.clone()); s.revision=0;
            t.session_ids.insert(new_session_id.clone()); t.pending=None;
            let response=t.state(task_id); t.acknowledged.insert(plan_id.clone(),(request_value(&op)?,response.clone())); Ok(response)
        },
        _=>fail("invalid_committed_context_operation"),
    }
}
fn commit(runtime:&mut Runtime, event:Value) -> Result<Value,String> {
    let encoded=bytes(&event)?;
    if encoded.len()>MAX_OBJECT {return fail("context_event_too_large");}
    let digest=xnet_fabric::digest(&encoded);
    // Project first. The projection is discarded on failure; only seal's audit append commits.
    let mut db=load(runtime)?;
    let response=apply(runtime,&mut db,&event,&digest)?;
    runtime.seal(&encoded,"oroboros-event")?;
    Ok(response)
}

pub(super) fn execute(runtime:&mut Runtime, op:Operation) -> Result<Value,String> {
    let db=load(runtime)?;
    let request=request_value(&op)?;
    match &op {
        Operation::ContextState{task_id}=>{id(task_id)?; Ok(db.tasks.get(task_id).map(|t|t.state(task_id)).unwrap_or_else(||Task::default().state(task_id)))},
        Operation::ContextHistory{task_id,after,limit}=>{
            id(task_id)?; if !(1..=32).contains(limit) {return fail("invalid_context_page_limit");}
            let empty=Task::default(); let t=db.tasks.get(task_id).unwrap_or(&empty);
            let page:Vec<Value>=t.events.iter().filter(|e|e.seq>=*after).take(*limit as usize).map(Event::value).collect();
            let next=page.last().and_then(|e|e["seq"].as_u64()).map(|n|n+1).filter(|n|(*n as usize)<t.events.len());
            Ok(json!({"task_id":task_id,"history_head":t.head(),"history_count":t.events.len(),"events":page,"next_after":next}))
        },
        Operation::ContextAppend{task_id,peer,event_id,kind,text,expected_head}=>{
            if text.len()>MAX_OBJECT {return fail("object_too_large");}
            let source=xnet_fabric::digest(text.as_bytes());
            if let Some(result)=append_check(&db,task_id,peer,event_id,kind,&source,expected_head)? {return Ok(result);}
            let mut saved=request; saved.as_object_mut().ok_or("context_encode_failed")?.remove("text");
            let event=json!({"schema":SCHEMA,"request":saved,"source_digest":source});
            if bytes(&event)?.len()>MAX_OBJECT {return fail("context_event_too_large");}
            runtime.seal(text.as_bytes(),"oroboros-source")?;
            commit(runtime,event)
        },
        Operation::ContextBind{task_id,peer,session_id,model_sha256,runner_sha256,window,reserve}=>{
            let s=Session{peer:peer.clone(),session_id:session_id.clone(),model_sha256:model_sha256.clone(),runner_sha256:runner_sha256.clone(),window:*window,reserve:*reserve,used:None,prompt_sha256:None,revision:0};
            if bind_check(&db,task_id,&s)? {return Ok(task(&db,task_id)?.state(task_id));}
            commit(runtime,json!({"schema":SCHEMA,"request":request}))
        },
        Operation::ContextOccupancy{task_id,peer,session_id,revision,used,prompt_sha256}=>{
            if occupancy_check(&db,task_id,peer,session_id,*revision,*used,prompt_sha256)? {return Ok(task(&db,task_id)?.state(task_id));}
            commit(runtime,json!({"schema":SCHEMA,"request":request}))
        },
        Operation::ContextPrepare{task_id,required_ids,max_bytes,..}=>{
            if let Some(plan)=prepare_check(&db,&op)? {return Ok(plan);}
            let t=task(&db,task_id)?;
            let sources=records(runtime,t,task_id,required_ids)?;
            checked_pack(&sources,required_ids.len(),*max_bytes)?;
            let packet=runtime.execute(Operation::PackContext{records:sources,max_bytes:*max_bytes})?;
            let mut plan=plan_body(t,task_id,packet)?; let plan_id=hash(&plan)?; plan["plan_id"]=plan_id.into();
            commit(runtime,json!({"schema":SCHEMA,"request":request,"plan":plan}))
        },
        Operation::ContextAcknowledge{..}=>{
            if let Some(response)=ack_check(&db,&op)? {return Ok(response);}
            commit(runtime,json!({"schema":SCHEMA,"request":request}))
        },
        _=>fail("invalid_context_operation"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    fn root()->PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        loop {
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir().join(format!("xnet-context-history-{}-{stamp}-{nonce}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot allocate test directory: {error}"),
            }
        }
    }
    fn pin()->String {"a".repeat(64)}
    fn state(r:&mut Runtime,t:&str)->Value {r.execute(Operation::ContextState{task_id:t.into()}).unwrap()}
    fn append(t:&str,p:&str,e:&str,text:&str,head:Option<String>)->Operation {Operation::ContextAppend{task_id:t.into(),peer:p.into(),event_id:e.into(),kind:"fact".into(),text:text.into(),expected_head:head}}
    fn head(v:&Value)->Option<String> {v["history_head"].as_str().map(str::to_owned)}
    fn bind(t:&str)->Operation {Operation::ContextBind{task_id:t.into(),peer:"assistant".into(),session_id:"s1".into(),model_sha256:pin(),runner_sha256:"b".repeat(64),window:1000,reserve:100}}
    fn occupancy(t:&str,revision:u64,used:u64)->Operation {Operation::ContextOccupancy{task_id:t.into(),peer:"assistant".into(),session_id:"s1".into(),revision,used,prompt_sha256:pin()}}
    fn prepare(t:&str,head:Option<String>,required:Vec<String>)->Operation {Operation::ContextPrepare{task_id:t.into(),peer:"assistant".into(),session_id:"s1".into(),expected_head:head,required_ids:required,max_bytes:4096}}
    fn ack(t:&str,plan:&Value,new_session:&str,used:u64)->Operation {Operation::ContextAcknowledge{task_id:t.into(),peer:"assistant".into(),plan_id:plan["plan_id"].as_str().unwrap().into(),new_session_id:new_session.into(),capsule_digest:plan["capsule"]["seal"]["digest"].as_str().unwrap().into(),prompt_sha256:"c".repeat(64),used}}
    fn count(r:&mut Runtime)->u64 {r.execute(Operation::Health).unwrap()["receipt_count"].as_u64().unwrap()}
    fn setup_plan(r:&mut Runtime)->Value {
        let a=r.execute(append("task","operator","e1","verbatim\r\nnotes \u{03bb}",None)).unwrap();
        r.execute(bind("task")).unwrap(); r.execute(occupancy("task",1,800)).unwrap();
        r.execute(prepare("task",head(&a),vec!["e1".into()])).unwrap()
    }
    #[test]
    fn durable_three_peer_occurrences_head_races_and_pages() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let a=r.execute(append("task","operator","e1","same raw text",None)).unwrap();
        assert!(r.execute(append("task","peer","raced","same raw text",None)).is_err());
        let b=r.execute(append("task","peer","e2","same raw text",head(&a))).unwrap();
        let c=r.execute(append("task","assistant","e3","same raw text",head(&b))).unwrap();
        assert_eq!(a["event"]["source_digest"],c["event"]["source_digest"]);
        assert_ne!(a["event"]["event_digest"],b["event"]["event_digest"]);
        assert_ne!(b["event"]["event_digest"],c["event"]["event_digest"]);
        let before=count(&mut r);
        let retry=r.execute(append("task","operator","e1","same raw text",None)).unwrap();
        assert_eq!(retry["event"],a["event"]); assert_eq!(retry["duplicate"],true); assert_eq!(count(&mut r),before);
        assert!(r.execute(append("task","operator","e1","changed",None)).is_err());
        assert!(r.execute(append("task","assistant","e1","same raw text",None)).is_err());
        drop(r); let mut r=Runtime::open(&p).unwrap();
        let page=r.execute(Operation::ContextHistory{task_id:"task".into(),after:0,limit:2}).unwrap();
        assert_eq!(page["history_count"],3); assert_eq!(page["next_after"],2); assert_eq!(page["events"][0],a["event"]);
        let tail=r.execute(Operation::ContextHistory{task_id:"task".into(),after:2,limit:2}).unwrap();
        assert_eq!(tail["events"][0],c["event"]); assert!(tail["next_after"].is_null());
        assert!(r.execute(Operation::ContextHistory{task_id:"task".into(),after:0,limit:33}).is_err());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn task_isolation_and_uncommitted_objects() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let a=r.execute(append("one","operator","event-one","private to task one",None)).unwrap();
        r.execute(append("two","peer","event-two","private to task two",None)).unwrap();
        r.execute(bind("two")).unwrap(); r.execute(occupancy("two",1,800)).unwrap();
        let h=head(&state(&mut r,"two"));
        assert!(r.execute(prepare("two",h,vec!["event-one".into()])).is_err());
        assert!(r.execute(append("two","assistant","stale","x",head(&a))).is_err());
        let orphan=r.cas.put(b"uncommitted raw source").unwrap();
        r.seal(b"raw source with no history commit","oroboros-source").unwrap();
        drop(r); let mut r=Runtime::open(&p).unwrap();
        assert_eq!(state(&mut r,"one")["history_count"],1); assert_eq!(state(&mut r,"two")["history_count"],1);
        assert_eq!(state(&mut r,"missing")["history_count"],0);
        assert!(r.cas.get(&orphan).is_ok());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn occupancy_is_unknown_then_absolute_and_revision_bound() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let first=r.execute(bind("task")).unwrap(); assert!(first["session"]["used"].is_null()); assert!(first["session"]["depth"].is_null());
        let n=count(&mut r); assert_eq!(r.execute(bind("task")).unwrap(),first); assert_eq!(count(&mut r),n);
        assert!(r.execute(prepare("task",None,vec![])).is_err());
        for (revision,used) in [(0,100),(1,1001),(1,u64::MAX)] {assert!(r.execute(occupancy("task",revision,used)).is_err());}
        assert_eq!(r.execute(occupancy("task",1,500)).unwrap()["session"]["depth"],"Bike");
        let n=count(&mut r); r.execute(occupancy("task",1,500)).unwrap(); assert_eq!(count(&mut r),n);
        assert!(r.execute(occupancy("task",1,501)).is_err());
        assert!(r.execute(prepare("task",None,vec![])).is_err());
        let lower=r.execute(occupancy("task",2,100)).unwrap(); assert_eq!(lower["session"]["used"],100); assert_eq!(lower["session"]["depth"],"Swim");
        assert!(r.execute(occupancy("task",1,500)).is_err());
        let mut other=occupancy("task",3,800); if let Operation::ContextOccupancy{peer,..}=&mut other {*peer="peer".into();}
        assert!(r.execute(other).is_err());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn plans_bind_occurrence_sources_and_freeze_mutations() {
        let p=root(); let mut r=Runtime::open(&p).unwrap(); let plan=setup_plan(&mut r);
        let packet=&plan["capsule"]; let occurrence=&packet["pack"]["records"][0];
        let parsed:Value=serde_json::from_str(occurrence["text"].as_str().unwrap()).unwrap();
        assert_eq!(parsed["task_id"],"task"); assert_eq!(parsed["event_id"],"e1"); assert_eq!(parsed["text"],"verbatim\r\nnotes \u{03bb}");
        assert_eq!(packet["source_seals"][0]["digest"],occurrence["id"]);
        assert_eq!(r.execute(Operation::Fetch{digest:parsed["source_digest"].as_str().unwrap().into()}).unwrap()["text"],parsed["text"]);
        let n=count(&mut r); let h=head(&plan);
        assert_eq!(r.execute(prepare("task",h.clone(),vec!["e1".into()])).unwrap(),plan); assert_eq!(count(&mut r),n);
        assert!(r.execute(prepare("task",h.clone(),vec![])).is_err());
        assert!(r.execute(append("task","peer","e2","later",h)).is_err());
        assert!(r.execute(occupancy("task",2,850)).is_err());
        drop(r); let mut r=Runtime::open(&p).unwrap(); assert_eq!(state(&mut r,"task")["pending"],plan);
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn acknowledgment_checks_room_identity_and_replays_after_restart() {
        let p=root(); let mut r=Runtime::open(&p).unwrap(); let plan=setup_plan(&mut r);
        for (new_id,used) in [("s1",100),("s2",0),("s2",800),("s2",901)] {assert!(r.execute(ack("task",&plan,new_id,used)).is_err());}
        let mut wrong=ack("task",&plan,"s2",100); if let Operation::ContextAcknowledge{capsule_digest,..}=&mut wrong {*capsule_digest="f".repeat(64);}
        assert!(r.execute(wrong).is_err());
        let good=ack("task",&plan,"s2",100); let result=r.execute(good.clone()).unwrap();
        assert!(result["pending"].is_null()); assert_eq!(result["session"]["revision"],0); assert_eq!(result["session"]["used"],100);
        assert_eq!(result["session"]["model_sha256"],pin());
        drop(r); let mut r=Runtime::open(&p).unwrap(); let n=count(&mut r);
        assert_eq!(r.execute(good).unwrap(),result); assert_eq!(count(&mut r),n);
        assert!(r.execute(ack("task",&plan,"s3",100)).is_err());
        assert!(r.execute(bind("task")).is_err());
        let mut snapshot=occupancy("task",1,800); if let Operation::ContextOccupancy{session_id,..}=&mut snapshot {*session_id="s2".into();}
        r.execute(snapshot).unwrap();
        let mut next=prepare("task",head(&result),vec!["e1".into()]); if let Operation::ContextPrepare{session_id,..}=&mut next {*session_id="s2".into();}
        let next=r.execute(next).unwrap(); assert!(r.execute(ack("task",&next,"s1",100)).is_err());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn mandatory_capacity_and_identifiers_fail_before_history_change() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        for (t,peer,event) in [("bad task","operator","e"),("task","other","e"),("task","assistant","")] {assert!(r.execute(append(t,peer,event,"data",None)).is_err());}
        let a=r.execute(append("task","operator","e1",&"x".repeat(1500),None)).unwrap();
        r.execute(bind("task")).unwrap(); r.execute(occupancy("task",1,800)).unwrap();
        let mut small=prepare("task",head(&a),vec!["e1".into()]); if let Operation::ContextPrepare{max_bytes,..}=&mut small {*max_bytes=512;}
        let n=count(&mut r); assert!(r.execute(small).is_err()); assert_eq!(count(&mut r),n); assert!(state(&mut r,"task")["pending"].is_null());
        assert!(r.execute(prepare("task",head(&a),vec!["e1".into(),"e1".into()])).is_err());
        let mut optional=prepare("task",head(&a),vec![]); if let Operation::ContextPrepare{max_bytes,..}=&mut optional {*max_bytes=512;}
        let plan=r.execute(optional).unwrap(); assert_eq!(plan["capsule"]["pack"]["records"],json!([]));
        assert!(!plan["capsule"]["pack"]["omitted"].as_array().unwrap().is_empty());
        assert!(r.execute(ack("task",&plan,"s2",0)).is_err());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn every_replay_rehashes_committed_sources_events_and_capsules() {
        for target in ["source","event","capsule"] {
            let p=root(); let mut r=Runtime::open(&p).unwrap(); let plan=setup_plan(&mut r);
            let page=r.execute(Operation::ContextHistory{task_id:"task".into(),after:0,limit:1}).unwrap();
            let h=match target {"source"=>page["events"][0]["source_digest"].as_str().unwrap(),"event"=>page["events"][0]["event_digest"].as_str().unwrap(),_=>plan["capsule"]["seal"]["digest"].as_str().unwrap()}.to_owned();
            std::fs::write(p.join("cas").join(&h[..2]).join(h),b"changed").unwrap();
            assert!(r.execute(Operation::ContextState{task_id:"task".into()}).is_err()); drop(r);
            assert!(Runtime::open(&p).is_err()); std::fs::remove_dir_all(p).unwrap();
        }
    }
    #[test]
    fn explicit_task_and_history_capacity_without_eviction() {
        let mut db=History::default();
        for i in 0..MAX_TASKS {db.tasks.insert(format!("task-{i}"),Task::default());}
        assert!(capacity(&db,"extra").is_err()); assert!(capacity(&db,"task-0").is_ok());
        let event=Event{seq:0,event_id:"old".into(),peer:"operator".into(),kind:"raw".into(),source_digest:pin(),event_digest:pin()};
        db.tasks.get_mut("task-0").unwrap().events=vec![event;MAX_EVENTS];
        assert!(append_check(&db,"task-0","peer","new","fact",&pin(),&Some(pin())).is_err());
        assert_eq!(db.tasks["task-0"].events.len(),MAX_EVENTS);
    }
    #[test]
    fn full_old_snapshot_can_rotate_but_fresh_ack_requires_reserved_room() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let a=r.execute(append("task","operator","e1","actual source",None)).unwrap();
        let mut binding=bind("task"); if let Operation::ContextBind{reserve,..}=&mut binding {*reserve=300;}
        r.execute(binding).unwrap(); r.execute(occupancy("task",1,1000)).unwrap();
        let plan=r.execute(prepare("task",head(&a),vec!["e1".into()])).unwrap();
        assert!(r.execute(ack("task",&plan,"s2",750)).is_err());
        assert!(r.execute(ack("task",&plan,"s2",700)).is_ok());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn reserve_trigger_uses_actual_snapshot_with_exact_fit_and_durable_plan() {
        let p=root(); let mut r=Runtime::open(&p).unwrap();
        let a=r.execute(append("task","operator","e1",&"x".repeat(1500),None)).unwrap();
        let mut binding=bind("task");
        if let Operation::ContextBind{window,reserve,..}=&mut binding {*window=2048;*reserve=650;}
        r.execute(binding).unwrap();
        let fit=r.execute(occupancy("task",1,1398)).unwrap();
        assert_eq!(fit["session"]["depth"],"Bike");
        let before=count(&mut r);
        assert!(r.execute(prepare("task",head(&a),vec!["e1".into()])).is_err());
        assert_eq!(count(&mut r),before);
        let overflow=r.execute(occupancy("task",2,1399)).unwrap();
        assert_eq!(overflow["session"]["depth"],"Bike");
        let mut small=prepare("task",head(&a),vec!["e1".into()]);
        if let Operation::ContextPrepare{max_bytes,..}=&mut small {*max_bytes=512;}
        let before=count(&mut r);
        assert!(r.execute(small).is_err());
        assert_eq!(count(&mut r),before);
        assert!(state(&mut r,"task")["pending"].is_null());
        let request=prepare("task",head(&a),vec!["e1".into()]);
        let plan=r.execute(request.clone()).unwrap();
        let before=count(&mut r);
        assert_eq!(r.execute(request).unwrap(),plan);
        assert_eq!(count(&mut r),before);
        assert!(r.execute(ack("task",&plan,"s2",1399)).is_err());
        drop(r); let mut r=Runtime::open(&p).unwrap();
        assert_eq!(state(&mut r,"task")["pending"],plan);
        assert!(r.execute(ack("task",&plan,"s2",1398)).is_ok());
        drop(r); std::fs::remove_dir_all(p).unwrap();
    }
    #[test]
    fn rotation_threshold_keeps_run_and_does_not_overflow() {
        assert!(!rotation_due(1398,650,2048));
        assert!(rotation_due(1399,650,2048));
        assert!(!rotation_due(1638,100,2048));
        assert!(rotation_due(1639,100,2048));
        assert!(!rotation_due(u64::MAX/2,u64::MAX/2,u64::MAX));
        assert!(rotation_due(u64::MAX/2+1,u64::MAX/2+1,u64::MAX));
    }
}
