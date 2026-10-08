//! Shared wire contracts, not shared application state or authority.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const API: &str = "xnet.fabric.v1";
pub const MAX_FRAME: usize = 262_144;
pub const MAX_OBJECT: usize = 65_536;
pub fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request { pub api: String, pub id: String, pub request: Operation }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag="op", rename_all="snake_case", deny_unknown_fields)]
pub enum Operation {
    Health,
    Sets,
    Seal { text: String },
    Fetch { digest: String },
    Verify,
    PackContext { records: Vec<ContextRecord>, max_bytes: usize },
    ContextDepth { used: u64, window: u64 },
    RankRoutes { observations: Vec<Observation>, candidates: Vec<String>, now_utc: i64 },
    StorageAdmission { tier: String, digest: String, quarantined: Vec<String>, degraded: bool },
    ContextAppend { task_id: String, peer: String, event_id: String, kind: String, text: String, expected_head: Option<String> },
    ContextHistory { task_id: String, after: u64, limit: u32 },
    ContextBind { task_id: String, peer: String, session_id: String, model_sha256: String, runner_sha256: String, window: u64, reserve: u64 },
    ContextOccupancy { task_id: String, peer: String, session_id: String, revision: u64, used: u64, prompt_sha256: String },
    ContextPrepare { task_id: String, peer: String, session_id: String, expected_head: Option<String>, required_ids: Vec<String>, max_bytes: usize },
    ContextAcknowledge { task_id: String, peer: String, plan_id: String, new_session_id: String, capsule_digest: String, prompt_sha256: String, used: u64 },
    ContextState { task_id: String },
    Shutdown,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextRecord { pub id: String, pub kind: String, pub text: String }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation { pub route: String, pub ok: bool, pub latency_ms: u32, pub time_utc: i64 }
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response { pub api: String, pub id: String, pub ok: bool, pub result: serde_json::Value, pub result_sha256: String, pub error: Option<String> }
impl Response {
    pub fn new(id: String, result: Result<serde_json::Value, String>) -> Self {
        let (ok, result, error) = match result { Ok(v) => (true,v,None), Err(e) => (false,serde_json::Value::Null,Some(e)) };
        let hash=digest(&serde_json::to_vec(&result).expect("JSON Value serializes"));
        Self { api: API.into(), id, ok, result, result_sha256: hash, error }
    }
    pub fn verify(&self, id: &str) -> bool {
        self.api==API && self.id==id && self.ok==self.error.is_none() &&
            self.result_sha256==digest(&serde_json::to_vec(&self.result).unwrap_or_default())
    }
}
pub fn parse_request(bytes: &[u8]) -> Result<Request, String> {
    if bytes.len()>MAX_FRAME { return Err("frame_too_large".into()); }
    let strict:StrictValue=serde_json::from_slice(bytes).map_err(|_|"invalid_request".to_string())?;
    let fields=strict.0.get("request").and_then(|v|v.as_object()).ok_or("invalid_request")?;
    let op=fields.get("op").and_then(|v|v.as_str()).ok_or("invalid_request")?;
    let expected:&[&str]=match op {
        "health"|"sets"|"verify"|"shutdown"=>&["op"], "seal"=>&["op","text"], "fetch"=>&["op","digest"],
        "pack_context"=>&["op","records","max_bytes"], "context_depth"=>&["op","used","window"],
        "rank_routes"=>&["op","observations","candidates","now_utc"],
        "storage_admission"=>&["op","tier","digest","quarantined","degraded"],
        "context_append"=>&["op","task_id","peer","event_id","kind","text","expected_head"],
        "context_history"=>&["op","task_id","after","limit"],
        "context_bind"=>&["op","task_id","peer","session_id","model_sha256","runner_sha256","window","reserve"],
        "context_occupancy"=>&["op","task_id","peer","session_id","revision","used","prompt_sha256"],
        "context_prepare"=>&["op","task_id","peer","session_id","expected_head","required_ids","max_bytes"],
        "context_acknowledge"=>&["op","task_id","peer","plan_id","new_session_id","capsule_digest","prompt_sha256","used"],
        "context_state"=>&["op","task_id"], _=>return Err("unknown_operation".into())
    };
    if fields.len()!=expected.len() || fields.keys().any(|k|!expected.contains(&k.as_str())) {return Err("unknown_or_missing_fields".into());}
    let r: Request=serde_json::from_value(strict.0).map_err(|_| "invalid_request".to_string())?;
    if r.api!=API || r.id.is_empty() || r.id.len()>96 || !r.id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_') {
        return Err("invalid_envelope".into());
    }
    Ok(r)
}

/// Bind a rejected body to its valid outer request ID; never admit that body.
pub fn rejected_request_id(bytes: &[u8]) -> String {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope { api:String, id:String, #[serde(rename="request")] _body:serde::de::IgnoredAny }
    if bytes.len()<=MAX_FRAME {
        if let Ok(envelope)=serde_json::from_slice::<Envelope>(bytes) {
            if envelope.api==API && !envelope.id.is_empty() && envelope.id.len()<=96 && envelope.id.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_') {
                return envelope.id;
            }
        }
    }
    "invalid".into()
}
struct StrictValue(serde_json::Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error> {
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value=StrictValue;
            fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result {write!(f,"bounded portable JSON")}
            fn visit_bool<E:serde::de::Error>(self,v:bool)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_i64<E:serde::de::Error>(self,v:i64)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_u64<E:serde::de::Error>(self,v:u64)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_str<E:serde::de::Error>(self,v:&str)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_string<E:serde::de::Error>(self,v:String)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(StrictValue(serde_json::Value::Null))}
            fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut a:A)->Result<Self::Value,A::Error>{
                let mut out=Vec::new();while let Some(v)=a.next_element::<StrictValue>()? {out.push(v.0);}Ok(StrictValue(out.into()))
            }
            fn visit_map<A:serde::de::MapAccess<'de>>(self,mut a:A)->Result<Self::Value,A::Error>{
                let mut out=serde_json::Map::new();while let Some((k,v))=a.next_entry::<String,StrictValue>()? {
                    if out.contains_key(&k){return Err(serde::de::Error::custom("duplicate JSON field"));}out.insert(k,v.0);
                }Ok(StrictValue(out.into()))
            }
        }
        d.deserialize_any(Visitor)
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn rejects_duplicate_unknown_version() {
        for s in [r#"{"api":"xnet.fabric.v1","api":"xnet.fabric.v1","id":"1","request":{"op":"health"}}"#,
                  r#"{"api":"xnet.fabric.v1","id":"1","request":{"op":"health","shell":"x"}}"#,
                  r#"{"api":"v2","id":"1","request":{"op":"health"}}"#] { assert!(parse_request(s.as_bytes()).is_err()); }
    }
    #[test] fn response_binding() {
        let mut r=Response::new("one".into(),Ok(serde_json::json!({"count":1})));
        assert!(r.verify("one")); assert!(!r.verify("two")); r.result=serde_json::json!({"count":2}); assert!(!r.verify("one"));
    }
    #[test] fn context_operations_require_exact_fields_and_explicit_head() {
        let mut request=serde_json::json!({"api":API,"id":"context-1","request":{"op":"context_append","task_id":"task","peer":"assistant","event_id":"one","kind":"fact","text":"exact","expected_head":null}});
        assert!(parse_request(&serde_json::to_vec(&request).unwrap()).is_ok());
        request["request"].as_object_mut().unwrap().remove("expected_head");
        assert!(parse_request(&serde_json::to_vec(&request).unwrap()).is_err());
        request["request"]["expected_head"]=serde_json::Value::Null;
        request["request"]["execute"]=true.into();
        assert!(parse_request(&serde_json::to_vec(&request).unwrap()).is_err());
        for s in [r#"{"api":"xnet.fabric.v1","id":"c","request":{"op":"context_state","task_id":"one","task_id":"two"}}"#,
            r#"{"api":"xnet.fabric.v1","id":"c","request":{"op":"context_occupancy","task_id":"one","peer":"assistant","session_id":"s","revision":1,"used":1.5,"prompt_sha256":"x"}}"#] {assert!(parse_request(s.as_bytes()).is_err());}
    }
}
