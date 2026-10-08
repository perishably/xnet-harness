//! An app may exchange typed requests without importing the runtime or Jcode.
pub use xnet_fabric::{Operation,Request,Response,API,ContextRecord,Observation};
pub fn encode(id:&str,op:Operation)->Result<Vec<u8>,String> {
    let mut b=serde_json::to_vec(&Request{api:API.into(),id:id.into(),request:op}).map_err(|_|"encode_failed")?;
    xnet_fabric::parse_request(&b)?; b.push(b'\n');
    if b.len()>xnet_fabric::MAX_FRAME {return Err("frame_too_large".into());} Ok(b)
}
pub fn decode(id:&str,b:&[u8])->Result<Response,String> {
    if b.len()>xnet_fabric::MAX_FRAME {return Err("frame_too_large".into());}
    let r:Response=serde_json::from_slice(b).map_err(|_|"invalid_response")?;
    if !r.verify(id){return Err("response_binding_failed".into());} Ok(r)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn peer_contract() {
        assert!(encode("app-1",Operation::Health).is_ok()); assert!(encode("bad id",Operation::Health).is_err());
        let r=Response::new("app-1".into(),Ok(serde_json::json!({"ready":true}))); let bytes=serde_json::to_vec(&r).unwrap();
        assert!(decode("app-1",&bytes).is_ok()); assert!(decode("other",&bytes).is_err());
    }
    #[test] fn durable_context_operations_are_plain_typed_peer_requests() {
        let op=Operation::ContextAppend{task_id:"task".into(),peer:"peer".into(),event_id:"one".into(),kind:"raw".into(),text:"same source\r\n".into(),expected_head:None};
        let encoded=encode("append-1",op).unwrap();
        let request=xnet_fabric::parse_request(&encoded).unwrap();
        assert!(matches!(request.request,Operation::ContextAppend{expected_head:None,..}));
        assert!(encode("state-1",Operation::ContextState{task_id:"task".into()}).is_ok());
    }
}
