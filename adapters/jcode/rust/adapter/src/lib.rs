//! Jcode policy stays here; XNET sees a versioned context request, never Jcode internals.
pub use jcode_xnet_policy as policy;
pub use jcode_xnet_scope as scope;
pub fn context_frame(id:&str, records:Vec<xnet_sdk::ContextRecord>, max_bytes:usize)->Result<Vec<u8>,String> {
    xnet_sdk::encode(id,xnet_sdk::Operation::PackContext{records,max_bytes})
}
#[cfg(test)] mod tests {
    #[test] fn independent_peer_request() {
        let text="operator decision";
        let records=vec![xnet_sdk::ContextRecord{id:"b".repeat(64),kind:"decision".into(),text:text.into()}];
        let frame=super::context_frame("jcode-1",records,1024).unwrap();
        assert!(std::str::from_utf8(&frame).unwrap().contains("pack_context"));
        // The runtime, not this client, validates source hashes. The adapter cannot admit targets.
        assert!(super::context_frame("invalid id",vec![],1024).is_err());
    }
}
