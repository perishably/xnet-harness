use serde_json::{json, Value};
use xnet_system_index::{handle_request, verify_source_bytes, Directory, Request, Status};

fn fixture() -> Value { serde_json::from_str(include_str!("fixtures/protocol.json")).unwrap() }
fn directory() -> Directory { serde_json::from_value(fixture()["directory"].clone()).unwrap() }
fn request(command: &str) -> Request { serde_json::from_value(json!({"schema":"xnet.system-index-request.v1","command":command,"query":"rag","module_id":"","limit":8})).unwrap() }

#[test]
fn python_cross_language_fixture_all_four_commands_match() {
    let fixture = fixture();
    let directory: Directory = serde_json::from_value(fixture["directory"].clone()).unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let request: Request = serde_json::from_value(case["request"].clone()).unwrap();
        assert_eq!(handle_request(&directory, &request).unwrap(), case["expected_response"]);
    }
}

#[test]
fn unknown_command_is_not_an_executor() { assert!(handle_request(&directory(), &request("execute")).is_err()); }

#[test]
fn permission_and_promotion_are_never_granted() {
    let result = handle_request(&directory(), &request("route-plan")).unwrap();
    assert_eq!(result["permission_granted"], false);
    assert_eq!(result["executed_commands"], 0);
    assert_eq!(result["learning_promotions"], 0);
}

#[test]
fn source_drift_is_refused() {
    let entry = directory().entries.pop().unwrap();
    assert!(verify_source_bytes(&entry, b"rag public fixture").is_ok());
    assert!(verify_source_bytes(&entry, b"different source").is_err());
}

#[test]
fn verified_label_requires_check_evidence() {
    let mut entry = directory().entries.pop().unwrap();
    entry.status = Status::Verified;
    assert!(entry.validate().is_err());
}

#[test]
fn wired_label_requires_binding() {
    let mut entry = directory().entries.pop().unwrap();
    entry.status = Status::Wired;
    assert!(entry.validate().is_err());
}

#[test]
fn metadata_cannot_claim_execution_authority() {
    let mut entry = directory().entries.pop().unwrap();
    entry.authority = "execute".into();
    assert!(entry.validate().is_err());
}

#[test]
fn invalid_paths_and_side_effects_refused() {
    let mut entry = directory().entries.pop().unwrap();
    entry.path = "../secret.py".into();
    assert!(entry.validate().is_err());
    entry.path = "rag.py".into();
    entry.side_effects = vec!["local-read".into(), "none".into()];
    assert!(entry.validate().is_err());
}

#[test]
fn directory_edits_break_its_source_bound_digest() {
    let mut directory = directory();
    directory.entries[0].notes = "changed".into();
    assert!(directory.validate().is_err());
}

#[test]
fn typed_duplicate_or_unknown_fields_refused() {
    let raw = br#"{"schema":"xnet.system-index-request.v1","schema":"evil","command":"query","query":"rag","module_id":"","limit":8}"#;
    assert!(serde_json::from_slice::<Request>(raw).is_err());
    let raw = br#"{"schema":"xnet.system-index-request.v1","command":"query","query":"rag","module_id":"","limit":8,"shell":"oops"}"#;
    assert!(serde_json::from_slice::<Request>(raw).is_err());
}

#[test]
fn nullable_source_field_is_still_required() {
    let mut value = fixture()["directory"]["entries"][0].clone();
    value["status"] = json!("pending");
    value.as_object_mut().unwrap().remove("source_sha256");
    assert!(serde_json::from_value::<xnet_system_index::Entry>(value).is_err());
}
