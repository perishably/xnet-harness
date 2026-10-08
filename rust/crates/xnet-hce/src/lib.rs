//! Native HCE (Hash-Addressed Capsule Encoding) codec.
//!
//! HCE preserves one bounded UTF-8 source byte-for-byte in canonical JSON and
//! binds it to a complete SHA-256 digest. It is deliberately a codec only:
//! it performs no translation, inference, storage, indexing, scope admission,
//! session rotation, or tool execution. The existing Python ledger/CAS path
//! remains the live storage authority until a separately reviewed adapter is
//! added.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const SCHEMA: &str = "xnet.hce-capsule.v1";
pub const MAX_SOURCE_BYTES: usize = 65_536;
pub const MAX_WIRE_BYTES: usize = 262_144;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HceError {
    #[error("complete lowercase SHA256 required")]
    InvalidHash,
    #[error("positive exact integer ring required")]
    InvalidRing,
    #[error("bounded kind identifier required")]
    InvalidKind,
    #[error("explicit caller-selected public classification required")]
    InvalidClassification,
    #[error("bounded nonempty exact UTF-8 source required")]
    InvalidSource,
    #[error("original source pin differs")]
    SourceHashMismatch,
    #[error("bounded canonical wire bytes required")]
    InvalidWire,
    #[error("expected full wire hash differs")]
    WireHashMismatch,
    #[error("canonical JSON object required; normalization forbidden")]
    NonCanonicalWire,
    #[error("capsule schema fields differ")]
    SchemaMismatch,
    #[error("capsule source backpointer differs")]
    SourceBackpointerMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capsule {
    pub classification: String,
    pub kind: String,
    pub ring: u32,
    pub schema: String,
    pub source_sha256: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Face {
    Machine,
    Chinese,
    English,
}

pub fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_kind(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn validate_identity(ring: u32, kind: &str, classification: &str) -> Result<(), HceError> {
    if ring == 0 || ring > i32::MAX as u32 {
        return Err(HceError::InvalidRing);
    }
    if !valid_kind(kind) {
        return Err(HceError::InvalidKind);
    }
    if classification != "public" {
        return Err(HceError::InvalidClassification);
    }
    Ok(())
}

fn validate_source(source: &[u8]) -> Result<&str, HceError> {
    if source.is_empty() || source.len() > MAX_SOURCE_BYTES {
        return Err(HceError::InvalidSource);
    }
    std::str::from_utf8(source).map_err(|_| HceError::InvalidSource)
}

fn canonical_bytes(capsule: &Capsule) -> Result<Vec<u8>, HceError> {
    let mut value = Map::new();
    value.insert(
        "classification".into(),
        Value::String(capsule.classification.clone()),
    );
    value.insert("kind".into(), Value::String(capsule.kind.clone()));
    value.insert("ring".into(), Value::from(capsule.ring));
    value.insert("schema".into(), Value::String(capsule.schema.clone()));
    value.insert(
        "source_sha256".into(),
        Value::String(capsule.source_sha256.clone()),
    );
    value.insert("text".into(), Value::String(capsule.text.clone()));
    serde_json::to_vec(&Value::Object(value)).map_err(|_| HceError::InvalidWire)
}

/// Encode exact public UTF-8 source as canonical HCE v1 JSON.
pub fn encode_capsule(
    source: &[u8],
    expected_source_sha256: &str,
    ring: u32,
    kind: &str,
    classification: &str,
) -> Result<Vec<u8>, HceError> {
    validate_identity(ring, kind, classification)?;
    if !valid_hash(expected_source_sha256) {
        return Err(HceError::InvalidHash);
    }
    let text = validate_source(source)?;
    if sha256(source) != expected_source_sha256 {
        return Err(HceError::SourceHashMismatch);
    }
    let capsule = Capsule {
        classification: classification.into(),
        kind: kind.into(),
        ring,
        schema: SCHEMA.into(),
        source_sha256: expected_source_sha256.into(),
        text: text.into(),
    };
    let bytes = canonical_bytes(&capsule)?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(HceError::InvalidWire);
    }
    Ok(bytes)
}

/// Verify the wire hash, strict schema, canonical form, and source backpointer.
pub fn decode_capsule(raw: &[u8], expected_sha256: &str) -> Result<Capsule, HceError> {
    if !valid_hash(expected_sha256) {
        return Err(HceError::InvalidHash);
    }
    if raw.is_empty() || raw.len() > MAX_WIRE_BYTES {
        return Err(HceError::InvalidWire);
    }
    if sha256(raw) != expected_sha256 {
        return Err(HceError::WireHashMismatch);
    }
    let capsule: Capsule = serde_json::from_slice(raw).map_err(|_| HceError::SchemaMismatch)?;
    if capsule.schema != SCHEMA {
        return Err(HceError::SchemaMismatch);
    }
    validate_identity(capsule.ring, &capsule.kind, &capsule.classification)?;
    if !valid_hash(&capsule.source_sha256) {
        return Err(HceError::InvalidHash);
    }
    let source = capsule.text.as_bytes();
    validate_source(source)?;
    if sha256(source) != capsule.source_sha256 {
        return Err(HceError::SourceBackpointerMismatch);
    }
    if canonical_bytes(&capsule)? != raw {
        return Err(HceError::NonCanonicalWire);
    }
    Ok(capsule)
}

/// Render a deterministic plain-text face. Consumers must still escape it for HTML.
pub fn render_face(capsule: &Capsule, face: Face) -> Result<String, HceError> {
    let raw = canonical_bytes(capsule)?;
    let verified = decode_capsule(&raw, &sha256(&raw))?;
    if face == Face::Machine {
        return String::from_utf8(raw).map_err(|_| HceError::InvalidWire);
    }
    let kind = serde_json::to_string(&verified.kind).map_err(|_| HceError::InvalidWire)?;
    let text = serde_json::to_string(&verified.text).map_err(|_| HceError::InvalidWire)?;
    Ok(match face {
        Face::Chinese => format!(
            "{}号环 | 类型 {} | 源SHA256 {} | 原文 {}",
            verified.ring, kind, verified.source_sha256, text
        ),
        Face::English => format!(
            "Ring {} | kind {} | source SHA256 {} | original text {}",
            verified.ring, kind, verified.source_sha256, text
        ),
        Face::Machine => unreachable!(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_HASH: &str = "4bf6c4d3bda50bc59519a0981d04d203b80817eec786352610d93d5876a85dfd";
    const WIRE_HASH: &str = "d7e245aa64fb5bd502567014901f154bb4463a393be579275d7b14398c00f61c";

    fn vector() -> Vec<u8> {
        encode_capsule(
            "GREEN-FOX-211\n中文".as_bytes(),
            SOURCE_HASH,
            21,
            "codeword",
            "public",
        )
        .unwrap()
    }

    #[test]
    fn matches_python_canonical_vector_and_roundtrips_exact_source() {
        let wire = vector();
        assert_eq!(sha256(&wire), WIRE_HASH);
        let capsule = decode_capsule(&wire, WIRE_HASH).unwrap();
        assert_eq!(capsule.text.as_bytes(), "GREEN-FOX-211\n中文".as_bytes());
        assert_eq!(
            render_face(&capsule, Face::Machine).unwrap().as_bytes(),
            wire
        );
        assert_eq!(
            render_face(&capsule, Face::Chinese).unwrap(),
            "21号环 | 类型 \"codeword\" | 源SHA256 4bf6c4d3bda50bc59519a0981d04d203b80817eec786352610d93d5876a85dfd | 原文 \"GREEN-FOX-211\\n中文\""
        );
    }

    #[test]
    fn tamper_wrong_hash_and_noncanonical_wire_are_refused() {
        let wire = vector();
        let mut tampered = wire.clone();
        let index = tampered.iter().position(|byte| *byte == b'G').unwrap();
        tampered[index] = b'B';
        assert_eq!(
            decode_capsule(&tampered, WIRE_HASH),
            Err(HceError::WireHashMismatch)
        );
        assert_eq!(
            encode_capsule(b"other", SOURCE_HASH, 21, "codeword", "public"),
            Err(HceError::SourceHashMismatch)
        );
        let spaced = String::from_utf8(wire)
            .unwrap()
            .replacen(":\"public\"", ": \"public\"", 1)
            .into_bytes();
        let spaced_hash = sha256(&spaced);
        assert_eq!(
            decode_capsule(&spaced, &spaced_hash),
            Err(HceError::NonCanonicalWire)
        );
    }

    #[test]
    fn invalid_identity_private_source_and_duplicate_fields_are_refused() {
        assert_eq!(
            encode_capsule(b"x", &sha256(b"x"), 0, "fact", "public"),
            Err(HceError::InvalidRing)
        );
        assert_eq!(
            encode_capsule(b"x", &sha256(b"x"), 1, "bad kind", "public"),
            Err(HceError::InvalidKind)
        );
        assert_eq!(
            encode_capsule(b"x", &sha256(b"x"), 1, "fact", "private"),
            Err(HceError::InvalidClassification)
        );
        assert_eq!(
            encode_capsule(&[0xff], &sha256(&[0xff]), 1, "fact", "public"),
            Err(HceError::InvalidSource)
        );
        let duplicate = br#"{"classification":"public","classification":"public","kind":"fact","ring":1,"schema":"xnet.hce-capsule.v1","source_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","text":"x"}"#;
        let hash = sha256(duplicate);
        assert_eq!(
            decode_capsule(duplicate, &hash),
            Err(HceError::SchemaMismatch)
        );
    }
}
