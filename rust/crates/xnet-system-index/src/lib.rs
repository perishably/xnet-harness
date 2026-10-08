//! Source-bound component discovery. No execution, authority or promotion API.
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

fn required_optional_string<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> { Option::<String>::deserialize(deserializer) }

pub const DIRECTORY_SCHEMA: &str = "xnet.system-directory.v1";
pub const REQUEST_SCHEMA: &str = "xnet.system-index-request.v1";
pub const RESPONSE_SCHEMA: &str = "xnet.system-index-response.v1";

#[derive(Debug, Error)]
#[error("system directory refused: {0}")]
pub struct CatalogError(pub String);

fn reject(message: &str) -> CatalogError { CatalogError(message.into()) }
fn hash(value: &str) -> bool { value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) }
fn identifier(value: &str) -> bool { (1..=192).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || b"_.:@/-".contains(&byte)) }
fn path(value: &str) -> bool {
    if value.is_empty() || value.len() > 384 || value.starts_with('/') || value.contains(':') || value.contains('\\') { return false; }
    let lower = value.to_ascii_lowercase();
    if value.split('/').any(|part| part.is_empty() || part == "." || part == "..") { return false; }
    if lower.split('/').any(|part| [".ssh", ".env", "credentials", "private_selftest", "evaluator-only", "protected-dataset"].contains(&part)) { return false; }
    ![".key", ".pem", ".pfx", ".parquet", ".gguf", ".qcow2"].iter().any(|suffix| lower.ends_with(suffix))
}
fn strings(values: &[String], maximum: usize, identifiers: bool) -> bool {
    values.len() <= maximum && values.windows(2).all(|pair| pair[0] < pair[1]) && values.iter().all(|value| if identifiers { identifier(value) } else { !value.is_empty() && value.len() <= 512 && !value.chars().any(|char| (char as u32) < 32) })
}
pub fn sha256(raw: &[u8]) -> String { format!("{:x}", Sha256::digest(raw)) }
fn digest(value: &Value) -> String { sha256(&serde_json::to_vec(value).expect("validated JSON value")) }

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status { Implemented, Wired, Verified, Inactive, Pending, Evidence }
impl Status {
    fn label(&self) -> &'static str { match self { Self::Implemented => "implemented", Self::Wired => "wired", Self::Verified => "verified", Self::Inactive => "inactive", Self::Pending => "pending", Self::Evidence => "evidence" } }
    fn route_candidate(&self) -> bool { matches!(self, Self::Implemented | Self::Wired | Self::Verified) }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub path: String,
    pub sha256: String,
    pub source_sha256: String,
    pub claim: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub module_id: String,
    pub path: String,
    #[serde(deserialize_with = "required_optional_string")]
    pub source_sha256: Option<String>,
    pub language: String,
    pub status: Status,
    pub features: Vec<String>,
    pub call_contract: Vec<String>,
    pub scopes: Vec<String>,
    pub side_effects: Vec<String>,
    pub evidence: Vec<Evidence>,
    pub notes: String,
    pub authority: String,
}

impl Entry {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if !identifier(&self.module_id) || !path(&self.path) || self.authority != "discovery-only" { return Err(reject("identity, path or permission claim")); }
        if !["python", "rust", "go", "zig", "julia", "powershell", "json", "markdown", "toml"].contains(&self.language.as_str()) { return Err(reject("language")); }
        if let Some(pin) = &self.source_sha256 { if !hash(pin) { return Err(reject("source hash")); } }
        else if self.status != Status::Pending { return Err(reject("only pending entries may lack source")); }
        if !strings(&self.features, 32, true) || !strings(&self.scopes, 16, true) || !strings(&self.call_contract, 32, false) || !strings(&self.side_effects, 8, true) { return Err(reject("bounded sorted fields")); }
        if self.side_effects.is_empty() || self.side_effects.iter().any(|effect| !["none", "local-read", "local-write", "network", "model-call", "process-control", "container", "user-interface"].contains(&effect.as_str())) || (self.side_effects.iter().any(|effect| effect == "none") && self.side_effects.len() != 1) { return Err(reject("side effects")); }
        if self.notes.len() > 1024 || self.notes.chars().any(|char| (char as u32) < 32) || self.evidence.len() > 8 { return Err(reject("notes/evidence bound")); }
        for proof in &self.evidence {
            if !path(&proof.path) || !hash(&proof.sha256) || !hash(&proof.source_sha256) || Some(&proof.source_sha256) != self.source_sha256.as_ref() || !["offline-check", "live-development", "source-integrity", "integration-binding", "historical-evidence"].contains(&proof.claim.as_str()) { return Err(reject("source-bound evidence")); }
        }
        if self.status == Status::Verified && !self.evidence.iter().any(|proof| ["offline-check", "live-development", "source-integrity"].contains(&proof.claim.as_str())) { return Err(reject("verified requires source-bound check")); }
        if self.status == Status::Wired && !self.evidence.iter().any(|proof| proof.claim == "integration-binding") { return Err(reject("wired requires source-bound binding")); }
        if matches!(self.status, Status::Inactive | Status::Pending) && self.notes.is_empty() { return Err(reject("limitation required")); }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Directory {
    pub schema: String,
    pub created_utc: String,
    pub entries: Vec<Entry>,
    pub directory_sha256: String,
}
impl Directory {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema != DIRECTORY_SCHEMA || self.created_utc.is_empty() || self.created_utc.chars().count() > 64 || self.entries.is_empty() || self.entries.len() > 4096 || !hash(&self.directory_sha256) { return Err(reject("directory shape/bounds")); }
        for entry in &self.entries { entry.validate()?; }
        if !self.entries.windows(2).all(|pair| pair[0].module_id < pair[1].module_id) { return Err(reject("unique sorted identities")); }
        let body = json!({"schema": self.schema, "created_utc": self.created_utc, "entries": self.entries});
        if digest(&body) != self.directory_sha256 { return Err(reject("directory hash differs")); }
        Ok(())
    }
    pub fn status_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for status in ["implemented", "wired", "verified", "inactive", "pending", "evidence"] { counts.insert(status.into(), 0); }
        for entry in &self.entries { *counts.get_mut(entry.status.label()).expect("status key") += 1; }
        counts
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub schema: String,
    pub command: String,
    pub query: String,
    pub module_id: String,
    pub limit: usize,
}
fn query_terms(value: &str) -> BTreeSet<String> {
    let mut terms = BTreeSet::new();
    let lower = value.to_lowercase();
    for run in lower.split(|char: char| !(char.is_ascii_alphanumeric() || char == '_')) {
        for chunk in run.as_bytes().chunks(64) {
            if chunk.len() >= 2 { terms.insert(String::from_utf8(chunk.to_vec()).expect("ASCII query term")); }
        }
    }
    terms
}

pub fn handle_request(directory: &Directory, request: &Request) -> Result<Value, CatalogError> {
    directory.validate()?;
    if request.schema != REQUEST_SCHEMA || !["list", "query", "select", "route-plan"].contains(&request.command.as_str()) { return Err(reject("unknown command or request schema; execution not provided")); }
    if !(1..=128).contains(&request.limit) || request.query.len() > 512 || request.module_id.chars().count() > 192 { return Err(reject("request bounds")); }
    let mut selected: Vec<&Entry>;
    if request.command == "select" {
        if !identifier(&request.module_id) { return Err(reject("selection identity")); }
        selected = directory.entries.iter().filter(|entry| entry.module_id == request.module_id).collect();
        if selected.is_empty() { return Err(reject("unknown module")); }
    } else if request.command == "query" || request.command == "route-plan" {
        let terms = query_terms(&request.query);
        if terms.is_empty() { return Err(reject("query terms required")); }
        let mut scored: Vec<(usize, &Entry)> = directory.entries.iter().filter_map(|entry| {
            let mut text = vec![entry.module_id.clone(), entry.path.clone()];
            text.extend(entry.features.clone()); text.extend(entry.call_contract.clone());
            let text = text.join(" ").to_lowercase();
            let score = terms.iter().filter(|term| text.contains(term.as_str())).count();
            (score > 0).then_some((score, entry))
        }).collect();
        scored.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.module_id.cmp(&right.1.module_id)));
        selected = scored.into_iter().map(|(_, entry)| entry).collect();
    } else { selected = directory.entries.iter().collect(); }
    selected.truncate(request.limit);
    let mut result = json!({"schema": RESPONSE_SCHEMA, "command": request.command, "directory_sha256": directory.directory_sha256, "entries": selected, "status_counts": directory.status_counts(), "authority": "discovery-only", "permission_granted": false, "executed_commands": 0, "learning_promotions": 0});
    if request.command == "route-plan" {
        let plan: Vec<Value> = selected.iter().enumerate().filter(|(_, entry)| entry.status.route_candidate()).map(|(number, entry)| json!({"order": number + 1, "module_id": entry.module_id, "source_sha256": entry.source_sha256, "required_scopes": entry.scopes, "side_effects": entry.side_effects, "status": "candidate-needs-current-source-and-caller-gate"})).collect();
        result["route_plan"] = json!(plan);
    }
    Ok(result)
}

/// The caller supplies already scoped source bytes. Discovery grants no read.
pub fn verify_source_bytes(entry: &Entry, bytes: &[u8]) -> Result<Value, CatalogError> {
    entry.validate()?;
    if bytes.len() > 2 * 1024 * 1024 || entry.source_sha256.as_ref() != Some(&sha256(bytes)) { return Err(reject("source drift or bound")); }
    Ok(json!({"module_id": entry.module_id, "source_sha256": entry.source_sha256, "bytes": bytes.len(), "source_verified": true, "permission_granted": false}))
}
