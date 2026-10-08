//! Native HALO (Hash-Addressed Long-context Observation) profile advice.
//!
//! A context pin belongs to one complete engine configuration. This crate
//! validates the identity and reports whether a caller-measured prompt has
//! reached its review point. It does no tokenization, inference, persistence,
//! rotation, or authority grant. Needle recall evidence does not establish
//! long-context reasoning quality.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const PROFILE_SCHEMA: &str = "xnet.halo-engine-profile.v1";
pub const ADVICE_SCHEMA: &str = "xnet.halo-context-advice.v1";
const MAX_TOKENS: u64 = 1_048_576;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HaloError {
    #[error("bounded engine identifier required")]
    InvalidEngineId,
    #[error("complete lowercase SHA256 required")]
    InvalidHash,
    #[error("bounded exact token count required")]
    InvalidTokenCount,
    #[error("reserve must leave prompt capacity")]
    InvalidReserve,
    #[error("review margin must precede the proven-good point")]
    InvalidReviewMargin,
    #[error("bounded unique immutable evidence pins required")]
    InvalidEvidence,
    #[error("this policy does not establish reasoning quality")]
    InvalidPurpose,
    #[error("pin belongs to a different engine configuration")]
    ProfileMismatch,
    #[error("recall point leaves insufficient generation headroom")]
    InsufficientHeadroom,
    #[error("frozen policy differs; use a new registry")]
    RegistryConflict,
    #[error("observed loaded profile differs")]
    ObservedProfileMismatch,
    #[error("no explicit policy for this profile")]
    PolicyMissing,
    #[error("rendered prompt plus reserve exceeds the capacity")]
    CapacityExceeded,
    #[error("canonical profile serialization failed")]
    Serialization,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EngineProfile {
    engine_id: String,
    model_sha256: String,
    runner_bundle_sha256: String,
    tokenizer_sha256: String,
    template_sha256: String,
    configuration_sha256: String,
    capacity_tokens: u64,
    generation_reserve_tokens: u64,
}

impl EngineProfile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        engine_id: impl Into<String>,
        model_sha256: impl Into<String>,
        runner_bundle_sha256: impl Into<String>,
        tokenizer_sha256: impl Into<String>,
        template_sha256: impl Into<String>,
        configuration_sha256: impl Into<String>,
        capacity_tokens: u64,
        generation_reserve_tokens: u64,
    ) -> Result<Self, HaloError> {
        let profile = Self {
            engine_id: engine_id.into(),
            model_sha256: model_sha256.into(),
            runner_bundle_sha256: runner_bundle_sha256.into(),
            tokenizer_sha256: tokenizer_sha256.into(),
            template_sha256: template_sha256.into(),
            configuration_sha256: configuration_sha256.into(),
            capacity_tokens,
            generation_reserve_tokens,
        };
        profile.validate()?;
        Ok(profile)
    }

    fn validate(&self) -> Result<(), HaloError> {
        if !valid_id(&self.engine_id) {
            return Err(HaloError::InvalidEngineId);
        }
        for value in [
            &self.model_sha256,
            &self.runner_bundle_sha256,
            &self.tokenizer_sha256,
            &self.template_sha256,
            &self.configuration_sha256,
        ] {
            require_hash(value)?;
        }
        require_tokens(self.capacity_tokens, 1)?;
        require_tokens(self.generation_reserve_tokens, 0)?;
        if self.generation_reserve_tokens >= self.capacity_tokens {
            return Err(HaloError::InvalidReserve);
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String, HaloError> {
        self.validate()?;
        let mut value = Map::new();
        value.insert("capacity_tokens".into(), Value::from(self.capacity_tokens));
        value.insert(
            "configuration_sha256".into(),
            Value::String(self.configuration_sha256.clone()),
        );
        value.insert("engine_id".into(), Value::String(self.engine_id.clone()));
        value.insert(
            "generation_reserve_tokens".into(),
            Value::from(self.generation_reserve_tokens),
        );
        value.insert(
            "model_sha256".into(),
            Value::String(self.model_sha256.clone()),
        );
        value.insert(
            "runner_bundle_sha256".into(),
            Value::String(self.runner_bundle_sha256.clone()),
        );
        value.insert("schema".into(), Value::String(PROFILE_SCHEMA.into()));
        value.insert(
            "template_sha256".into(),
            Value::String(self.template_sha256.clone()),
        );
        value.insert(
            "tokenizer_sha256".into(),
            Value::String(self.tokenizer_sha256.clone()),
        );
        let bytes =
            serde_json::to_vec(&Value::Object(value)).map_err(|_| HaloError::Serialization)?;
        Ok(hex_digest(&bytes))
    }

    pub fn capacity_tokens(&self) -> u64 {
        self.capacity_tokens
    }

    pub fn generation_reserve_tokens(&self) -> u64 {
        self.generation_reserve_tokens
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContextPinProposal {
    profile_sha256: String,
    review_tokens: u64,
    proven_good_tokens: u64,
    evidence_sha256s: Vec<String>,
    purpose: String,
}

impl ContextPinProposal {
    pub fn new(
        profile_sha256: impl Into<String>,
        review_tokens: u64,
        proven_good_tokens: u64,
        evidence_sha256s: Vec<String>,
    ) -> Result<Self, HaloError> {
        let proposal = Self {
            profile_sha256: profile_sha256.into(),
            review_tokens,
            proven_good_tokens,
            evidence_sha256s,
            purpose: "needle-recall-only".into(),
        };
        proposal.validate()?;
        Ok(proposal)
    }

    fn validate(&self) -> Result<(), HaloError> {
        require_hash(&self.profile_sha256)?;
        require_tokens(self.review_tokens, 1)?;
        require_tokens(self.proven_good_tokens, 1)?;
        if self.review_tokens >= self.proven_good_tokens {
            return Err(HaloError::InvalidReviewMargin);
        }
        if self.evidence_sha256s.is_empty() || self.evidence_sha256s.len() > 16 {
            return Err(HaloError::InvalidEvidence);
        }
        let mut unique = BTreeSet::new();
        for pin in &self.evidence_sha256s {
            require_hash(pin).map_err(|_| HaloError::InvalidEvidence)?;
            if !unique.insert(pin) {
                return Err(HaloError::InvalidEvidence);
            }
        }
        if self.purpose != "needle-recall-only" {
            return Err(HaloError::InvalidPurpose);
        }
        Ok(())
    }

    pub fn validate_for(&self, profile: &EngineProfile) -> Result<(), HaloError> {
        self.validate()?;
        if profile.sha256()? != self.profile_sha256 {
            return Err(HaloError::ProfileMismatch);
        }
        let needed = self
            .proven_good_tokens
            .checked_add(profile.generation_reserve_tokens)
            .ok_or(HaloError::InsufficientHeadroom)?;
        if needed > profile.capacity_tokens {
            return Err(HaloError::InsufficientHeadroom);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextAdvice {
    pub schema: String,
    pub profile_sha256: String,
    pub rendered_prompt_sha256: String,
    pub measured_prompt_tokens: u64,
    pub capacity_tokens: u64,
    pub generation_reserve_tokens: u64,
    pub review_tokens: u64,
    pub review_due: bool,
    pub remaining_after_reserve: u64,
    pub evidence_sha256s: Vec<String>,
    pub identity_basis: String,
    pub purpose: String,
    pub authority: String,
    pub rotation_performed: bool,
}

#[derive(Debug, Default)]
pub struct HaloPinRegistry {
    entries: BTreeMap<String, (EngineProfile, ContextPinProposal)>,
}

impl HaloPinRegistry {
    pub fn register(
        &mut self,
        profile: EngineProfile,
        proposal: ContextPinProposal,
    ) -> Result<String, HaloError> {
        proposal.validate_for(&profile)?;
        let identity = profile.sha256()?;
        let entry = (profile, proposal);
        if let Some(existing) = self.entries.get(&identity) {
            if existing != &entry {
                return Err(HaloError::RegistryConflict);
            }
            return Ok(identity);
        }
        self.entries.insert(identity.clone(), entry);
        Ok(identity)
    }

    pub fn advise(
        &self,
        profile_sha256: &str,
        observed_profile_sha256: &str,
        rendered_prompt_sha256: &str,
        measured_prompt_tokens: u64,
    ) -> Result<ContextAdvice, HaloError> {
        require_hash(profile_sha256)?;
        require_hash(observed_profile_sha256)?;
        require_hash(rendered_prompt_sha256)?;
        require_tokens(measured_prompt_tokens, 0)?;
        if observed_profile_sha256 != profile_sha256 {
            return Err(HaloError::ObservedProfileMismatch);
        }
        let (profile, proposal) = self
            .entries
            .get(profile_sha256)
            .ok_or(HaloError::PolicyMissing)?;
        proposal.validate_for(profile)?;
        let required = measured_prompt_tokens
            .checked_add(profile.generation_reserve_tokens)
            .ok_or(HaloError::CapacityExceeded)?;
        if required > profile.capacity_tokens {
            return Err(HaloError::CapacityExceeded);
        }
        Ok(ContextAdvice {
            schema: ADVICE_SCHEMA.into(),
            profile_sha256: profile_sha256.into(),
            rendered_prompt_sha256: rendered_prompt_sha256.into(),
            measured_prompt_tokens,
            capacity_tokens: profile.capacity_tokens,
            generation_reserve_tokens: profile.generation_reserve_tokens,
            review_tokens: proposal.review_tokens,
            review_due: measured_prompt_tokens >= proposal.review_tokens,
            remaining_after_reserve: profile.capacity_tokens - required,
            evidence_sha256s: proposal.evidence_sha256s.clone(),
            identity_basis: "caller-attested-current-profile".into(),
            purpose: proposal.purpose.clone(),
            authority: "none".into(),
            rotation_performed: false,
        })
    }
}

fn require_hash(value: &str) -> Result<(), HaloError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(HaloError::InvalidHash)
    }
}

fn require_tokens(value: u64, minimum: u64) -> Result<(), HaloError> {
    if (minimum..=MAX_TOKENS).contains(&value) {
        Ok(())
    } else {
        Err(HaloError::InvalidTokenCount)
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> EngineProfile {
        EngineProfile::new(
            "qwen-fixture",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            8192,
            650,
        )
        .unwrap()
    }

    fn proposal(profile: &EngineProfile) -> ContextPinProposal {
        ContextPinProposal::new(profile.sha256().unwrap(), 6500, 7000, vec!["f".repeat(64)])
            .unwrap()
    }

    #[test]
    fn profile_hash_matches_python_contract_vector() {
        assert_eq!(
            profile().sha256().unwrap(),
            "b9e341f7ca0f8ac46f5a531e3a995f8a43fb7a8142cb881f1695354178e496b7"
        );
    }

    #[test]
    fn exact_boundary_reserve_and_advice_labels() {
        let profile = profile();
        let identity = profile.sha256().unwrap();
        let mut registry = HaloPinRegistry::default();
        registry
            .register(profile.clone(), proposal(&profile))
            .unwrap();
        let before = registry
            .advise(&identity, &identity, &"0".repeat(64), 6499)
            .unwrap();
        assert!(!before.review_due);
        let at = registry
            .advise(&identity, &identity, &"0".repeat(64), 6500)
            .unwrap();
        assert!(at.review_due);
        assert_eq!(at.authority, "none");
        assert!(!at.rotation_performed);
        let exact = registry
            .advise(&identity, &identity, &"0".repeat(64), 7542)
            .unwrap();
        assert_eq!(exact.remaining_after_reserve, 0);
        assert_eq!(
            registry.advise(&identity, &identity, &"0".repeat(64), 7543),
            Err(HaloError::CapacityExceeded)
        );
    }

    #[test]
    fn pin_cannot_cross_profiles_or_silently_change() {
        let first = profile();
        let first_id = first.sha256().unwrap();
        let lite = EngineProfile::new(
            "lite-fixture",
            "a".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "d".repeat(64),
            "e".repeat(64),
            4096,
            650,
        )
        .unwrap();
        assert_eq!(
            proposal(&first).validate_for(&lite),
            Err(HaloError::ProfileMismatch)
        );
        let mut registry = HaloPinRegistry::default();
        registry.register(first.clone(), proposal(&first)).unwrap();
        let changed =
            ContextPinProposal::new(first_id.clone(), 6400, 7000, vec!["f".repeat(64)]).unwrap();
        assert_eq!(
            registry.register(first, changed),
            Err(HaloError::RegistryConflict)
        );
        assert_eq!(
            registry.advise(&first_id, &lite.sha256().unwrap(), &"0".repeat(64), 1),
            Err(HaloError::ObservedProfileMismatch)
        );
    }

    #[test]
    fn malformed_identity_evidence_and_headroom_are_refused() {
        assert_eq!(
            EngineProfile::new(
                "bad id",
                "a".repeat(64),
                "b".repeat(64),
                "c".repeat(64),
                "d".repeat(64),
                "e".repeat(64),
                8192,
                650,
            ),
            Err(HaloError::InvalidEngineId)
        );
        let profile = profile();
        assert_eq!(
            ContextPinProposal::new(profile.sha256().unwrap(), 6500, 7000, vec![]),
            Err(HaloError::InvalidEvidence)
        );
        let too_deep =
            ContextPinProposal::new(profile.sha256().unwrap(), 7500, 8000, vec!["f".repeat(64)])
                .unwrap();
        assert_eq!(
            too_deep.validate_for(&profile),
            Err(HaloError::InsufficientHeadroom)
        );
    }
}
