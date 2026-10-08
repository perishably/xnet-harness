//! Pure, offline engagement-scope admission for XNET.
//!
//! This crate deliberately has no filesystem, subprocess, DNS, network,
//! credential, provider, or inference dependency. A successful decision is a
//! content-free receipt, not an execution capability.

use hmac::{Hmac, Mac};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

type HmacSha256 = Hmac<Sha256>;

pub const SCOPE_SCHEMA: &str = "xnet.security-engagement-scope.v1";
pub const SCOPE_DOMAIN: &[u8] = b"XNET-SECURITY-SCOPE-V1\0";
pub const AUTHORIZATION_DOMAIN: &[u8] = b"XNET-SECURITY-AUTHORIZATION-V1\0";
pub const TARGET_FINGERPRINT_DOMAIN: &[u8] = b"XNET-SECURITY-TARGET-V1\0";
pub const ADAPTER_POLICY_VERSION: &str = "xnet.security-adapter-policy.v1";

const MAX_SCOPE_SECONDS: u64 = 366 * 86_400;
const MAX_TARGETS_PER_KIND: usize = 1_024;
const MAX_METHODS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ScopeMode {
    Bounty,
    Lab,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Action {
    HttpProbe,
    ServiceProbe,
    TcpConnectScan,
}

impl Action {
    fn as_str(self) -> &'static str {
        match self {
            Self::HttpProbe => "http-probe",
            Self::ServiceProbe => "service-probe",
            Self::TcpConnectScan => "tcp-connect-scan",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetKind {
    Domain,
    Ip,
    Cidr,
    WifiBssid,
    BleMac,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeTargets {
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub wifi_bssids: Vec<String>,
    pub ble_macs: Vec<String>,
}

impl ScopeTargets {
    pub fn empty() -> Self {
        Self {
            domains: Vec::new(),
            cidrs: Vec::new(),
            wifi_bssids: Vec::new(),
            ble_macs: Vec::new(),
        }
    }

    fn is_empty(&self) -> bool {
        self.domains.is_empty()
            && self.cidrs.is_empty()
            && self.wifi_bssids.is_empty()
            && self.ble_macs.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementScope {
    pub schema: String,
    pub scope_id: String,
    pub program_id: String,
    pub mode: ScopeMode,
    pub policy_capture_sha256: String,
    pub tool_registry_sha256: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub allow_live_network: bool,
    pub requests_per_minute: u16,
    pub max_parallel: u8,
    pub methods: Vec<Action>,
    pub allowed: ScopeTargets,
    pub excluded: ScopeTargets,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedScope {
    #[serde(flatten)]
    pub scope: EngagementScope,
    pub signature_hmac_sha256: String,
}

/// Explicit trust material. It is intentionally neither serializable nor
/// debuggable, and no global or environment fallback exists.
pub struct ScopeTrustKey {
    bytes: Vec<u8>,
}

impl ScopeTrustKey {
    pub fn new(bytes: impl AsRef<[u8]>) -> Result<Self, GateErrorCode> {
        let bytes = bytes.as_ref();
        if !(32..=1_024).contains(&bytes.len()) {
            return Err(GateErrorCode::InvalidTrustKey);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Verified scope internals remain opaque so logs cannot accidentally print
/// targets or engagement content.
pub struct VerifiedScope {
    scope: EngagementScope,
    scope_sha256: String,
}

impl VerifiedScope {
    pub fn scope_sha256(&self) -> &str {
        &self.scope_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Domain(String),
    Ip(String),
    Cidr(String),
    WifiBssid(String),
    BleMac(String),
}

impl Target {
    pub fn kind(&self) -> TargetKind {
        match self {
            Self::Domain(_) => TargetKind::Domain,
            Self::Ip(_) => TargetKind::Ip,
            Self::Cidr(_) => TargetKind::Cidr,
            Self::WifiBssid(_) => TargetKind::WifiBssid,
            Self::BleMac(_) => TargetKind::BleMac,
        }
    }
}

/// Content-free result of checking one target against a verified scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedTarget {
    pub kind: TargetKind,
    pub target_hmac_sha256: String,
    pub reason: AdmissionReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterPolicyId {
    HttpxV1,
    NmapV1,
}

/// The complete fixed X1A registry. Its digest is signed into every scope, so
/// callers cannot substitute a different binary identity after signing.
#[derive(Clone, PartialEq, Eq)]
pub struct AdapterRegistry {
    bindings: Vec<AdapterBinding>,
}

impl AdapterRegistry {
    pub fn initial(
        httpx_binary_sha256: impl Into<String>,
        nmap_binary_sha256: impl Into<String>,
    ) -> Result<Self, GateErrorCode> {
        Ok(Self {
            bindings: vec![
                AdapterBinding::httpx(httpx_binary_sha256)?,
                AdapterBinding::nmap(nmap_binary_sha256)?,
            ],
        })
    }

    pub fn registry_sha256(&self) -> Result<String, GateErrorCode> {
        let mut bindings = self
            .bindings
            .iter()
            .map(|binding| AdapterPolicyIdentity {
                policy_version: ADAPTER_POLICY_VERSION,
                adapter: binding.id,
                binary_identity_sha256: &binding.binary_identity_sha256,
            })
            .collect::<Vec<_>>();
        bindings.sort_by_key(|binding| binding.adapter);
        canonical_sha256(&AdapterRegistryIdentity {
            policy_version: ADAPTER_POLICY_VERSION,
            bindings,
        })
    }

    fn binding(&self, id: AdapterPolicyId) -> &AdapterBinding {
        self.bindings
            .iter()
            .find(|binding| binding.id == id)
            .expect("the fixed initial registry always contains both adapters")
    }
}

/// A fixed adapter identity plus an externally pinned binary digest. The gate
/// does not read that binary and never constructs argv.
#[derive(Clone, PartialEq, Eq)]
pub struct AdapterBinding {
    id: AdapterPolicyId,
    binary_identity_sha256: String,
}

impl AdapterBinding {
    pub fn httpx(binary_identity_sha256: impl Into<String>) -> Result<Self, GateErrorCode> {
        Self::new(AdapterPolicyId::HttpxV1, binary_identity_sha256)
    }

    pub fn nmap(binary_identity_sha256: impl Into<String>) -> Result<Self, GateErrorCode> {
        Self::new(AdapterPolicyId::NmapV1, binary_identity_sha256)
    }

    fn new(
        id: AdapterPolicyId,
        binary_identity_sha256: impl Into<String>,
    ) -> Result<Self, GateErrorCode> {
        let binary_identity_sha256 = binary_identity_sha256.into();
        validate_hash(&binary_identity_sha256)?;
        Ok(Self {
            id,
            binary_identity_sha256,
        })
    }

    pub fn id(&self) -> AdapterPolicyId {
        self.id
    }

    pub fn binary_identity_sha256(&self) -> &str {
        &self.binary_identity_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdmissionReason {
    Admitted,
}

/// Successful adapter admission. Every string field is a SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmissionReceipt {
    pub reason: AdmissionReason,
    pub execution_ready: bool,
    pub authorized_at: u64,
    pub expires_at: u64,
    pub scope_sha256: String,
    pub registry_sha256: String,
    pub adapter_policy_sha256: String,
    pub binary_identity_sha256: String,
    pub action_sha256: String,
    pub target_hmac_sha256: String,
    pub human_confirmation_sha256: Option<String>,
    pub authorization_sha256: String,
    pub authorization_hmac_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GateErrorCode {
    InvalidTrustKey,
    InvalidScopeSchema,
    InvalidIdentifier,
    InvalidHash,
    InvalidTimeRange,
    InvalidRateLimits,
    LiveNetworkNotAllowed,
    EmptyMethods,
    EmptyAllowedTargets,
    TooManyEntries,
    DuplicateEntry,
    InvalidDomain,
    WildcardTargetForbidden,
    InvalidCidr,
    UnboundedCidr,
    NonCanonicalCidr,
    InvalidIp,
    InvalidMac,
    NonCanonicalScope,
    SignatureMismatch,
    ScopeNotActive,
    MethodOutsideScope,
    MethodOutsideAdapterPolicy,
    TargetKindOutsideAdapterPolicy,
    TargetExcluded,
    TargetOutsideScope,
    RfRequiresLabMode,
    HumanConfirmationRequired,
    RegistryBindingMismatch,
    AuthorizationHashMismatch,
    AuthorizationSignatureMismatch,
    AuthorizationBindingMismatch,
    AuthorizationNotActive,
    InvalidExecutionBoundary,
    SerializationFailed,
}

impl GateErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InvalidTrustKey => "invalid-trust-key",
            Self::InvalidScopeSchema => "invalid-scope-schema",
            Self::InvalidIdentifier => "invalid-identifier",
            Self::InvalidHash => "invalid-hash",
            Self::InvalidTimeRange => "invalid-time-range",
            Self::InvalidRateLimits => "invalid-rate-limits",
            Self::LiveNetworkNotAllowed => "live-network-not-allowed",
            Self::EmptyMethods => "empty-methods",
            Self::EmptyAllowedTargets => "empty-allowed-targets",
            Self::TooManyEntries => "too-many-entries",
            Self::DuplicateEntry => "duplicate-entry",
            Self::InvalidDomain => "invalid-domain",
            Self::WildcardTargetForbidden => "wildcard-target-forbidden",
            Self::InvalidCidr => "invalid-cidr",
            Self::UnboundedCidr => "unbounded-cidr",
            Self::NonCanonicalCidr => "non-canonical-cidr",
            Self::InvalidIp => "invalid-ip",
            Self::InvalidMac => "invalid-mac",
            Self::NonCanonicalScope => "non-canonical-scope",
            Self::SignatureMismatch => "signature-mismatch",
            Self::ScopeNotActive => "scope-not-active",
            Self::MethodOutsideScope => "method-outside-scope",
            Self::MethodOutsideAdapterPolicy => "method-outside-adapter-policy",
            Self::TargetKindOutsideAdapterPolicy => "target-kind-outside-adapter-policy",
            Self::TargetExcluded => "target-excluded",
            Self::TargetOutsideScope => "target-outside-scope",
            Self::RfRequiresLabMode => "rf-requires-lab-mode",
            Self::HumanConfirmationRequired => "human-confirmation-required",
            Self::RegistryBindingMismatch => "registry-binding-mismatch",
            Self::AuthorizationHashMismatch => "authorization-hash-mismatch",
            Self::AuthorizationSignatureMismatch => "authorization-signature-mismatch",
            Self::AuthorizationBindingMismatch => "authorization-binding-mismatch",
            Self::AuthorizationNotActive => "authorization-not-active",
            Self::InvalidExecutionBoundary => "invalid-execution-boundary",
            Self::SerializationFailed => "serialization-failed",
        }
    }
}

impl fmt::Display for GateErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::error::Error for GateErrorCode {}

pub fn sign_scope(
    scope: &EngagementScope,
    trust_key: &ScopeTrustKey,
) -> Result<SignedScope, GateErrorCode> {
    let scope = normalize_scope(scope)?;
    let canonical = canonical_bytes(&scope)?;
    let signature_hmac_sha256 = sign_bytes(trust_key, &canonical)?;
    Ok(SignedScope {
        scope,
        signature_hmac_sha256,
    })
}

pub fn verify_scope(
    signed_scope: &SignedScope,
    trust_key: &ScopeTrustKey,
    trusted_now: u64,
) -> Result<VerifiedScope, GateErrorCode> {
    validate_hash(&signed_scope.signature_hmac_sha256)?;
    let normalized = normalize_scope(&signed_scope.scope)?;
    if normalized != signed_scope.scope {
        return Err(GateErrorCode::NonCanonicalScope);
    }

    let canonical = canonical_bytes(&normalized)?;
    verify_signature(trust_key, &canonical, &signed_scope.signature_hmac_sha256)?;
    if trusted_now < normalized.issued_at || trusted_now >= normalized.expires_at {
        return Err(GateErrorCode::ScopeNotActive);
    }

    Ok(VerifiedScope {
        scope: normalized,
        scope_sha256: canonical_sha256(signed_scope)?,
    })
}

pub fn canonical_scope_json(scope: &EngagementScope) -> Result<String, GateErrorCode> {
    let normalized = normalize_scope(scope)?;
    let bytes = canonical_bytes(&normalized)?;
    String::from_utf8(bytes).map_err(|_| GateErrorCode::SerializationFailed)
}

pub fn verify_target(
    verified_scope: &VerifiedScope,
    trust_key: &ScopeTrustKey,
    target: &Target,
) -> Result<VerifiedTarget, GateErrorCode> {
    let normalized = match target {
        Target::Domain(value) => {
            let target = normalize_domain(value, false)?;
            if verified_scope
                .scope
                .excluded
                .domains
                .iter()
                .any(|pattern| domain_matches(pattern, &target))
            {
                return Err(GateErrorCode::TargetExcluded);
            }
            if !verified_scope
                .scope
                .allowed
                .domains
                .iter()
                .any(|pattern| domain_matches(pattern, &target))
            {
                return Err(GateErrorCode::TargetOutsideScope);
            }
            target
        }
        Target::Ip(value) => {
            let target = normalize_ip(value)?;
            let address = IpAddr::from_str(&target).map_err(|_| GateErrorCode::InvalidIp)?;
            if scope_cidrs(&verified_scope.scope.excluded)?
                .iter()
                .any(|network| network.contains(&address))
            {
                return Err(GateErrorCode::TargetExcluded);
            }
            if !scope_cidrs(&verified_scope.scope.allowed)?
                .iter()
                .any(|network| network.contains(&address))
            {
                return Err(GateErrorCode::TargetOutsideScope);
            }
            target
        }
        Target::Cidr(value) => {
            let target = parse_cidr(value)?;
            if scope_cidrs(&verified_scope.scope.excluded)?
                .iter()
                .any(|excluded| cidrs_overlap(excluded, &target))
            {
                return Err(GateErrorCode::TargetExcluded);
            }
            if !scope_cidrs(&verified_scope.scope.allowed)?
                .iter()
                .any(|allowed| allowed.contains(&target))
            {
                return Err(GateErrorCode::TargetOutsideScope);
            }
            target.to_string()
        }
        Target::WifiBssid(value) => {
            let target = normalize_mac(value)?;
            if verified_scope.scope.excluded.wifi_bssids.contains(&target) {
                return Err(GateErrorCode::TargetExcluded);
            }
            if !verified_scope.scope.allowed.wifi_bssids.contains(&target) {
                return Err(GateErrorCode::TargetOutsideScope);
            }
            target
        }
        Target::BleMac(value) => {
            let target = normalize_mac(value)?;
            if verified_scope.scope.excluded.ble_macs.contains(&target) {
                return Err(GateErrorCode::TargetExcluded);
            }
            if !verified_scope.scope.allowed.ble_macs.contains(&target) {
                return Err(GateErrorCode::TargetOutsideScope);
            }
            target
        }
    };

    Ok(VerifiedTarget {
        kind: target.kind(),
        target_hmac_sha256: keyed_canonical_hmac(
            trust_key,
            TARGET_FINGERPRINT_DOMAIN,
            &normalized,
        )?,
        reason: AdmissionReason::Admitted,
    })
}

pub fn admit_adapter_request(
    signed_scope: &SignedScope,
    trust_key: &ScopeTrustKey,
    trusted_now: u64,
    registry: &AdapterRegistry,
    adapter_id: AdapterPolicyId,
    action: Action,
    target: &Target,
    human_confirmation_sha256: Option<&str>,
) -> Result<AdmissionReceipt, GateErrorCode> {
    let verified_scope = verify_scope(signed_scope, trust_key, trusted_now)?;
    let registry_sha256 = registry.registry_sha256()?;
    if registry_sha256 != verified_scope.scope.tool_registry_sha256 {
        return Err(GateErrorCode::RegistryBindingMismatch);
    }
    if !verified_scope.scope.methods.contains(&action) {
        return Err(GateErrorCode::MethodOutsideScope);
    }

    let adapter = registry.binding(adapter_id);
    let rules = adapter_rules(adapter.id);
    if !rules.actions.contains(&action) {
        return Err(GateErrorCode::MethodOutsideAdapterPolicy);
    }
    if !rules.target_kinds.contains(&target.kind()) {
        return Err(GateErrorCode::TargetKindOutsideAdapterPolicy);
    }

    let verified_target = verify_target(&verified_scope, trust_key, target)?;
    let human_confirmation_sha256 = enforce_rf_gate(
        verified_scope.scope.mode,
        rules.rf_active,
        human_confirmation_sha256,
    )?;
    let adapter_policy_sha256 = adapter_policy_sha256(adapter)?;
    let action_sha256 = sha256_hex(action.as_str().as_bytes());

    let body = AdmissionBody {
        reason: AdmissionReason::Admitted,
        execution_ready: false,
        authorized_at: trusted_now,
        expires_at: verified_scope.scope.expires_at,
        scope_sha256: verified_scope.scope_sha256.clone(),
        registry_sha256: registry_sha256.clone(),
        adapter_policy_sha256: adapter_policy_sha256.clone(),
        binary_identity_sha256: adapter.binary_identity_sha256.clone(),
        action_sha256: action_sha256.clone(),
        target_hmac_sha256: verified_target.target_hmac_sha256.clone(),
        human_confirmation_sha256: human_confirmation_sha256.clone(),
    };
    let authorization_sha256 = canonical_sha256(&body)?;
    let signed_body = SignedAdmissionBody {
        body: body.clone(),
        authorization_sha256: authorization_sha256.clone(),
    };
    let authorization_hmac_sha256 =
        keyed_canonical_hmac(trust_key, AUTHORIZATION_DOMAIN, &signed_body)?;

    Ok(AdmissionReceipt {
        reason: body.reason,
        execution_ready: body.execution_ready,
        authorized_at: body.authorized_at,
        expires_at: body.expires_at,
        scope_sha256: body.scope_sha256,
        registry_sha256,
        adapter_policy_sha256,
        binary_identity_sha256: body.binary_identity_sha256,
        action_sha256,
        target_hmac_sha256: body.target_hmac_sha256,
        human_confirmation_sha256,
        authorization_sha256,
        authorization_hmac_sha256,
    })
}

pub fn verify_admission_receipt(
    receipt: &AdmissionReceipt,
    trust_key: &ScopeTrustKey,
    trusted_now: u64,
    expected_scope_sha256: &str,
    expected_registry_sha256: &str,
) -> Result<AdmissionReason, GateErrorCode> {
    for hash in [
        &receipt.scope_sha256,
        &receipt.registry_sha256,
        &receipt.adapter_policy_sha256,
        &receipt.binary_identity_sha256,
        &receipt.action_sha256,
        &receipt.target_hmac_sha256,
        &receipt.authorization_sha256,
        &receipt.authorization_hmac_sha256,
    ] {
        validate_hash(hash)?;
    }
    if let Some(hash) = &receipt.human_confirmation_sha256 {
        validate_hash(hash)?;
    }
    validate_hash(expected_scope_sha256)?;
    validate_hash(expected_registry_sha256)?;
    if receipt.execution_ready {
        return Err(GateErrorCode::InvalidExecutionBoundary);
    }
    if trusted_now < receipt.authorized_at || trusted_now >= receipt.expires_at {
        return Err(GateErrorCode::AuthorizationNotActive);
    }
    if receipt.scope_sha256 != expected_scope_sha256
        || receipt.registry_sha256 != expected_registry_sha256
    {
        return Err(GateErrorCode::AuthorizationBindingMismatch);
    }

    let body = AdmissionBody::from(receipt);
    if canonical_sha256(&body)? != receipt.authorization_sha256 {
        return Err(GateErrorCode::AuthorizationHashMismatch);
    }
    let signed_body = SignedAdmissionBody {
        body,
        authorization_sha256: receipt.authorization_sha256.clone(),
    };
    verify_canonical_hmac(
        trust_key,
        AUTHORIZATION_DOMAIN,
        &signed_body,
        &receipt.authorization_hmac_sha256,
        GateErrorCode::AuthorizationSignatureMismatch,
    )?;
    Ok(receipt.reason)
}

#[derive(Clone, Serialize)]
struct AdmissionBody {
    reason: AdmissionReason,
    execution_ready: bool,
    authorized_at: u64,
    expires_at: u64,
    scope_sha256: String,
    registry_sha256: String,
    adapter_policy_sha256: String,
    binary_identity_sha256: String,
    action_sha256: String,
    target_hmac_sha256: String,
    human_confirmation_sha256: Option<String>,
}

impl From<&AdmissionReceipt> for AdmissionBody {
    fn from(receipt: &AdmissionReceipt) -> Self {
        Self {
            reason: receipt.reason,
            execution_ready: receipt.execution_ready,
            authorized_at: receipt.authorized_at,
            expires_at: receipt.expires_at,
            scope_sha256: receipt.scope_sha256.clone(),
            registry_sha256: receipt.registry_sha256.clone(),
            adapter_policy_sha256: receipt.adapter_policy_sha256.clone(),
            binary_identity_sha256: receipt.binary_identity_sha256.clone(),
            action_sha256: receipt.action_sha256.clone(),
            target_hmac_sha256: receipt.target_hmac_sha256.clone(),
            human_confirmation_sha256: receipt.human_confirmation_sha256.clone(),
        }
    }
}

#[derive(Serialize)]
struct SignedAdmissionBody {
    #[serde(flatten)]
    body: AdmissionBody,
    authorization_sha256: String,
}

struct AdapterRules {
    actions: &'static [Action],
    target_kinds: &'static [TargetKind],
    rf_active: bool,
}

fn adapter_rules(id: AdapterPolicyId) -> AdapterRules {
    match id {
        AdapterPolicyId::HttpxV1 => AdapterRules {
            actions: &[Action::HttpProbe],
            target_kinds: &[TargetKind::Domain, TargetKind::Ip],
            rf_active: false,
        },
        AdapterPolicyId::NmapV1 => AdapterRules {
            actions: &[Action::ServiceProbe, Action::TcpConnectScan],
            target_kinds: &[TargetKind::Ip, TargetKind::Cidr],
            rf_active: false,
        },
    }
}

#[derive(Serialize)]
struct AdapterPolicyIdentity<'a> {
    policy_version: &'static str,
    adapter: AdapterPolicyId,
    binary_identity_sha256: &'a str,
}

#[derive(Serialize)]
struct AdapterRegistryIdentity<'a> {
    policy_version: &'static str,
    bindings: Vec<AdapterPolicyIdentity<'a>>,
}

fn adapter_policy_sha256(adapter: &AdapterBinding) -> Result<String, GateErrorCode> {
    canonical_sha256(&AdapterPolicyIdentity {
        policy_version: ADAPTER_POLICY_VERSION,
        adapter: adapter.id,
        binary_identity_sha256: &adapter.binary_identity_sha256,
    })
}

fn enforce_rf_gate(
    mode: ScopeMode,
    rf_active: bool,
    human_confirmation_sha256: Option<&str>,
) -> Result<Option<String>, GateErrorCode> {
    if rf_active && mode != ScopeMode::Lab {
        return Err(GateErrorCode::RfRequiresLabMode);
    }
    if rf_active && human_confirmation_sha256.is_none() {
        return Err(GateErrorCode::HumanConfirmationRequired);
    }
    if let Some(value) = human_confirmation_sha256 {
        validate_hash(value)?;
        return Ok(Some(value.to_string()));
    }
    Ok(None)
}

fn normalize_scope(scope: &EngagementScope) -> Result<EngagementScope, GateErrorCode> {
    if scope.schema != SCOPE_SCHEMA {
        return Err(GateErrorCode::InvalidScopeSchema);
    }
    validate_identifier(&scope.scope_id)?;
    validate_identifier(&scope.program_id)?;
    validate_hash(&scope.policy_capture_sha256)?;
    validate_hash(&scope.tool_registry_sha256)?;
    if scope.expires_at <= scope.issued_at || scope.expires_at - scope.issued_at > MAX_SCOPE_SECONDS
    {
        return Err(GateErrorCode::InvalidTimeRange);
    }
    if !scope.allow_live_network {
        return Err(GateErrorCode::LiveNetworkNotAllowed);
    }
    if !(1..=600).contains(&scope.requests_per_minute) || !(1..=16).contains(&scope.max_parallel) {
        return Err(GateErrorCode::InvalidRateLimits);
    }

    let mut methods = scope.methods.clone();
    if methods.is_empty() {
        return Err(GateErrorCode::EmptyMethods);
    }
    if methods.len() > MAX_METHODS {
        return Err(GateErrorCode::TooManyEntries);
    }
    methods.sort_unstable();
    reject_duplicates(&methods)?;

    let allowed = normalize_targets(&scope.allowed)?;
    if allowed.is_empty() {
        return Err(GateErrorCode::EmptyAllowedTargets);
    }
    let excluded = normalize_targets(&scope.excluded)?;

    Ok(EngagementScope {
        schema: SCOPE_SCHEMA.to_string(),
        scope_id: scope.scope_id.clone(),
        program_id: scope.program_id.clone(),
        mode: scope.mode,
        policy_capture_sha256: scope.policy_capture_sha256.clone(),
        tool_registry_sha256: scope.tool_registry_sha256.clone(),
        issued_at: scope.issued_at,
        expires_at: scope.expires_at,
        allow_live_network: true,
        requests_per_minute: scope.requests_per_minute,
        max_parallel: scope.max_parallel,
        methods,
        allowed,
        excluded,
    })
}

fn normalize_targets(targets: &ScopeTargets) -> Result<ScopeTargets, GateErrorCode> {
    Ok(ScopeTargets {
        domains: normalize_unique(&targets.domains, |value| normalize_domain(value, true))?,
        cidrs: normalize_unique(&targets.cidrs, |value| {
            parse_cidr(value).map(|network| network.to_string())
        })?,
        wifi_bssids: normalize_unique(&targets.wifi_bssids, |value| normalize_mac(value))?,
        ble_macs: normalize_unique(&targets.ble_macs, |value| normalize_mac(value))?,
    })
}

fn normalize_unique<F>(values: &[String], mut normalize: F) -> Result<Vec<String>, GateErrorCode>
where
    F: FnMut(&str) -> Result<String, GateErrorCode>,
{
    if values.len() > MAX_TARGETS_PER_KIND {
        return Err(GateErrorCode::TooManyEntries);
    }
    let mut normalized = values
        .iter()
        .map(|value| normalize(value))
        .collect::<Result<Vec<_>, _>>()?;
    normalized.sort();
    reject_duplicates(&normalized)?;
    Ok(normalized)
}

fn reject_duplicates<T: PartialEq>(values: &[T]) -> Result<(), GateErrorCode> {
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(GateErrorCode::DuplicateEntry);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), GateErrorCode> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > 128
        || !bytes[0].is_ascii_lowercase() && !bytes[0].is_ascii_digit()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'.' | b':' | b'-')
        })
    {
        return Err(GateErrorCode::InvalidIdentifier);
    }
    Ok(())
}

fn validate_hash(value: &str) -> Result<(), GateErrorCode> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(GateErrorCode::InvalidHash);
    }
    Ok(())
}

fn normalize_domain(value: &str, allow_wildcard: bool) -> Result<String, GateErrorCode> {
    let mut candidate = value.trim().trim_end_matches('.').to_lowercase();
    let wildcard = candidate.starts_with("*.");
    if wildcard {
        if !allow_wildcard {
            return Err(GateErrorCode::WildcardTargetForbidden);
        }
        candidate = candidate[2..].to_string();
    }
    if candidate.contains('*') || candidate.is_empty() {
        return Err(GateErrorCode::InvalidDomain);
    }

    let ascii = idna::domain_to_ascii(&candidate)
        .map_err(|_| GateErrorCode::InvalidDomain)?
        .to_ascii_lowercase();
    if ascii.len() > 253 {
        return Err(GateErrorCode::InvalidDomain);
    }
    let labels = ascii.split('.').collect::<Vec<_>>();
    if labels.len() < 2
        || labels.iter().any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
    {
        return Err(GateErrorCode::InvalidDomain);
    }

    if wildcard {
        Ok(format!("*.{ascii}"))
    } else {
        Ok(ascii)
    }
}

fn domain_matches(pattern: &str, target: &str) -> bool {
    if let Some(base) = pattern.strip_prefix("*.") {
        target != base
            && target
                .strip_suffix(base)
                .is_some_and(|prefix| prefix.ends_with('.'))
    } else {
        target == pattern
    }
}

fn parse_cidr(value: &str) -> Result<IpNet, GateErrorCode> {
    let candidate = value.trim();
    let network = IpNet::from_str(candidate).map_err(|_| GateErrorCode::InvalidCidr)?;
    if network.prefix_len() == 0 {
        return Err(GateErrorCode::UnboundedCidr);
    }
    if network.addr() != network.network() {
        return Err(GateErrorCode::NonCanonicalCidr);
    }
    Ok(network)
}

fn normalize_ip(value: &str) -> Result<String, GateErrorCode> {
    IpAddr::from_str(value.trim())
        .map(|address| address.to_string())
        .map_err(|_| GateErrorCode::InvalidIp)
}

fn normalize_mac(value: &str) -> Result<String, GateErrorCode> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', ":");
    let parts = normalized.split(':').collect::<Vec<_>>();
    if parts.len() != 6
        || parts
            .iter()
            .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err(GateErrorCode::InvalidMac);
    }
    Ok(normalized)
}

fn scope_cidrs(targets: &ScopeTargets) -> Result<Vec<IpNet>, GateErrorCode> {
    targets
        .cidrs
        .iter()
        .map(|value| parse_cidr(value))
        .collect()
}

fn cidrs_overlap(left: &IpNet, right: &IpNet) -> bool {
    left.contains(right) || right.contains(left)
}

fn sign_bytes(trust_key: &ScopeTrustKey, canonical_scope: &[u8]) -> Result<String, GateErrorCode> {
    keyed_hmac(trust_key, SCOPE_DOMAIN, canonical_scope)
}

fn keyed_canonical_hmac<T: Serialize>(
    trust_key: &ScopeTrustKey,
    domain: &[u8],
    value: &T,
) -> Result<String, GateErrorCode> {
    keyed_hmac(trust_key, domain, &canonical_bytes(value)?)
}

fn keyed_hmac(
    trust_key: &ScopeTrustKey,
    domain: &[u8],
    body: &[u8],
) -> Result<String, GateErrorCode> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(trust_key.as_bytes())
        .map_err(|_| GateErrorCode::InvalidTrustKey)?;
    mac.update(domain);
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

fn verify_canonical_hmac<T: Serialize>(
    trust_key: &ScopeTrustKey,
    domain: &[u8],
    value: &T,
    signature: &str,
    error: GateErrorCode,
) -> Result<(), GateErrorCode> {
    let signature = hex::decode(signature).map_err(|_| GateErrorCode::InvalidHash)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(trust_key.as_bytes())
        .map_err(|_| GateErrorCode::InvalidTrustKey)?;
    mac.update(domain);
    mac.update(&canonical_bytes(value)?);
    mac.verify_slice(&signature).map_err(|_| error)
}

fn verify_signature(
    trust_key: &ScopeTrustKey,
    canonical_scope: &[u8],
    signature: &str,
) -> Result<(), GateErrorCode> {
    let signature = hex::decode(signature).map_err(|_| GateErrorCode::InvalidHash)?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(trust_key.as_bytes())
        .map_err(|_| GateErrorCode::InvalidTrustKey)?;
    mac.update(SCOPE_DOMAIN);
    mac.update(canonical_scope);
    mac.verify_slice(&signature)
        .map_err(|_| GateErrorCode::SignatureMismatch)
}

fn canonical_sha256<T: Serialize>(value: &T) -> Result<String, GateErrorCode> {
    Ok(sha256_hex(&canonical_bytes(value)?))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, GateErrorCode> {
    let value = serde_json::to_value(value).map_err(|_| GateErrorCode::SerializationFailed)?;
    let mut output = Vec::new();
    write_canonical_value(&value, &mut output)?;
    Ok(output)
}

fn write_canonical_value(value: &Value, output: &mut Vec<u8>) -> Result<(), GateErrorCode> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => {
            let encoded =
                serde_json::to_string(value).map_err(|_| GateErrorCode::SerializationFailed)?;
            output.extend_from_slice(encoded.as_bytes());
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_value(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                let encoded_key =
                    serde_json::to_string(key).map_err(|_| GateErrorCode::SerializationFailed)?;
                output.extend_from_slice(encoded_key.as_bytes());
                output.push(b':');
                write_canonical_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod internal_tests {
    use super::*;

    #[test]
    fn rf_gate_shape_requires_lab_and_confirmation_without_exposing_an_adapter() {
        let confirmation = "c".repeat(64);
        assert_eq!(
            enforce_rf_gate(ScopeMode::Bounty, true, Some(&confirmation)),
            Err(GateErrorCode::RfRequiresLabMode)
        );
        assert_eq!(
            enforce_rf_gate(ScopeMode::Lab, true, None),
            Err(GateErrorCode::HumanConfirmationRequired)
        );
        assert_eq!(
            enforce_rf_gate(ScopeMode::Lab, true, Some("bad")),
            Err(GateErrorCode::InvalidHash)
        );
        assert_eq!(
            enforce_rf_gate(ScopeMode::Lab, true, Some(&confirmation)),
            Ok(Some(confirmation))
        );
        assert!(!adapter_rules(AdapterPolicyId::HttpxV1).rf_active);
        assert!(!adapter_rules(AdapterPolicyId::NmapV1).rf_active);
    }
}
