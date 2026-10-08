//! Pure, offline route selection for the XNET Jcode harness.
//!
//! This crate deliberately has no provider, transport, credential, daemon, or
//! inference dependencies. Callers supply a validated policy and a snapshot of
//! route availability; the resolver returns one deterministic decision or
//! fails closed.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::fmt;

/// The only policy version understood by this crate.
pub const POLICY_VERSION: &str = "xnet-routing-v1";

/// A stable XNET execution role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XnetRole {
    Primary,
    FastWorker,
    BalancedWorker,
    OfflineFallback,
}

impl fmt::Display for XnetRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Primary => "primary",
            Self::FastWorker => "fast-worker",
            Self::BalancedWorker => "balanced-worker",
            Self::OfflineFallback => "offline-fallback",
        };
        formatter.write_str(value)
    }
}

/// Machine-readable explanation for a selected route.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionReason {
    RequestedRoleAvailable,
    CloudRoleFallback,
    CloudUnavailableOfflineFallback,
    CloudRoutesUnavailableOfflineFallback,
    ExplicitOfflineFallback,
}

/// One route admitted into the XNET policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// Stable policy-local identifier used by health/readiness snapshots.
    pub id: String,
    pub role: XnetRole,
    /// Jcode model route, for example `openai-oauth:gpt-6-luna` or
    /// `xnet-local:qwen2.5-coder-7b-instruct-abliterated-q6k`.
    pub model_spec: String,
    /// Lower values win. Ties are broken by route id, then model spec.
    pub priority: u16,
    /// Must be true exactly for `offline-fallback` routes.
    pub offline: bool,
}

/// Versioned, serializable XNET routing policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingPolicy {
    pub version: String,
    pub routes: Vec<RouteConfig>,
}

/// Readiness supplied by the caller. This crate never probes a route itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AvailabilitySnapshot {
    /// False excludes every cloud route, even if its id appears in `available_route_ids`.
    pub cloud_available: bool,
    /// Local Qwen remains stopped unless the caller explicitly authorizes this
    /// fallback for the decision being made.
    pub allow_offline_fallback: bool,
    /// Route ids whose independent health/admission checks passed.
    pub available_route_ids: BTreeSet<String>,
}

impl AvailabilitySnapshot {
    pub fn new<I, S>(cloud_available: bool, available_route_ids: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            cloud_available,
            allow_offline_fallback: false,
            available_route_ids: available_route_ids.into_iter().map(Into::into).collect(),
        }
    }

    /// Explicitly authorize or revoke local fallback for this snapshot.
    pub fn with_offline_fallback_authorized(mut self, authorized: bool) -> Self {
        self.allow_offline_fallback = authorized;
        self
    }
}

/// A deterministic routing decision. It contains no prompt or model output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingDecision {
    pub policy_version: String,
    pub requested_role: XnetRole,
    pub selected_role: XnetRole,
    pub route_id: String,
    pub model_spec: String,
    pub reason: SelectionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    UnsupportedVersion(String),
    EmptyRoutes,
    MissingRole(XnetRole),
    InvalidRouteId(String),
    InvalidModelSpec {
        route_id: String,
        model_spec: String,
    },
    OfflineRoleMismatch {
        route_id: String,
        role: XnetRole,
        offline: bool,
    },
    DuplicateRouteId(String),
    DuplicateModelSpec(String),
    UnknownAvailabilityRoute(String),
    NoEligibleRoute(XnetRole),
    Serialization(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported XNET policy version: {version}")
            }
            Self::EmptyRoutes => formatter.write_str("XNET policy has no routes"),
            Self::MissingRole(role) => write!(formatter, "XNET policy is missing role {role}"),
            Self::InvalidRouteId(id) => write!(formatter, "invalid XNET route id: {id:?}"),
            Self::InvalidModelSpec {
                route_id,
                model_spec,
            } => write!(
                formatter,
                "route {route_id:?} has invalid model spec {model_spec:?}"
            ),
            Self::OfflineRoleMismatch {
                route_id,
                role,
                offline,
            } => write!(
                formatter,
                "route {route_id:?} has role {role} but offline={offline}"
            ),
            Self::DuplicateRouteId(id) => write!(formatter, "duplicate XNET route id: {id}"),
            Self::DuplicateModelSpec(spec) => {
                write!(formatter, "duplicate XNET model spec: {spec}")
            }
            Self::UnknownAvailabilityRoute(id) => {
                write!(formatter, "availability references unknown route: {id}")
            }
            Self::NoEligibleRoute(role) => {
                write!(
                    formatter,
                    "no eligible XNET route for requested role {role}"
                )
            }
            Self::Serialization(error) => {
                write!(formatter, "failed to serialize XNET policy: {error}")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

impl RoutingPolicy {
    /// Validate every invariant needed for deterministic, fail-closed selection.
    pub fn validate(&self) -> Result<(), PolicyError> {
        if self.version != POLICY_VERSION {
            return Err(PolicyError::UnsupportedVersion(self.version.clone()));
        }
        if self.routes.is_empty() {
            return Err(PolicyError::EmptyRoutes);
        }

        let mut ids = HashSet::new();
        let mut model_specs = HashSet::new();
        let mut roles = HashSet::new();
        for route in &self.routes {
            if !valid_route_id(&route.id) {
                return Err(PolicyError::InvalidRouteId(route.id.clone()));
            }
            if !valid_model_spec(&route.model_spec) {
                return Err(PolicyError::InvalidModelSpec {
                    route_id: route.id.clone(),
                    model_spec: route.model_spec.clone(),
                });
            }
            if route.offline != (route.role == XnetRole::OfflineFallback) {
                return Err(PolicyError::OfflineRoleMismatch {
                    route_id: route.id.clone(),
                    role: route.role,
                    offline: route.offline,
                });
            }
            if !ids.insert(route.id.as_str()) {
                return Err(PolicyError::DuplicateRouteId(route.id.clone()));
            }
            if !model_specs.insert(route.model_spec.as_str()) {
                return Err(PolicyError::DuplicateModelSpec(route.model_spec.clone()));
            }
            roles.insert(route.role);
        }

        for role in [
            XnetRole::Primary,
            XnetRole::FastWorker,
            XnetRole::BalancedWorker,
            XnetRole::OfflineFallback,
        ] {
            if !roles.contains(&role) {
                return Err(PolicyError::MissingRole(role));
            }
        }
        Ok(())
    }

    /// Select one route using only the supplied snapshot.
    pub fn select(
        &self,
        requested_role: XnetRole,
        availability: &AvailabilitySnapshot,
    ) -> Result<RoutingDecision, PolicyError> {
        self.validate()?;
        let known_ids: HashSet<&str> = self.routes.iter().map(|route| route.id.as_str()).collect();
        if let Some(unknown) = availability
            .available_route_ids
            .iter()
            .find(|id| !known_ids.contains(id.as_str()))
        {
            return Err(PolicyError::UnknownAvailabilityRoute(unknown.clone()));
        }

        for role in role_precedence(requested_role) {
            let selected = self
                .routes
                .iter()
                .filter(|route| route.role == *role)
                .filter(|route| route.offline || availability.cloud_available)
                .filter(|route| !route.offline || availability.allow_offline_fallback)
                .filter(|route| availability.available_route_ids.contains(&route.id))
                .min_by(|left, right| route_sort_key(left).cmp(&route_sort_key(right)));

            if let Some(route) = selected {
                return Ok(RoutingDecision {
                    policy_version: self.version.clone(),
                    requested_role,
                    selected_role: route.role,
                    route_id: route.id.clone(),
                    model_spec: route.model_spec.clone(),
                    reason: selection_reason(
                        requested_role,
                        route.role,
                        availability.cloud_available,
                    ),
                });
            }
        }

        Err(PolicyError::NoEligibleRoute(requested_role))
    }

    /// Compact, stable JSON independent of route declaration order.
    pub fn canonical_json(&self) -> Result<String, PolicyError> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.routes.sort_by(|left, right| {
            canonical_route_sort_key(left).cmp(&canonical_route_sort_key(right))
        });
        serde_json::to_string(&canonical)
            .map_err(|error| PolicyError::Serialization(error.to_string()))
    }
}

fn role_precedence(role: XnetRole) -> &'static [XnetRole] {
    match role {
        XnetRole::Primary => &[
            XnetRole::Primary,
            XnetRole::BalancedWorker,
            XnetRole::FastWorker,
            XnetRole::OfflineFallback,
        ],
        XnetRole::FastWorker => &[
            XnetRole::FastWorker,
            XnetRole::BalancedWorker,
            XnetRole::OfflineFallback,
        ],
        XnetRole::BalancedWorker => &[
            XnetRole::BalancedWorker,
            XnetRole::FastWorker,
            XnetRole::OfflineFallback,
        ],
        XnetRole::OfflineFallback => &[XnetRole::OfflineFallback],
    }
}

fn selection_reason(
    requested: XnetRole,
    selected: XnetRole,
    cloud_available: bool,
) -> SelectionReason {
    if requested == XnetRole::OfflineFallback {
        SelectionReason::ExplicitOfflineFallback
    } else if selected == requested {
        SelectionReason::RequestedRoleAvailable
    } else if selected != XnetRole::OfflineFallback {
        SelectionReason::CloudRoleFallback
    } else if cloud_available {
        SelectionReason::CloudRoutesUnavailableOfflineFallback
    } else {
        SelectionReason::CloudUnavailableOfflineFallback
    }
}

fn route_sort_key(route: &RouteConfig) -> (u16, &str, &str) {
    (route.priority, route.id.as_str(), route.model_spec.as_str())
}

fn canonical_route_sort_key(route: &RouteConfig) -> (u8, u16, &str, &str) {
    (
        role_rank(route.role),
        route.priority,
        route.id.as_str(),
        route.model_spec.as_str(),
    )
}

fn role_rank(role: XnetRole) -> u8 {
    match role {
        XnetRole::Primary => 0,
        XnetRole::FastWorker => 1,
        XnetRole::BalancedWorker => 2,
        XnetRole::OfflineFallback => 3,
    }
}

fn valid_route_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value == value.trim()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_model_spec(value: &str) -> bool {
    if value.is_empty()
        || value != value.trim()
        || value.chars().any(char::is_whitespace)
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let Some((route, model)) = value.split_once(':') else {
        return false;
    };
    !route.is_empty()
        && !model.is_empty()
        && route.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}
