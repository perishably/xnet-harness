//! xnet-storage — storage tier law, enforced in types (sim S7 made this law).
//!   Hot  = internal NVMe CAS/index: the ONLY tier an inference call may touch.
//!   Warm = portable D:: staged prefetch, ahead-of-time, integrity-verified.
//!   Cold = Proton Drive: background recovery; never live authority (rule 8).
//! Raw Warm/Cold reads on the critical path are unrepresentable here:
//! `InferenceSource` can only be constructed from bytes already in the Hot CAS.

use serde::{Deserialize, Serialize};
use xnet_cas::{Cas, Hash32};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Hot,
    Warm,
    Cold,
}

impl Tier {
    /// The tier law: only Hot may serve an inference call.
    pub fn on_critical_path(self) -> bool {
        matches!(self, Tier::Hot)
    }
}

/// Proof token: these bytes came out of the Hot CAS, rehash-verified.
pub struct InferenceSource {
    pub digest: Hash32,
    bytes: Vec<u8>,
}

impl InferenceSource {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Load an object for inference. Signature takes the Hot CAS only —
/// there is no parameter through which a Warm/Cold path could be passed.
pub fn load_for_inference(hot: &Cas, digest: &Hash32) -> Result<InferenceSource, xnet_cas::CasError> {
    let bytes = hot.get(digest)?; // rehash-on-read inside
    Ok(InferenceSource { digest: *digest, bytes })
}

/// Prefetch plan entry: move Warm -> Hot with lead time, verifying integrity
/// before the object is ever needed. GPT: schedule with >= 300 s lead
/// (sim S7: staging 500 MiB from D: takes ~17.7 s measured-bound).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrefetchPlan {
    pub digest: String,
    pub needed_by_utc: i64,
    pub scheduled_utc: i64,
}

impl PrefetchPlan {
    pub fn new(digest: String, needed_by_utc: i64, lead_s: i64) -> Self {
        Self { digest, needed_by_utc, scheduled_utc: needed_by_utc.saturating_sub(lead_s.max(300)) }
    }
}

/// Pagefile/paging observation (GPT phone review: headroom, never speed).
/// Degrade status when hard faults climb; the RAM figure is never inflated.
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryVitals {
    pub commit_charge_mib: u64,
    pub commit_limit_mib: u64,
    pub available_ram_mib: u64,
    pub hard_faults_per_s: u64,
}

impl MemoryVitals {
    pub fn status(&self) -> &'static str {
        if self.hard_faults_per_s > 100 || self.available_ram_mib < 1_024 {
            "degraded"
        } else {
            "healthy"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_hot_is_on_path() {
        assert!(Tier::Hot.on_critical_path());
        assert!(!Tier::Warm.on_critical_path());
        assert!(!Tier::Cold.on_critical_path());
    }

    #[test]
    fn prefetch_lead_never_under_300s() {
        let p = PrefetchPlan::new("d".into(), 10_000, 5);
        assert!(p.needed_by_utc - p.scheduled_utc >= 300);
    }

    #[test]
    fn load_for_inference_roundtrip() {
        let d = std::env::temp_dir().join(format!("xnet-storage-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let cas = Cas::open(&d).unwrap();
        let h = cas.put(b"cartridge").unwrap();
        let src = load_for_inference(&cas, &h).unwrap();
        assert_eq!(src.bytes(), b"cartridge");
        let _ = std::fs::remove_dir_all(&d);
    }
}
