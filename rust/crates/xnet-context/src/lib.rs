//! xnet-context — the Context Ouroboros (C-02/C-03 in the Goliath graph).
//! Tracks REAL token occupancy; at the Run threshold, builds a bounded,
//! sealed capsule, stores it in CAS, receipts it, and starts a FRESH session.
//! Post-binding: the aggregate seal is computed AFTER an exchange over the
//! ordered exchange-receipt hashes and verified from ledger data alone —
//! never asserted live. Context Spring = optional Hunter/Guardian profile.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use xnet_cas::Cas;
use xnet_ledger::{Actor, Kind, Ledger};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Depth {
    Swim, // < 50% occupancy: full context rides along
    Bike, // 50–80%: begin compression discipline
    Run,  // >= 80%: handoff NOW
}

impl Depth {
    pub fn from_occupancy(used: u64, window: u64) -> Self {
        let pct = (used as u128 * 100) / window.max(1) as u128;
        if pct >= 80 {
            Depth::Run
        } else if pct >= 50 {
            Depth::Bike
        } else {
            Depth::Swim
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capsule {
    /// CAS digest of the compressed handoff payload (counts/hashes only in receipts)
    pub digest: String,
    pub token_budget: u32,
    pub created_utc: i64,
    pub expires_utc: i64,
    /// receipt seq of the seal that admitted this capsule
    pub seal_seq: u64,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ContextSpring {
    /// Optional role profile. Its latency and quality effects are unmeasured.
    pub enabled: bool,
}

pub struct Ouroboros {
    pub window_tokens: u64,
    pub used_tokens: u64,
    pub spring: ContextSpring,
}

impl Ouroboros {
    pub fn new(window_tokens: u64) -> Self {
        Self { window_tokens, used_tokens: 0, spring: ContextSpring::default() }
    }

    pub fn depth(&self) -> Depth {
        Depth::from_occupancy(self.used_tokens, self.window_tokens)
    }

    /// Feed measured token counts (from the tokenizer, never estimated).
    /// Returns Some(Capsule) when a handoff fired — caller starts a fresh session.
    pub fn observe_turn(
        &mut self,
        tokens_in: u64,
        tokens_out: u64,
        payload: &[u8],
        cas: &Cas,
        ledger: &mut Ledger,
        ts_utc: i64,
    ) -> Option<Capsule> {
        self.used_tokens = self.used_tokens.saturating_add(tokens_in.saturating_add(tokens_out));
        if self.depth() != Depth::Run {
            return None;
        }
        Some(self.handoff(payload, cas, ledger, ts_utc))
    }

    fn handoff(&mut self, payload: &[u8], cas: &Cas, ledger: &mut Ledger, ts_utc: i64) -> Capsule {
        let digest = cas.put(payload).expect("CAS write failed — cannot hand off safely");
        let mut detail = BTreeMap::new();
        detail.insert("event".into(), "context-handoff".into());
        detail.insert("digest".into(), xnet_cas::hex(&digest).into());
        detail.insert("used_tokens".into(), self.used_tokens.into());
        detail.insert("spring".into(), self.spring.enabled.into());
        let r = ledger
            .append(Kind::Seal, Actor::System, ts_utc, digest, detail)
            .expect("ledger append failed — halting handoff");
        self.used_tokens = 0; // fresh session starts clean; capsule carries the bounded past
        Capsule {
            digest: xnet_cas::hex(&digest),
            token_budget: (self.window_tokens / 4).min(u32::MAX as u64) as u32,
            created_utc: ts_utc,
            expires_utc: ts_utc.saturating_add(86_400),
            seal_seq: r.seq,
        }
    }
}

/// Post-binding aggregate seal: digest over the ORDERED exchange receipt hashes
/// in `seq_range`. Recomputed independently during verification (g-context-spring-live).
pub fn aggregate_seal(exchange_hashes: &[[u8; 32]]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for e in exchange_hashes {
        h.update(e);
    }
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_thresholds() {
        assert_eq!(Depth::from_occupancy(400, 1000), Depth::Swim);
        assert_eq!(Depth::from_occupancy(600, 1000), Depth::Bike);
        assert_eq!(Depth::from_occupancy(850, 1000), Depth::Run);
    }

    #[test]
    fn handoff_fires_at_run_and_resets() {
        let d = std::env::temp_dir().join(format!("xnet-ctx-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let cas = Cas::open(d.join("cas")).unwrap();
        let mut ledger = Ledger::open(d.join("ledger.jsonl")).unwrap();
        let mut o = Ouroboros::new(1000);
        assert!(o.observe_turn(300, 300, b"t1", &cas, &mut ledger, 1).is_none()); // 60% Bike
        let cap = o.observe_turn(150, 100, b"t2", &cas, &mut ledger, 2);          // 85% Run
        assert!(cap.is_some());
        assert_eq!(o.used_tokens, 0);
        assert_eq!(Ledger::verify(d.join("ledger.jsonl")).unwrap(), 1);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn aggregate_is_order_sensitive() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_ne!(aggregate_seal(&[a, b]), aggregate_seal(&[b, a]));
    }
}
