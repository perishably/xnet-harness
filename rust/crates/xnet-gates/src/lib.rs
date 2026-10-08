//! xnet-gates — Dragon Trap. The original harness executes; XNET admits.
//! Every Jcode tool call / file write / shell exec / model request passes
//! through `Gate::admit`. Every verdict is receipted. No receipt, no execution.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use xnet_ledger::{Actor, Kind, Ledger};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Op {
    ToolCall { name: String },
    FileWrite { path: String },
    /// hash of argv, never the raw command line (may carry secrets — rule 5)
    ShellExec { argv_hash: String },
    ModelRequest { model_id_hash: String, tokens_in: u64 },
    StorageRead { tier: String, digest: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Degrade { reason: String },
    Halt { reason: String },
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Ctx {
    /// digests/paths under quarantine (TTL managed by caller)
    pub quarantined: Vec<String>,
    /// system-wide degraded flag (paging pressure, thermal, etc.)
    pub degraded: bool,
    pub detail: BTreeMap<String, serde_json::Value>,
}

pub trait Gate {
    fn name(&self) -> &'static str;
    fn admit(&self, op: &Op, ctx: &Ctx) -> Verdict;
}

fn hash_op_verdict(op: &Op, verdict: &Verdict) -> [u8; 32] {
    let v = serde_json::json!({ "op": op, "verdict": verdict });
    let bytes = serde_json::to_vec(&v).expect("serialization cannot fail");
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Gate chain: first Halt wins; otherwise any Degrade degrades; every op receipted.
pub struct GateChain<'a> {
    pub gates: Vec<Box<dyn Gate + 'a>>,
}

impl<'a> GateChain<'a> {
    pub fn admit_and_receipt(
        &self,
        op: &Op,
        ctx: &Ctx,
        ledger: &mut Ledger,
        ts_utc: i64,
    ) -> Verdict {
        let mut verdict = Verdict::Allow;
        for g in &self.gates {
            match g.admit(op, ctx) {
                Verdict::Halt { reason } => {
                    verdict = Verdict::Halt { reason: format!("{}: {reason}", g.name()) };
                    break;
                }
                Verdict::Degrade { reason } if verdict.is_allow() => {
                    verdict = Verdict::Degrade { reason: format!("{}: {reason}", g.name()) };
                }
                _ => {}
            }
        }
        let mut detail = BTreeMap::new();
        detail.insert("op".into(), serde_json::to_value(op).unwrap_or_default());
        detail.insert("verdict".into(), serde_json::to_value(&verdict).unwrap_or_default());
        let hash = hash_op_verdict(op, &verdict);
        // An append failure must itself halt the op: no receipt, no execution.
        ledger
            .append(Kind::GateVerdict, Actor::System, ts_utc, hash, detail)
            .expect("ledger append failed — halting op (no receipt, no execution)");
        verdict
    }
}

/// The critical-path storage rule as a gate (sim S7 made this law):
/// Warm/Cold bytes may not be read inside an inference call.
pub struct StoragePathGate;
impl Gate for StoragePathGate {
    fn name(&self) -> &'static str {
        "storage-path"
    }
    fn admit(&self, op: &Op, ctx: &Ctx) -> Verdict {
        if let Op::StorageRead { tier, .. } = op {
            if tier != "hot" {
                return Verdict::Halt {
                    reason: "warm/cold read on inference critical path (violates tier law)".into(),
                };
            }
        }
        if ctx.degraded {
            return Verdict::Degrade { reason: "system degraded".into() };
        }
        Verdict::Allow
    }
}

/// Quarantine gate: any op touching a quarantined digest/path halts (sim S6).
pub struct QuarantineGate;
impl Gate for QuarantineGate {
    fn name(&self) -> &'static str {
        "quarantine"
    }
    fn admit(&self, op: &Op, ctx: &Ctx) -> Verdict {
        let key = match op {
            Op::FileWrite { path } => Some(path.clone()),
            Op::StorageRead { digest, .. } => Some(digest.clone()),
            _ => None,
        };
        if let Some(k) = key {
            if ctx.quarantined.iter().any(|q| *q == k) {
                return Verdict::Halt { reason: format!("{k} is quarantined") };
            }
        }
        Verdict::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_ledger() -> (PathBuf, Ledger) {
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        tmp_ledger_at(stamp)
    }

    fn tmp_ledger_at(stamp: u128) -> (PathBuf, Ledger) {
        // A timestamp is diagnostic, not uniqueness: Windows clocks may repeat.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let d = loop {
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let candidate = std::env::temp_dir().join(format!("xnet-gates-test-{}-{stamp}-{nonce}", std::process::id()));
            match std::fs::create_dir(&candidate) {
                Ok(()) => break candidate,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot allocate test directory: {error}"),
            }
        };
        let p = d.join("ledger.jsonl");
        let l = Ledger::open(&p).unwrap();
        (d, l)
    }

    #[test]
    fn parallel_test_roots_hold_independent_writer_leases_at_the_same_timestamp() {
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let workers: Vec<_> = (0..8).map(|_| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                tmp_ledger_at(0)
            })
        }).collect();
        // Hold every writer until all opens succeed. Equal fixture clocks must
        // never share a root or delete another test's live lease.
        let fixtures: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        let roots: std::collections::BTreeSet<_> = fixtures.iter().map(|(root, _)| root.clone()).collect();
        assert_eq!(roots.len(), 8);
        drop(fixtures);
        for root in roots { std::fs::remove_dir_all(root).unwrap(); }
    }

    #[test]
    fn warm_read_on_critical_path_halts_and_receipts() {
        let (d, mut l) = tmp_ledger();
        let chain = GateChain { gates: vec![Box::new(StoragePathGate), Box::new(QuarantineGate)] };
        let v = chain.admit_and_receipt(
            &Op::StorageRead { tier: "warm".into(), digest: "abc".into() },
            &Ctx::default(),
            &mut l,
            1_700_000_000,
        );
        assert!(matches!(v, Verdict::Halt { .. }));
        assert_eq!(Ledger::verify(d.join("ledger.jsonl")).unwrap(), 1);
        drop(l);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn quarantined_digest_halts() {
        let (d, mut l) = tmp_ledger();
        let chain = GateChain { gates: vec![Box::new(QuarantineGate)] };
        let ctx = Ctx { quarantined: vec!["poison".into()], ..Default::default() };
        let v = chain.admit_and_receipt(
            &Op::StorageRead { tier: "hot".into(), digest: "poison".into() },
            &ctx,
            &mut l,
            1_700_000_000,
        );
        assert!(matches!(v, Verdict::Halt { .. }));
        drop(l);
        std::fs::remove_dir_all(&d).unwrap();
    }
}
