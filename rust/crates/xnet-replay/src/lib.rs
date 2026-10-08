//! xnet-replay — deterministic replay. The audit superpower and the
//! fixture-core test harness (WO#1 Stage 1B' runs on this).
//! Rebuilds a task from ledger receipts + CAS objects and bit-compares
//! the rebuilt output digest against the recorded one. Any mismatch is a
//! finding, never something to paper over.

use thiserror::Error;
use xnet_cas::Cas;
use xnet_ledger::{Ledger, LedgerError};

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("ledger: {0}")]
    Ledger(#[from] LedgerError),
    #[error("cas: {0}")]
    Cas(#[from] xnet_cas::CasError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("output mismatch: recorded {recorded}, rebuilt {rebuilt}")]
    Mismatch { recorded: String, rebuilt: String },
}

/// Read all receipts in [from_seq, to_seq] after verifying the whole chain.
/// Replay never operates on an unverified chain (stop rule, sim S12).
pub fn receipts_in_range(
    ledger_path: &std::path::Path,
    from_seq: u64,
    to_seq: u64,
) -> Result<Vec<serde_json::Value>, ReplayError> {
    let count = Ledger::verify(ledger_path)?; // whole chain first — no partial trust
    // A fresh audit has no file until its first append; vacuous verification
    // is valid for missing and zero-length audits alike.
    if count == 0 { return Ok(Vec::new()); }
    let f = std::fs::File::open(ledger_path)?;
    let mut out = Vec::new();
    for line in std::io::BufRead::lines(std::io::BufReader::new(f)) {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let v: serde_json::Value = serde_json::from_str(&line)?;
        let seq = v["seq"].as_u64().unwrap_or(u64::MAX);
        if (from_seq..=to_seq).contains(&seq) {
            out.push(v);
        }
    }
    Ok(out)
}

/// Verify a recorded output: rebuild the digest from CAS-stored output bytes
/// and compare against the digest recorded in the seal receipt.
pub fn verify_output_digest(
    cas: &Cas,
    recorded_digest_hex: &str,
) -> Result<(), ReplayError> {
    let h = xnet_ledger::unhex(recorded_digest_hex)
        .ok_or_else(|| ReplayError::Mismatch {
            recorded: recorded_digest_hex.into(),
            rebuilt: "unparseable".into(),
        })?;
    let bytes = cas.get(&h)?; // rehash-on-read proves bytes match address
    let rebuilt = {
        use sha2::{Digest, Sha256};
        let mut d = Sha256::new();
        d.update(&bytes);
        format!("{:x}", d.finalize())
    };
    if rebuilt != recorded_digest_hex {
        return Err(ReplayError::Mismatch { recorded: recorded_digest_hex.into(), rebuilt });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use xnet_ledger::{Actor, Kind};

    #[test]
    fn range_read_and_output_verify() {
        let d = std::env::temp_dir().join(format!("xnet-replay-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let lp = d.join("ledger.jsonl");
        let cas = Cas::open(d.join("cas")).unwrap();
        let mut l = Ledger::open(&lp).unwrap();
        let out_digest = cas.put(b"task output v1").unwrap();
        l.append(Kind::Seal, Actor::System, 1, out_digest, BTreeMap::new()).unwrap();
        l.append(Kind::Measurement, Actor::System, 2, [9u8; 32], BTreeMap::new()).unwrap();
        drop(l);

        let rs = receipts_in_range(&lp, 0, 0).unwrap();
        assert_eq!(rs.len(), 1);
        verify_output_digest(&cas, &xnet_ledger::hex(out_digest)).unwrap();

        // corrupted recording must fail loudly
        let mut bad = xnet_ledger::hex(out_digest);
        bad.replace_range(..2, "00");
        assert!(verify_output_digest(&cas, &bad).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
