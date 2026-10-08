//! xnet-ledger — SISMA receipt ledger. The sole mutation channel of XNET.
//!
//! Rules enforced here (non-negotiable, both lanes agreed):
//! - append-only: no update, no delete, no rewrite — ever;
//! - every receipt carries `prev_hash`; genesis carries `null`;
//! - hashing is over canonical JSON (sorted keys via BTreeMap, UTF-8, no
//!   insignificant whitespace) EXCLUDING the `receipt_hash` field itself;
//! - `verify()` replays the whole chain and names the first broken `seq`;
//! - receipts prove invariants only. A hash proves existence/integrity,
//!   never semantic truth.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub type Hash32 = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Admission,
    Seal,
    Measurement,
    Transition,
    GateVerdict,
    Rejection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Actor {
    Operator,
    Assistant,
    Peer,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub seq: u64,
    pub ts_utc: i64,
    pub kind: Kind,
    pub actor: Actor,
    /// sha256 of the payload this receipt attests (file, digest set, verdict...).
    /// Counts and hashes ONLY — never prompt/completion content (rule 5).
    pub payload_hash: Hash32,
    pub prev_hash: Option<Hash32>,
    /// Free-form machine-readable detail, e.g. {"gate":"g-ledger-integrity","pass":true}
    #[serde(default)]
    pub detail: BTreeMap<String, serde_json::Value>,
    pub receipt_hash: Hash32,
}

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("writer lease already present; existing owner or legacy lease must be inspected")]
    WriterLeasePresent,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("chain break at seq {seq}: {why}")]
    ChainBreak { seq: u64, why: String },
    #[error("append out of order: expected seq {expected}, got {got}")]
    OutOfOrder { expected: u64, got: u64 },
}

fn sha256(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Canonical bytes of a receipt MINUS its `receipt_hash` field.
/// serde_json::Value + BTreeMap-backed Map gives sorted keys; no whitespace.
fn canonical_body(r: &Receipt) -> Vec<u8> {
    let v = serde_json::json!({
        "seq": r.seq,
        "ts_utc": r.ts_utc,
        "kind": r.kind,
        "actor": r.actor,
        "payload_hash": hex(r.payload_hash),
        "prev_hash": r.prev_hash.map(hex),
        "detail": r.detail,
    });
    serde_json::to_vec(&v).expect("canonical serialization cannot fail")
}

pub fn hex(h: Hash32) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Option<Hash32> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// One receipt as stored on disk: hashes hex-encoded for diffability.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Line {
    seq: u64,
    ts_utc: i64,
    kind: Kind,
    actor: Actor,
    payload_hash: String,
    prev_hash: Option<String>,
    #[serde(default)]
    detail: BTreeMap<String, serde_json::Value>,
    receipt_hash: String,
}

impl From<&Receipt> for Line {
    fn from(r: &Receipt) -> Self {
        Line {
            seq: r.seq,
            ts_utc: r.ts_utc,
            kind: r.kind,
            actor: r.actor,
            payload_hash: hex(r.payload_hash),
            prev_hash: r.prev_hash.map(hex),
            detail: r.detail.clone(),
            receipt_hash: hex(r.receipt_hash),
        }
    }
}

impl TryFrom<Line> for Receipt {
    type Error = LedgerError;
    fn try_from(l: Line) -> Result<Self, Self::Error> {
        Ok(Receipt {
            seq: l.seq,
            ts_utc: l.ts_utc,
            kind: l.kind,
            actor: l.actor,
            payload_hash: unhex(&l.payload_hash)
                .ok_or(LedgerError::ChainBreak { seq: l.seq, why: "bad payload_hash hex".into() })?,
            prev_hash: match &l.prev_hash {
                Some(s) => Some(unhex(s)
                    .ok_or(LedgerError::ChainBreak { seq: l.seq, why: "bad prev_hash hex".into() })?),
                None => None,
            },
            detail: l.detail,
            receipt_hash: unhex(&l.receipt_hash)
                .ok_or(LedgerError::ChainBreak { seq: l.seq, why: "bad receipt_hash hex".into() })?,
        })
    }
}

pub struct Ledger {
    path: PathBuf,
    next_seq: u64,
    tip: Option<Hash32>,
    _writer: WriterLease,
}

struct WriterLease {
    _file: File,
    #[cfg(not(windows))] path: PathBuf,
    #[cfg(not(windows))] identity: Vec<u8>,
}
impl WriterLease {
    fn acquire(path: &Path) -> Result<Self, LedgerError> {
        let path = path.with_extension("writer.lock");
        let identity = format!("{}-{:?}", std::process::id(), std::time::SystemTime::now()).into_bytes();
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)] {
            use std::os::windows::fs::OpenOptionsExt;
            // Exclusive, non-inherited ownership. Windows releases/deletes this
            // newly created lease on handle close, including a killed process.
            // CREATE_NEW never opens or deletes an existing/legacy lease.
            options.access_mode(0x40010000).share_mode(0).custom_flags(0x04000000);
        }
        let mut file = options.open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists
                || error.raw_os_error() == Some(32)
                || error.raw_os_error() == Some(5) && path.exists() {
                LedgerError::WriterLeasePresent
            } else { LedgerError::Io(error) }
        })?;
        file.write_all(&identity)?;
        file.sync_all()?;
        Ok(Self {
            _file: file,
            #[cfg(not(windows))] path,
            #[cfg(not(windows))] identity,
        })
    }
}
impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(not(windows))]
        if std::fs::read(&self.path).ok().as_deref() == Some(self.identity.as_slice()) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

impl Ledger {
    /// Open (or create) a ledger and verify the existing chain before use.
    /// Refuses to append to a broken chain.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref().to_path_buf();
        let writer = WriterLease::acquire(&path)?;
        let receipts = read_all(&path)?;
        let (next_seq, tip) = verify_chain(&receipts)?;
        Ok(Self { path, next_seq, tip, _writer: writer })
    }

    /// THE ONLY mutation path. Computes the hash, appends one JSONL line, fsyncs.
    pub fn append(
        &mut self,
        kind: Kind,
        actor: Actor,
        ts_utc: i64,
        payload_hash: Hash32,
        detail: BTreeMap<String, serde_json::Value>,
    ) -> Result<Receipt, LedgerError> {
        let mut r = Receipt {
            seq: self.next_seq,
            ts_utc,
            kind,
            actor,
            payload_hash,
            prev_hash: self.tip,
            detail,
            receipt_hash: [0u8; 32],
        };
        r.receipt_hash = sha256(&canonical_body(&r));
        let mut line = serde_json::to_vec(&Line::from(&r))?;
        line.push(b'\n');
        let mut f = OpenOptions::new().create(true).append(true).open(&self.path)?;
        f.write_all(&line)?;
        f.sync_all()?;
        self.tip = Some(r.receipt_hash);
        self.next_seq += 1;
        Ok(r)
    }

    /// Full independent replay. Exit-code friendly for the verifier CLI.
    pub fn verify(path: impl AsRef<Path>) -> Result<u64, LedgerError> {
        let receipts = read_all(path.as_ref())?;
        let (n, _) = verify_chain(&receipts)?;
        Ok(n)
    }

    pub fn tip(&self) -> Option<Hash32> {
        self.tip
    }
    pub fn verify_head(path: impl AsRef<Path>) -> Result<(u64, Option<Hash32>), LedgerError> {
        verify_chain(&read_all(path.as_ref())?)
    }
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }
}

fn read_all(path: &Path) -> Result<Vec<Receipt>, LedgerError> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let f: File = File::open(path)?;
    if f.metadata()?.len() > 64 * 1024 * 1024 { return Err(LedgerError::ChainBreak {seq:0,why:"audit size limit".into()}); }
    let mut out = Vec::new();
    let mut reader = BufReader::new(f);
    loop {
        let mut line = Vec::new();
        let n = reader.by_ref().take(262146).read_until(b'\n', &mut line)?;
        if n == 0 { break; }
        if n > 262144 || line.last() != Some(&b'\n') || out.len() >= 100000 {
            return Err(LedgerError::ChainBreak {seq:out.len() as u64,why:"invalid audit frame".into()});
        }
        let l: Line = serde_json::from_slice(&line)?;
        if serde_json::to_vec(&l)? != line[..line.len()-1] {
            return Err(LedgerError::ChainBreak {seq:out.len() as u64,why:"noncanonical audit frame".into()});
        }
        out.push(Receipt::try_from(l)?);
    }
    Ok(out)
}

/// Returns (next_seq, tip) on success; ChainBreak naming the first bad seq otherwise.
fn verify_chain(rs: &[Receipt]) -> Result<(u64, Option<Hash32>), LedgerError> {
    let mut prev: Option<Hash32> = None;
    for (i, r) in rs.iter().enumerate() {
        if r.seq != i as u64 {
            return Err(LedgerError::OutOfOrder { expected: i as u64, got: r.seq });
        }
        if r.prev_hash != prev {
            return Err(LedgerError::ChainBreak {
                seq: r.seq,
                why: "prev_hash does not match chain tip".into(),
            });
        }
        if r.receipt_hash != sha256(&canonical_body(r)) {
            return Err(LedgerError::ChainBreak {
                seq: r.seq,
                why: "receipt_hash does not match canonical body".into(),
            });
        }
        prev = Some(r.receipt_hash);
    }
    Ok((rs.len() as u64, prev))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir() -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        loop {
            let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let d = std::env::temp_dir().join(format!("xnet-ledger-test-{}-{}-{}", std::process::id(), std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos(), nonce));
            match std::fs::create_dir(&d) {
                Ok(()) => return d,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create test directory: {error}"),
            }
        }
    }

    fn append_three(l: &mut Ledger) {
        for i in 0..3u8 {
            l.append(
                Kind::Measurement,
                Actor::System,
                1_700_000_000 + i as i64,
                sha256(&[i]),
                BTreeMap::new(),
            )
            .unwrap();
        }
    }

    #[test]
    fn chain_builds_and_verifies() {
        let d = tmpdir();
        let p = d.join("ledger.jsonl");
        let mut l = Ledger::open(&p).unwrap();
        append_three(&mut l);
        assert_eq!(Ledger::verify(&p).unwrap(), 3);
        assert!(Ledger::open(&p).is_err());
        drop(l);
        // reopen: chain still good, continues at seq 3
        let l2 = Ledger::open(&p).unwrap();
        assert_eq!(l2.next_seq(), 3);
        assert!(l2.tip().is_some());
        drop(l2);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn refuses_extra_fields_and_incomplete_tail() {
        let d=tmpdir(); let p=d.join("ledger.jsonl");
        let mut ledger=Ledger::open(&p).unwrap();append_three(&mut ledger);drop(ledger);
        let original=std::fs::read_to_string(&p).unwrap();
        std::fs::write(&p,original.replace("\"detail\":{}","\"detail\":{},\"extra\":true")).unwrap();
        assert!(Ledger::verify(&p).is_err());
        std::fs::write(&p,&original[..original.len()-1]).unwrap();
        assert!(Ledger::verify(&p).is_err());
        std::fs::write(&p,original).unwrap();assert_eq!(Ledger::verify(&p).unwrap(),3);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn tamper_is_detected_at_correct_seq() {
        let d = tmpdir();
        let p = d.join("ledger.jsonl");
        let mut l = Ledger::open(&p).unwrap();
        append_three(&mut l);
        drop(l);
        // flip one byte inside line 2 (seq 1)
        let raw = std::fs::read(&p).unwrap();
        let mut lines: Vec<Vec<u8>> = raw.split(|&b| b == b'\n').map(|s| s.to_vec()).collect();
        let pos = lines[1].len() / 2;
        lines[1][pos] ^= 0x01;
        let mut rebuilt = lines.join(&b'\n');
        if rebuilt.ends_with(&[b'\n'][..]) == false {
            rebuilt.push(b'\n');
        }
        std::fs::write(&p, rebuilt).unwrap();
        match Ledger::verify(&p) {
            Err(LedgerError::ChainBreak { seq, .. }) => assert_eq!(seq, 1),
            Err(LedgerError::Json(_)) => { /* byte flip broke JSON: also a detection */ }
            other => panic!("tamper not detected: {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn open_refuses_broken_chain() {
        let d = tmpdir();
        let p = d.join("ledger.jsonl");
        let mut l = Ledger::open(&p).unwrap();
        append_three(&mut l);
        drop(l);
        // truncate the last line -> chain shortens but stays internally valid;
        // instead corrupt prev_hash linkage by swapping lines 2 and 3
        let raw = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = raw.lines().collect();
        lines.swap(1, 2);
        std::fs::write(&p, lines.join("\n") + "\n").unwrap();
        assert!(Ledger::open(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
