pub mod json;
pub mod sha256;

use json::{n, obj, s, Json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub seq: usize,
    pub prev_hash: String,
    pub event_hash: String,
    pub receipt_hash: String,
}

impl Receipt {
    pub fn as_json(&self) -> Json {
        obj([
            ("seq".into(), n(self.seq)),
            ("prev_hash".into(), s(self.prev_hash.as_str())),
            ("event_hash".into(), s(self.event_hash.as_str())),
            ("receipt_hash".into(), s(self.receipt_hash.as_str())),
        ])
    }

    fn from_json(value: &Json) -> Result<Self, String> {
        Ok(Self {
            seq: value.usize_field("seq")?,
            prev_hash: value.str_field("prev_hash")?.to_string(),
            event_hash: value.str_field("event_hash")?.to_string(),
            receipt_hash: value.str_field("receipt_hash")?.to_string(),
        })
    }

    fn calculate(seq: usize, prev_hash: &str, event_hash: &str) -> Self {
        let preimage = obj([
            ("seq".into(), n(seq)),
            ("prev_hash".into(), s(prev_hash)),
            ("event_hash".into(), s(event_hash)),
        ]).encode();
        Self {
            seq,
            prev_hash: prev_hash.to_string(),
            event_hash: event_hash.to_string(),
            receipt_hash: sha256::hex(preimage.as_bytes()),
        }
    }
}

struct JournalLock { path: PathBuf }

impl JournalLock {
    fn acquire(path: &Path) -> Result<Self, String> {
        for _ in 0..500 {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    let guard = Self { path: path.to_path_buf() };
                    writeln!(file, "pid={}", std::process::id()).map_err(|e| e.to_string())?;
                    file.sync_all().map_err(|e| e.to_string())?;
                    return Ok(guard);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(format!("journal lock: {error}")),
            }
        }
        Err(format!("journal lock busy: {}", path.display()))
    }
}

impl Drop for JournalLock {
    fn drop(&mut self) { let _ = fs::remove_file(&self.path); }
}

pub struct Engine {
    data_dir: PathBuf,
    journal_len: u64,
    receipts: Vec<Receipt>,
    by_id: HashMap<String, usize>,
}

impl Engine {
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Self, String> {
        let data_dir = data_dir.as_ref().to_path_buf();
        fs::create_dir_all(&data_dir).map_err(|e| format!("create data directory: {e}"))?;
        let mut engine = Self { data_dir, journal_len: 0, receipts: Vec::new(), by_id: HashMap::new() };
        engine.reload()?;
        Ok(engine)
    }

    fn journal_path(&self) -> PathBuf { self.data_dir.join("journal.jsonl") }

    pub fn reload(&mut self) -> Result<(), String> {
        let path = self.journal_path();
        let mut bytes = Vec::new();
        match File::open(&path) {
            Ok(mut file) => { file.read_to_end(&mut bytes).map_err(|e| format!("read journal: {e}"))?; }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(format!("open journal: {error}")),
        }
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            return Err("journal ends in an incomplete record; preserve it for recovery".into());
        }
        let text = String::from_utf8(bytes).map_err(|_| "journal is not UTF-8".to_string())?;
        let mut receipts = Vec::new();
        let mut by_id = HashMap::new();
        let mut prev_hash = ZERO_HASH.to_string();
        for (index, line) in text.lines().enumerate() {
            let record = Json::parse(line).map_err(|e| format!("journal line {}: {e}", index + 1))?;
            let event = record.get("event").ok_or_else(|| format!("journal line {} missing event", index + 1))?;
            validate_event(event).map_err(|e| format!("journal line {}: {e}", index + 1))?;
            let id = event.str_field("event_id")?.to_string();
            if by_id.contains_key(&id) { return Err(format!("journal duplicate event_id at line {}", index + 1)); }
            let receipt = Receipt::from_json(record.get("receipt").ok_or_else(|| format!("journal line {} missing receipt", index + 1))?)?;
            let event_hash = sha256::hex(event.encode().as_bytes());
            let expected = Receipt::calculate(index + 1, &prev_hash, &event_hash);
            if receipt != expected { return Err(format!("journal receipt mismatch at line {}", index + 1)); }
            prev_hash = receipt.receipt_hash.clone();
            by_id.insert(id, index);
            receipts.push(receipt);
        }
        self.journal_len = text.len() as u64;
        self.receipts = receipts;
        self.by_id = by_id;
        Ok(())
    }

    pub fn handle(&mut self, command: &Json) -> Result<Json, String> {
        match command.str_field("op")? {
            "health" => Ok(obj([
                ("ok".into(), Json::Bool(true)),
                ("op".into(), s("health")),
                ("service".into(), s("xnet-core")),
                ("protocol_version".into(), n(1)),
                ("events".into(), n(self.receipts.len())),
                ("tail_hash".into(), s(self.receipts.last().map(|r| r.receipt_hash.as_str()).unwrap_or(ZERO_HASH))),
            ])),
            "verify" => {
                self.reload()?;
                Ok(obj([
                    ("ok".into(), Json::Bool(true)),
                    ("op".into(), s("verify")),
                    ("events".into(), n(self.receipts.len())),
                    ("tail_hash".into(), s(self.receipts.last().map(|r| r.receipt_hash.as_str()).unwrap_or(ZERO_HASH))),
                ]))
            }
            "ingest" => self.ingest(command.get("event").ok_or_else(|| "missing event".to_string())?),
            "run" => run_jobs(command),
            other => Err(format!("unsupported operation: {other}")),
        }
    }

    pub fn ingest(&mut self, event: &Json) -> Result<Json, String> {
        validate_event(event)?;
        let event_id = event.str_field("event_id")?.to_string();
        let event_hash = sha256::hex(event.encode().as_bytes());
        let _lock = JournalLock::acquire(&self.data_dir.join("journal.lock"))?;
        let size = match fs::metadata(self.journal_path()) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(format!("stat journal: {error}")),
        };
        if size != self.journal_len { self.reload()?; }
        if let Some(&index) = self.by_id.get(&event_id) {
            let receipt = &self.receipts[index];
            if receipt.event_hash != event_hash { return Err("event_id conflict: content differs".into()); }
            return Ok(ingest_response(receipt, true));
        }
        let prev_hash = self.receipts.last().map(|r| r.receipt_hash.as_str()).unwrap_or(ZERO_HASH);
        let receipt = Receipt::calculate(self.receipts.len() + 1, prev_hash, &event_hash);
        let record = obj([
            ("event".into(), event.clone()),
            ("receipt".into(), receipt.as_json()),
        ]);
        let line = format!("{}\n", record.encode());
        let mut file = OpenOptions::new().append(true).create(true).open(self.journal_path())
            .map_err(|e| format!("open journal for append: {e}"))?;
        file.write_all(line.as_bytes()).map_err(|e| format!("append journal: {e}"))?;
        file.sync_all().map_err(|e| format!("sync journal: {e}"))?;
        self.journal_len += line.len() as u64;
        self.by_id.insert(event_id, self.receipts.len());
        self.receipts.push(receipt.clone());
        Ok(ingest_response(&receipt, false))
    }
}

fn ingest_response(receipt: &Receipt, duplicate: bool) -> Json {
    obj([
        ("ok".into(), Json::Bool(true)),
        ("op".into(), s("ingest")),
        ("duplicate".into(), Json::Bool(duplicate)),
        ("receipt".into(), receipt.as_json()),
    ])
}

pub fn validate_event(event: &Json) -> Result<(), String> {
    let Json::Object(fields) = event else { return Err("event must be an object".into()); };
    let allowed = ["v", "event_id", "task_id", "scope_id", "policy_version", "source", "kind", "time_utc", "payload", "payload_sha256", "signature_hmac_sha256"];
    if fields.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err("event fields do not match protocol v1".into());
    }
    if event.usize_field("v")? != 1 { return Err("unsupported event version".into()); }
    for (key, limit) in [("event_id",128),("task_id",128),("scope_id",128),("policy_version",64),("source",64),("kind",64)] {
        let value = event.str_field(key)?;
        if value.is_empty() || value.chars().count() > limit || value.chars().any(|c| c < ' ') {
            return Err(format!("invalid event field: {key}"));
        }
    }
    let payload = event.get("payload").ok_or_else(|| "missing payload".to_string())?;
    if !matches!(payload, Json::Object(_)) || payload.encode().len() > 65_536 {
        return Err("payload must be an object of at most 64 KiB".into());
    }
    match event.get("time_utc") {
        Some(Json::String(value)) if !value.is_empty() => {},
        Some(Json::Number(value)) if value.parse::<i64>().is_ok() => {},
        _ => return Err("invalid time_utc".into()),
    }
    let declared = event.str_field("payload_sha256")?;
    if declared.len() != 64 || !declared.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return Err("payload_sha256 must be lowercase SHA-256 hex".into());
    }
    let actual = sha256::hex(payload.encode().as_bytes());
    if declared != actual { return Err("payload_sha256 mismatch".into()); }
    if let Some(signature) = event.get("signature_hmac_sha256") {
        let Json::String(signature) = signature else { return Err("invalid event signature".into()); };
        if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
            return Err("invalid event signature".into());
        }
    }
    Ok(())
}

#[derive(Clone)]
enum FixtureKind { Sha256(String), SleepMs(u64) }

#[derive(Clone)]
struct FixtureJob { job_id: String, kind: FixtureKind }

fn run_jobs(command: &Json) -> Result<Json, String> {
    let task_id = command.str_field("task_id")?;
    if task_id.is_empty() { return Err("task_id is empty".into()); }
    let max_workers = command.usize_field("max_workers")?;
    if !(1..=32).contains(&max_workers) { return Err("max_workers must be 1..32".into()); }
    let raw_jobs = match command.get("jobs") { Some(Json::Array(jobs)) => jobs, _ => return Err("jobs must be an array".into()) };
    if raw_jobs.len() > 10_000 { return Err("jobs exceeds 10,000".into()); }
    let mut jobs = Vec::with_capacity(raw_jobs.len());
    let mut seen = HashSet::new();
    let mut total_sleep = 0u64;
    let mut total_data = 0usize;
    for raw in raw_jobs {
        let job_id = raw.str_field("job_id")?.to_string();
        if job_id.is_empty() || !seen.insert(job_id.clone()) { return Err("job_id must be nonempty and unique".into()); }
        let kind = match raw.str_field("kind")? {
            "sha256" => {
                let data = raw.str_field("data")?;
                if data.len() > 1_048_576 { return Err("sha256 fixture data exceeds 1 MiB".into()); }
                total_data += data.len();
                if total_data > 8 * 1024 * 1024 { return Err("total sha256 fixture data exceeds 8 MiB".into()); }
                FixtureKind::Sha256(data.to_string())
            }
            "sleep_ms" => {
                let ms = raw.usize_field("ms")?;
                if ms > 1_000 { return Err("sleep_ms fixture exceeds 1,000 ms".into()); }
                total_sleep += ms as u64;
                if total_sleep > 10_000 { return Err("total sleep fixture budget exceeds 10,000 ms".into()); }
                FixtureKind::SleepMs(ms as u64)
            }
            other => return Err(format!("unsupported fixture kind: {other}")),
        };
        jobs.push(FixtureJob { job_id, kind });
    }
    if jobs.is_empty() {
        return Ok(obj([
            ("ok".into(), Json::Bool(true)), ("op".into(), s("run")), ("task_id".into(), s(task_id)),
            ("max_workers".into(), n(max_workers)), ("completed".into(), n(0)), ("results".into(), Json::Array(Vec::new())),
        ]));
    }
    let count = jobs.len();
    let queue: Arc<Mutex<VecDeque<(usize, FixtureJob)>>> = Arc::new(Mutex::new(jobs.into_iter().enumerate().collect()));
    let (tx, rx) = mpsc::channel();
    let mut workers = Vec::new();
    for _ in 0..max_workers.min(count) {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        workers.push(thread::spawn(move || loop {
            let next = match queue.lock() { Ok(mut guard) => guard.pop_front(), Err(_) => return };
            let Some((index, job)) = next else { return };
            let result = match job.kind {
                FixtureKind::Sha256(data) => obj([
                    ("job_id".into(), s(job.job_id)), ("kind".into(), s("sha256")),
                    ("sha256".into(), s(sha256::hex(data.as_bytes()))), ("ok".into(), Json::Bool(true)),
                ]),
                FixtureKind::SleepMs(ms) => {
                    thread::sleep(Duration::from_millis(ms));
                    obj([
                        ("job_id".into(), s(job.job_id)), ("kind".into(), s("sleep_ms")),
                        ("slept_ms".into(), n(ms as usize)), ("ok".into(), Json::Bool(true)),
                    ])
                }
            };
            if tx.send((index, result)).is_err() { return; }
        }));
    }
    drop(tx);
    let mut results = vec![None; count];
    for _ in 0..count {
        let (index, result) = rx.recv().map_err(|_| "fixture worker stopped before all jobs completed".to_string())?;
        results[index] = Some(result);
    }
    for worker in workers { worker.join().map_err(|_| "fixture worker panicked".to_string())?; }
    Ok(obj([
        ("ok".into(), Json::Bool(true)), ("op".into(), s("run")), ("task_id".into(), s(task_id)),
        ("max_workers".into(), n(max_workers)), ("completed".into(), n(count)),
        ("results".into(), Json::Array(results.into_iter().map(|result| result.expect("all jobs received")).collect())),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let marker = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("xnet-core-test-{}-{marker}", std::process::id()))
    }
    fn event(id: &str) -> Json {
        let payload = obj([("a".into(), n(1)), ("z".into(), s("🐝"))]);
        obj([
            ("v".into(), n(1)), ("event_id".into(), s(id)), ("task_id".into(), s("task")),
            ("scope_id".into(), s("local")), ("policy_version".into(), s("1")),
            ("source".into(), s("fixture")), ("kind".into(), s("observation")),
            ("time_utc".into(), n(1_790_812_800)),
            ("payload_sha256".into(), s(sha256::hex(payload.encode().as_bytes()))),
            ("payload".into(), payload),
        ])
    }
    #[test]
    fn durable_chain_duplicate_and_tamper_detection() {
        let dir = temp_dir();
        let mut engine = Engine::open(&dir).unwrap();
        let first = engine.ingest(&event("one")).unwrap();
        assert_eq!(first.get("duplicate"), Some(&Json::Bool(false)));
        assert_eq!(event("one").str_field("payload_sha256").unwrap(), "2f6497afbdf6550ec2fbbe53c96be32c362ebbe4084a55261468d4483e5b5fdb");
        assert_eq!(engine.receipts[0].event_hash, "549636b4081901c3d3039028beff6337ec83ec50cd8032496135506fd29b7226");
        assert_eq!(engine.receipts[0].receipt_hash, "f35da1b26f2c3960c3008a2aecaa86967826efb4523f7ba46dd7a42929f75777");
        let repeated = engine.ingest(&event("one")).unwrap();
        assert_eq!(repeated.get("duplicate"), Some(&Json::Bool(true)));
        engine.ingest(&event("two")).unwrap();
        let expected_tail = engine.receipts[1].receipt_hash.clone();
        drop(engine);
        let engine = Engine::open(&dir).unwrap();
        assert_eq!(engine.receipts.len(), 2);
        assert_eq!(engine.receipts[1].prev_hash, engine.receipts[0].receipt_hash);
        assert_eq!(engine.receipts[1].receipt_hash, expected_tail);
        drop(engine);
        let path = dir.join("journal.jsonl");
        let mut text = fs::read_to_string(&path).unwrap();
        text = text.replace("\"event_id\":\"two\"", "\"event_id\":\"bad\"");
        fs::write(path, text).unwrap();
        assert!(Engine::open(&dir).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn fixture_workers_preserve_order_and_reject_commands() {
        let command = Json::parse("{\"op\":\"run\",\"task_id\":\"t\",\"max_workers\":2,\"jobs\":[{\"job_id\":\"slow\",\"kind\":\"sleep_ms\",\"ms\":15},{\"job_id\":\"hash\",\"kind\":\"sha256\",\"data\":\"abc\"}]}").unwrap();
        let result = run_jobs(&command).unwrap();
        let Json::Array(results) = result.get("results").unwrap() else { panic!("expected results"); };
        assert_eq!(results[0].str_field("job_id").unwrap(), "slow");
        assert_eq!(results[1].str_field("sha256").unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let bad = Json::parse("{\"op\":\"run\",\"task_id\":\"t\",\"max_workers\":1,\"jobs\":[{\"job_id\":\"x\",\"kind\":\"command\",\"data\":\"whoami\"}]}").unwrap();
        assert!(run_jobs(&bad).is_err());
    }
    #[test]
    fn payload_hash_gate() {
        let mut value = event("bad");
        if let Json::Object(fields) = &mut value { fields.insert("payload_sha256".into(), s(ZERO_HASH)); }
        assert!(validate_event(&value).is_err());
    }
}
