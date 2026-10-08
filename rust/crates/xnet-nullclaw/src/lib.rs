//! xnet-nullclaw — the exact deterministic CPU lane.
//! Hashing, diffing, receipt math, path policy: work with ONE correct answer.
//! The gate layer rejects any NullClaw task routed to a model (see xnet-gates).
//! Same input -> same output, always, or it is a bug, never a "personality".

use sha2::{Digest, Sha256};

/// Marker: tasks implementing this trait are forbidden on the model lane.
pub trait Deterministic {
    fn run(&self) -> NullClawOutput;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NullClawOutput {
    pub bytes: Vec<u8>,
    pub digest: [u8; 32],
}

impl NullClawOutput {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        let digest = {
            let mut d = Sha256::new();
            d.update(&bytes);
            d.finalize().into()
        };
        Self { bytes, digest }
    }
}

/// Exact byte diff (unified, line-based, no fuzz).
pub struct ExactDiff {
    pub old: String,
    pub new: String,
}

impl Deterministic for ExactDiff {
    fn run(&self) -> NullClawOutput {
        let mut out = String::new();
        let old: Vec<&str> = self.old.lines().collect();
        let new: Vec<&str> = self.new.lines().collect();
        // O(n*m) LCS-free minimal form: prefix/suffix trim, then mark the changed core.
        let mut start = 0;
        while start < old.len() && start < new.len() && old[start] == new[start] {
            start += 1;
        }
        let mut end_old = old.len();
        let mut end_new = new.len();
        while end_old > start && end_new > start && old[end_old - 1] == new[end_new - 1] {
            end_old -= 1;
            end_new -= 1;
        }
        for l in &old[..start] {
            out.push_str(&format!("  {l}\n"));
        }
        for l in &old[start..end_old] {
            out.push_str(&format!("- {l}\n"));
        }
        for l in &new[start..end_new] {
            out.push_str(&format!("+ {l}\n"));
        }
        for l in &old[end_old..] {
            out.push_str(&format!("  {l}\n"));
        }
        NullClawOutput::from_bytes(out.into_bytes())
    }
}

/// Path policy: is `path` inside an allowed root, with no traversal?
pub struct PathPolicy<'a> {
    pub root: &'a std::path::Path,
}

impl<'a> PathPolicy<'a> {
    pub fn admits(&self, path: &std::path::Path) -> bool {
        // lexical check only; callers canonicalize first when symlinks matter
        !path.components().any(|c| c == std::path::Component::ParentDir)
            && path.starts_with(self.root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn diff_is_deterministic() {
        let d = ExactDiff { old: "a\nb\nc\n".into(), new: "a\nx\nc\n".into() };
        let o1 = d.run();
        let o2 = ExactDiff { old: "a\nb\nc\n".into(), new: "a\nx\nc\n".into() }.run();
        assert_eq!(o1.digest, o2.digest);
        assert!(String::from_utf8(o1.bytes).unwrap().contains("- b\n+ x\n"));
    }

    #[test]
    fn traversal_rejected() {
        let p = PathPolicy { root: Path::new("work") };
        assert!(p.admits(Path::new("work/ok/file.rs")));
        assert!(!p.admits(Path::new("work/../escape")));
        assert!(!p.admits(Path::new("elsewhere/file")));
    }
}
