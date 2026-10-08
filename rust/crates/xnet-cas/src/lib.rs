//! xnet-cas — content-addressed store on the hot NVMe tier.
//! Objects are addressed by sha256 of their bytes, never by path.
//! Writes are crash-safe (temp + rename); reads rehash and reject corruption.

use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub type Hash32 = [u8; 32];

#[derive(Debug, Error)]
pub enum CasError {
    #[error("storage path or object bound rejected")]
    Bounds,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("integrity: stored bytes do not match address {0}")]
    Integrity(String),
}

pub fn hex(h: &Hash32) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

pub struct Cas {
    root: PathBuf, // Host selects the root; this type does not prove physical disk speed.
}

impl Cas {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CasError> {
        let root = root.as_ref().to_path_buf();
        check_path(&root)?;
        fs::create_dir_all(&root)?;
        let cas = Self { root };
        // Partial files may belong to an active writer; cleanup is never automatic.
        Ok(cas)
    }

    fn object_path(&self, h: &Hash32) -> PathBuf {
        let s = hex(h);
        self.root.join(&s[..2]).join(&s)
    }

    /// Store bytes; returns their content address. Idempotent.
    pub fn put(&self, bytes: &[u8]) -> Result<Hash32, CasError> {
        if bytes.len() > 65536 { return Err(CasError::Bounds); }
        let h: Hash32 = {
            let mut d = Sha256::new();
            d.update(bytes);
            d.finalize().into()
        };
        let p = self.object_path(&h);
        check_path(&p)?;
        if p.exists() {
            self.get(&h)?;
            return Ok(h);
        }
        fs::create_dir_all(p.parent().unwrap())?;
        let stamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos();
        let tmp = p.with_extension(format!("{}-{stamp}.partial", std::process::id()));
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        if let Err(error) = fs::rename(&tmp, &p) {
            if p.exists() { self.get(&h)?; fs::remove_file(&tmp)?; }
            else { return Err(error.into()); }
        }
        self.get(&h)?;
        Ok(h)
    }

    /// Read by address, REHASHING the bytes before returning them.
    pub fn get(&self, h: &Hash32) -> Result<Vec<u8>, CasError> {
        let path = self.object_path(h);
        check_path(&path)?;
        let mut file = fs::File::open(path)?;
        if file.metadata()?.len() > 65536 { return Err(CasError::Bounds); }
        let mut bytes = Vec::new();
        use std::io::Read;
        std::io::Read::by_ref(&mut file).take(65537).read_to_end(&mut bytes)?;
        if bytes.len() > 65536 { return Err(CasError::Bounds); }
        let actual: Hash32 = {
            let mut d = Sha256::new();
            d.update(&bytes);
            d.finalize().into()
        };
        if &actual != h {
            return Err(CasError::Integrity(hex(h)));
        }
        Ok(bytes)
    }

    pub fn contains(&self, h: &Hash32) -> bool {
        self.object_path(h).exists()
    }

    /// Explicit maintenance only; caller must first establish that no writers are active.
    pub fn sweep_orphans(&self) -> Result<(), CasError> {
        for entry in fs::read_dir(&self.root)? {
            let shard = entry?;
            if !shard.file_type()?.is_dir() {
                continue;
            }
            for obj in fs::read_dir(shard.path())? {
                let obj = obj?;
                if obj.path().extension().map(|e| e == "partial").unwrap_or(false) {
                    fs::remove_file(obj.path())?;
                }
            }
        }
        Ok(())
    }
}
fn check_path(path: &Path) -> Result<(), CasError> {
    for p in path.ancestors() {
        if let Ok(m) = fs::symlink_metadata(p) {
            if m.file_type().is_symlink() { return Err(CasError::Bounds); }
            #[cfg(windows)] { use std::os::windows::fs::MetadataExt; if m.file_attributes() & 0x400 != 0 { return Err(CasError::Bounds); } }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_rehash() {
        let d = std::env::temp_dir().join(format!("xnet-cas-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        let cas = Cas::open(&d).unwrap();
        let h = cas.put(b"hello xnet").unwrap();
        assert_eq!(cas.get(&h).unwrap(), b"hello xnet");
        // corrupt on disk -> get must refuse
        let p = cas.object_path(&h);
        fs::write(&p, b"tampered").unwrap();
        assert!(matches!(cas.get(&h), Err(CasError::Integrity(_))));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn startup_preserves_partial_files() {
        let d = std::env::temp_dir().join(format!("xnet-cas-sweep-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(d.join("ab")).unwrap();
        fs::write(d.join("ab").join("deadbeef.partial"), b"x").unwrap();
        let _ = Cas::open(&d).unwrap();
        assert!(d.join("ab").join("deadbeef.partial").exists());
        let _ = fs::remove_dir_all(&d);
    }
}
