use crate::detect::{ArtifactKind, detect_bytes, detect_path};
use crate::error::{Error, Result};
use crate::hash;
use std::any::Any;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// Default maximum input size (1 GiB). Hostile inputs can be huge; we refuse
/// rather than exhaust memory.
pub const DEFAULT_MAX_SIZE: u64 = 1 << 30;

/// An input under analysis: raw bytes plus what we believe they are.
///
/// rex **never executes** an artifact. Everything is static inspection of bytes.
#[derive(Debug)]
pub struct Artifact {
    name: String,
    path: Option<PathBuf>,
    data: Vec<u8>,
    kind: ArtifactKind,
    sha256: OnceLock<String>,
    memo: Memo,
}

/// Per-artifact cache of expensive derived values (one per type), so the analyzers that run over
/// the same input share one parse instead of each re-parsing a 200 MB binary.
#[derive(Default)]
struct Memo(Mutex<Vec<Arc<dyn Any + Send + Sync>>>);

impl std::fmt::Debug for Memo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Memo")
    }
}

impl Artifact {
    /// Load from a path. Directories are allowed and produce an empty-data artifact.
    pub fn from_path(path: impl AsRef<Path>, max_size: u64) -> Result<Self> {
        let path = path.as_ref();
        let io = |source| Error::Io {
            path: path.to_path_buf(),
            source,
        };
        let meta = std::fs::metadata(path).map_err(io)?;
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        if meta.is_dir() {
            return Ok(Self {
                name,
                path: Some(path.to_path_buf()),
                data: Vec::new(),
                kind: ArtifactKind::Directory,
                sha256: OnceLock::new(),
                memo: Memo::default(),
            });
        }
        if !meta.is_file() {
            // FIFOs block, and /dev/zero-style devices never end; neither is a file to analyse.
            return Err(Error::Unsupported(format!(
                "{} is not a regular file (FIFO, socket or device)",
                path.display()
            )));
        }
        if meta.len() > max_size {
            return Err(Error::TooLarge {
                size: meta.len(),
                limit: max_size,
            });
        }
        // Read through a cap as well: /proc files report size 0, and a file can grow after stat.
        let mut data = Vec::with_capacity(meta.len().min(max_size) as usize);
        {
            use std::io::Read;
            std::fs::File::open(path)
                .map_err(io)?
                .take(max_size.saturating_add(1))
                .read_to_end(&mut data)
                .map_err(io)?;
        }
        if data.len() as u64 > max_size {
            return Err(Error::TooLarge {
                size: data.len() as u64,
                limit: max_size,
            });
        }
        let kind = detect_path(path, &data);
        Ok(Self {
            name,
            path: Some(path.to_path_buf()),
            data,
            kind,
            sha256: OnceLock::new(),
            memo: Memo::default(),
        })
    }

    /// Build from in-memory bytes.
    pub fn from_bytes(name: impl Into<String>, data: Vec<u8>) -> Self {
        let name = name.into();
        let kind = detect_bytes(&data, Some(&name));
        Self {
            name,
            path: None,
            data,
            kind,
            sha256: OnceLock::new(),
            memo: Memo::default(),
        }
    }

    /// Override the detected kind (e.g. `--as har`).
    pub fn with_kind(mut self, kind: ArtifactKind) -> Self {
        self.kind = kind;
        self
    }

    /// Display name (file name).
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Filesystem path, if loaded from disk.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Raw bytes (empty for directories).
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Detected kind.
    pub fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Size in bytes.
    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    /// The value of type `T` derived from this artifact, computed once on first use. Analyzers
    /// run in parallel; a second caller waits for the first instead of computing it again.
    pub fn memo<T: Any + Send + Sync>(&self, compute: impl FnOnce(&Self) -> T) -> Arc<T> {
        let slot: Arc<OnceLock<Arc<T>>> = {
            let mut v = self.memo.0.lock().unwrap_or_else(|e| e.into_inner());
            match v
                .iter()
                .find_map(|x| Arc::clone(x).downcast::<OnceLock<Arc<T>>>().ok())
            {
                Some(s) => s,
                None => {
                    let s = Arc::new(OnceLock::new());
                    v.push(s.clone());
                    s
                }
            }
        };
        slot.get_or_init(|| Arc::new(compute(self))).clone()
    }

    /// SHA-256 (cached).
    pub fn sha256(&self) -> &str {
        self.sha256.get_or_init(|| hash::sha256_hex(&self.data))
    }

    /// Overall Shannon entropy.
    pub fn entropy(&self) -> f64 {
        hash::entropy(&self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_file_and_dir() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("x.bin");
        std::fs::write(&f, b"\x7fELF\x02\x01\x01\x00").unwrap();
        let a = Artifact::from_path(&f, DEFAULT_MAX_SIZE).unwrap();
        assert_eq!(a.kind(), ArtifactKind::Elf);
        assert_eq!(a.size(), 8);
        let d = Artifact::from_path(dir.path(), DEFAULT_MAX_SIZE).unwrap();
        assert_eq!(d.kind(), ArtifactKind::Directory);
    }

    #[test]
    fn enforces_size_limit() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big");
        std::fs::write(&f, vec![0u8; 100]).unwrap();
        assert!(matches!(
            Artifact::from_path(&f, 10),
            Err(Error::TooLarge { .. })
        ));
    }
}
