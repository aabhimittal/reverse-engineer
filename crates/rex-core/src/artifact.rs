use crate::detect::{ArtifactKind, detect_bytes, detect_path};
use crate::error::{Error, Result};
use crate::hash;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

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
            });
        }
        if meta.len() > max_size {
            return Err(Error::TooLarge {
                size: meta.len(),
                limit: max_size,
            });
        }
        let data = std::fs::read(path).map_err(io)?;
        let kind = detect_path(path, &data);
        Ok(Self {
            name,
            path: Some(path.to_path_buf()),
            data,
            kind,
            sha256: OnceLock::new(),
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
