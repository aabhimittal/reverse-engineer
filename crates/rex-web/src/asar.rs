//! Electron ASAR archives.
//!
//! An `.asar` is a tar-like container with no compression: a small header that says where every
//! file lives, followed by the files back to back. Electron apps ship their entire JavaScript
//! application inside one, which makes it the single most valuable file when reversing a desktop
//! app built on web technology.
//!
//! ```text
//! offset 0   u32 = 4                       (size of the next field, from Chromium's Pickle format)
//! offset 4   u32 = N                       (size of the header "pickle")
//! offset 8   u32 = N - 4                   (pickle payload size)
//! offset 12  u32 = L                       (JSON length)
//! offset 16  L bytes of JSON, zero padded to 4
//! offset 8+N file data; every entry stores a decimal-string `offset` relative to here
//! ```
//!
//! Every length is attacker-controlled, so all reads are bounds-checked and the JSON walk is
//! depth- and count-limited.

use crate::js::safe_relative;
use rex_core::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::path::Path;

const MAX_ENTRIES: usize = 500_000;
const MAX_DEPTH: usize = 64;
const MAX_HEADER: usize = 128 << 20;

/// One file or symlink inside the archive.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// `/`-separated path inside the archive.
    pub path: String,
    /// Size in bytes.
    pub size: u64,
    /// Offset from the end of the header.
    pub offset: u64,
    /// Stored outside the archive, in `<name>.asar.unpacked/` (native addons usually are).
    pub unpacked: bool,
    /// Executable bit.
    pub executable: bool,
    /// Symlink target, when this entry is a link.
    pub link: Option<String>,
    /// The header carries an integrity hash for this file.
    pub integrity: bool,
}

/// A parsed archive borrowing the input bytes.
pub struct Archive<'a> {
    data: &'a [u8],
    base: usize,
    /// Files and links, sorted by path.
    pub entries: Vec<Entry>,
    /// Directory count.
    pub dirs: usize,
    /// Header size in bytes (JSON plus framing).
    pub header_size: usize,
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    let b = d.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Cheap structural test used by format detection (ASAR has no magic number).
pub fn looks_like(data: &[u8]) -> bool {
    header_json(data).is_some_and(|j| j.starts_with(br#"{"files""#))
}

fn header_json(data: &[u8]) -> Option<&[u8]> {
    if u32_at(data, 0)? != 4 {
        return None;
    }
    let hsize = u32_at(data, 4)? as usize;
    let payload = u32_at(data, 8)? as usize;
    let jlen = u32_at(data, 12)? as usize;
    if !(8..=MAX_HEADER).contains(&hsize)
        || payload != hsize - 4
        || jlen > payload.saturating_sub(4)
    {
        return None;
    }
    data.get(16..16usize.checked_add(jlen)?)
}

/// Parse an archive. Never panics; malformed input is an error.
pub fn parse(data: &[u8]) -> Result<Archive<'_>> {
    let json = header_json(data).ok_or_else(|| Error::parse("ASAR", "not an ASAR header"))?;
    let hsize = u32_at(data, 4).unwrap_or(0) as usize;
    let base = 8 + hsize;
    let root: Value = serde_json::from_slice(json)
        .map_err(|e| Error::parse("ASAR", format!("header JSON: {e}")))?;
    let files = root
        .get("files")
        .and_then(Value::as_object)
        .ok_or_else(|| Error::parse("ASAR", "header has no \"files\" object"))?;
    let mut a = Archive {
        data,
        base,
        entries: Vec::new(),
        dirs: 1,
        header_size: hsize,
    };
    walk(files, "", 0, &mut a)?;
    a.entries.sort_by(|x, y| x.path.cmp(&y.path));
    Ok(a)
}

fn walk(
    files: &serde_json::Map<String, Value>,
    prefix: &str,
    depth: usize,
    a: &mut Archive<'_>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::parse("ASAR", "directory nesting too deep"));
    }
    for (name, node) in files {
        if a.entries.len() >= MAX_ENTRIES {
            return Err(Error::parse("ASAR", "too many entries"));
        }
        let path = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if let Some(dir) = node.get("files").and_then(Value::as_object) {
            a.dirs += 1;
            walk(dir, &path, depth + 1, a)?;
            continue;
        }
        let num = |k: &str| -> u64 {
            match node.get(k) {
                Some(Value::String(s)) => s.parse().unwrap_or(0),
                Some(v) => v.as_u64().unwrap_or(0),
                None => 0,
            }
        };
        a.entries.push(Entry {
            path,
            size: num("size"),
            offset: num("offset"),
            unpacked: node.get("unpacked").and_then(Value::as_bool) == Some(true),
            executable: node.get("executable").and_then(Value::as_bool) == Some(true),
            link: node.get("link").and_then(Value::as_str).map(str::to_string),
            integrity: node.get("integrity").is_some_and(Value::is_object),
        });
    }
    Ok(())
}

impl<'a> Archive<'a> {
    /// The bytes of a packed file, or `None` when unpacked, a link, or out of bounds.
    pub fn read(&self, e: &Entry) -> Option<&'a [u8]> {
        if e.unpacked || e.link.is_some() {
            return None;
        }
        let start = self.base.checked_add(usize::try_from(e.offset).ok()?)?;
        let end = start.checked_add(usize::try_from(e.size).ok()?)?;
        self.data.get(start..end)
    }

    /// Look up an entry by exact path.
    pub fn find(&self, path: &str) -> Option<&Entry> {
        self.entries.iter().find(|e| e.path == path)
    }

    /// Write every packed file under `dir`, refusing paths that would escape it.
    /// Returns `(written, skipped)`; skipped covers links, unpacked and unsafe entries.
    pub fn extract(&self, dir: &Path) -> std::io::Result<(usize, usize)> {
        let (mut written, mut skipped) = (0, 0);
        for e in &self.entries {
            let (Some(rel), Some(bytes)) = (safe_relative(&e.path), self.read(e)) else {
                skipped += 1;
                continue;
            };
            let dest = dir.join(rel);
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&dest, bytes)?;
            written += 1;
        }
        Ok((written, skipped))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Build an archive from `(path, contents)` pairs. Paths with `/` create nested directories.
    pub fn build(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut root = serde_json::Map::new();
        let mut blob = Vec::new();
        for (path, content) in files {
            let mut cur = &mut root;
            let parts: Vec<&str> = path.split('/').collect();
            for dir in &parts[..parts.len() - 1] {
                let slot = cur
                    .entry(dir.to_string())
                    .or_insert_with(|| serde_json::json!({ "files": {} }));
                cur = slot["files"].as_object_mut().unwrap();
            }
            cur.insert(
                parts[parts.len() - 1].to_string(),
                serde_json::json!({ "size": content.len(), "offset": blob.len().to_string() }),
            );
            blob.extend_from_slice(content);
        }
        let json = serde_json::to_vec(&serde_json::json!({ "files": root })).unwrap();
        let padded = json.len().div_ceil(4) * 4;
        let mut out = Vec::new();
        out.extend(4u32.to_le_bytes());
        out.extend(((padded + 8) as u32).to_le_bytes());
        out.extend(((padded + 4) as u32).to_le_bytes());
        out.extend((json.len() as u32).to_le_bytes());
        out.extend(&json);
        out.resize(16 + padded, 0);
        out.extend(blob);
        out
    }

    #[test]
    fn parses_and_reads_back() {
        let d = build(&[
            ("package.json", br#"{"main":"main.js"}"#),
            ("src/a.js", b"console.log(1)"),
            ("src/deep/b.js", b"x"),
        ]);
        assert!(looks_like(&d));
        assert_eq!(
            rex_core::detect_bytes(&d, None),
            rex_core::ArtifactKind::Asar
        );
        let a = parse(&d).unwrap();
        assert_eq!(a.entries.len(), 3);
        assert_eq!(a.dirs, 3);
        let e = a.find("src/a.js").unwrap();
        assert_eq!(a.read(e).unwrap(), b"console.log(1)");
        assert_eq!(a.read(a.find("src/deep/b.js").unwrap()).unwrap(), b"x");
    }

    #[test]
    fn extraction_cannot_escape() {
        let d = build(&[("../../evil.js", b"x"), ("ok/fine.js", b"y")]);
        let a = parse(&d).unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("out");
        std::fs::create_dir_all(&out).unwrap();
        let (written, _) = a.extract(&out).unwrap();
        assert_eq!(written, 2);
        assert!(!tmp.path().join("evil.js").exists());
        assert!(out.join("ok/fine.js").exists());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let good = build(&[("a.js", b"hello"), ("b/c.js", b"world")]);
        for n in 0..good.len() {
            let _ = parse(&good[..n]);
        }
        let mut seed = 0x2545f491u32;
        for _ in 0..4000 {
            let mut d = good.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                let i = (seed >> 8) as usize % d.len();
                d[i] ^= (seed & 0xff) as u8;
            }
            if let Ok(a) = parse(&d) {
                for e in a.entries.clone() {
                    let _ = a.read(&e);
                }
            }
        }
        assert!(parse(b"").is_err());
        assert!(!looks_like(b"\x04\0\0\0\xff\xff\xff\xff"));
    }

    #[test]
    fn out_of_range_offsets_read_as_none() {
        let mut d = build(&[("a.js", b"hello")]);
        d.truncate(d.len() - 3);
        let a = parse(&d).unwrap();
        assert!(a.read(&a.entries[0]).is_none());
    }
}
