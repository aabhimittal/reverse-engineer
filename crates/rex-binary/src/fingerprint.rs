//! Hashes used to identify and cluster samples.
//!
//! * Cryptographic hashes (MD5/SHA-1/SHA-256) identify *exact* files.
//! * **imphash** hashes the import table: two builds of the same malware
//!   family often share it even when every byte of code differs.
//! * **TLSH** is a *fuzzy* hash: similar files get similar digests, so you can
//!   measure distance between variants (lower = more alike).

use crate::model::{BinFormat, Binary};
use rex_core::hash;
use serde::Serialize;

/// Fingerprints of a file.
#[derive(Debug, Clone, Serialize)]
pub struct Fingerprints {
    /// MD5.
    pub md5: String,
    /// SHA-1.
    pub sha1: String,
    /// SHA-256.
    pub sha256: String,
    /// TLSH (None for inputs < 50 bytes or with too little variation).
    pub tlsh: Option<String>,
    /// PE import hash (Mandiant / pefile compatible).
    pub imphash: Option<String>,
    /// MD5 of sorted, lower-cased import names (any format).
    pub import_set_md5: Option<String>,
}

/// TLSH digest (`T1…`).
pub fn tlsh(data: &[u8]) -> Option<String> {
    let mut b = tlsh2::TlshDefaultBuilder::new();
    b.update(data);
    b.build()
        .map(|t| String::from_utf8_lossy(&t.hash()).into_owned())
}

/// TLSH distance between two digests computed from data (0 = identical).
pub fn tlsh_distance(a: &[u8], b: &[u8]) -> Option<i32> {
    let mut x = tlsh2::TlshDefaultBuilder::new();
    x.update(a);
    let mut y = tlsh2::TlshDefaultBuilder::new();
    y.update(b);
    Some(x.build()?.diff(&y.build()?, true))
}

/// pefile-compatible imphash.
pub fn imphash(bin: &Binary) -> Option<String> {
    if bin.format != BinFormat::Pe || bin.imports.is_empty() {
        return None;
    }
    let parts: Vec<String> = bin
        .imports
        .iter()
        .map(|i| {
            let lib = i.library.as_deref().unwrap_or("").to_ascii_lowercase();
            let lib = ["dll", "ocx", "sys"]
                .iter()
                .find_map(|ext| lib.strip_suffix(&format!(".{ext}")))
                .unwrap_or(&lib)
                .to_string();
            let func = match i.name.strip_prefix("ORDINAL ") {
                Some(n) => format!("ord{n}"),
                None => i.name.to_ascii_lowercase(),
            };
            format!("{lib}.{func}")
        })
        .collect();
    Some(hash::md5_hex(parts.join(",").as_bytes()))
}

/// Compute all fingerprints.
pub fn compute(data: &[u8], bin: Option<&Binary>) -> Fingerprints {
    let import_set_md5 = bin.filter(|b| !b.imports.is_empty()).map(|b| {
        let mut v: Vec<String> = b
            .imports
            .iter()
            .map(|i| i.name.to_ascii_lowercase())
            .collect();
        v.sort();
        v.dedup();
        hash::md5_hex(v.join(",").as_bytes())
    });
    Fingerprints {
        md5: hash::md5_hex(data),
        sha1: hash::sha1_hex(data),
        sha256: hash::sha256_hex(data),
        tlsh: tlsh(data),
        imphash: bin.and_then(imphash),
        import_set_md5,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsh_similarity() {
        let a: Vec<u8> = (0..4096u32)
            .map(|i| (i * 7 % 251) as u8 ^ (i / 13) as u8)
            .collect();
        let mut b = a.clone();
        b[100] ^= 0xff;
        b[2000] ^= 0x55;
        let c: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
            .collect();
        assert!(tlsh(&a).unwrap().starts_with("T1"));
        let near = tlsh_distance(&a, &b).unwrap();
        let far = tlsh_distance(&a, &c).unwrap();
        assert!(near < far, "near={near} far={far}");
        assert!(tlsh(b"short").is_none());
    }
}
