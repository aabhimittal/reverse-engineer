//! Hashing and entropy helpers.

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Lower-case hex encoding.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

/// MD5 of `data` as hex.
pub fn md5_hex(data: &[u8]) -> String {
    hex(&Md5::digest(data))
}

/// SHA-1 of `data` as hex.
pub fn sha1_hex(data: &[u8]) -> String {
    hex(&Sha1::digest(data))
}

/// SHA-256 of `data` as hex.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// Shannon entropy in bits per byte (0.0 ..= 8.0).
///
/// Think of it as "how surprised are you by the next byte?". Plain text sits
/// around 4.5, machine code around 6, and compressed or encrypted data
/// approaches 8 because every byte value is roughly equally likely.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Entropy of consecutive blocks of `block` bytes. Returns `(offset, entropy)` pairs.
pub fn entropy_profile(data: &[u8], block: usize) -> Vec<(usize, f64)> {
    let block = block.max(16);
    data.chunks(block)
        .enumerate()
        .map(|(i, c)| (i * block, entropy(c)))
        .collect()
}

/// Render values in `0.0..=max` as a unicode sparkline (▁▂▃▄▅▆▇█).
pub fn sparkline(values: &[f64], max: f64) -> String {
    const BARS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    values
        .iter()
        .map(|v| {
            let idx = ((v / max).clamp(0.0, 1.0) * 7.0).round() as usize;
            BARS[idx]
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hashes() {
        assert_eq!(md5_hex(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(sha1_hex(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn entropy_bounds() {
        assert_eq!(entropy(&[]), 0.0);
        assert_eq!(entropy(&[7u8; 1000]), 0.0);
        let all: Vec<u8> = (0..=255u8).collect();
        assert!((entropy(&all) - 8.0).abs() < 1e-9);
        let two = [0u8, 1u8].repeat(50);
        assert!((entropy(&two) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn sparkline_maps_range() {
        assert_eq!(sparkline(&[0.0, 8.0], 8.0), "▁█");
    }
}
