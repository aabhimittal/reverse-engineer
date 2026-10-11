//! Minimal Base64 decoding (standard and URL-safe alphabets, padding optional).

/// Decode Base64 / Base64url. Whitespace is ignored. Returns `None` on invalid input.
pub fn decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn decodes() {
        assert_eq!(super::decode("aGVsbG8gd29ybGQ=").unwrap(), b"hello world");
        assert_eq!(super::decode("aGVsbG8gd29ybGQ").unwrap(), b"hello world");
        assert_eq!(super::decode("-_8").unwrap(), [0xfb, 0xff]);
        assert!(super::decode("a$b").is_none());
    }
}
