//! String extraction and classification.
//!
//! Strings are the "fingerprints left on the glass": error messages, URLs,
//! file paths, format strings and registry keys often tell you what a binary
//! does before you read a single instruction.

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// Text encoding of an extracted string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Encoding {
    /// 7-bit ASCII (also covers UTF-8 subsets).
    Ascii,
    /// UTF-16 little-endian (Windows "wide" strings).
    Utf16Le,
}

/// What a string looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Category {
    /// http(s)/ftp URL.
    Url,
    /// IPv4 address (optionally with port).
    Ip,
    /// Email address.
    Email,
    /// Domain name with a common TLD.
    Domain,
    /// Windows registry key.
    Registry,
    /// Filesystem path.
    Path,
    /// Shell / command interpreter invocation.
    Command,
    /// Cryptocurrency wallet address.
    Wallet,
    /// Embedded secret / credential pattern.
    Secret,
    /// Base64 blob.
    Base64,
    /// printf-style format string.
    Format,
    /// User-agent string.
    UserAgent,
    /// Anything else.
    Other,
}

impl Category {
    /// Label.
    pub fn as_str(self) -> &'static str {
        match self {
            Category::Url => "url",
            Category::Ip => "ip",
            Category::Email => "email",
            Category::Domain => "domain",
            Category::Registry => "registry",
            Category::Path => "path",
            Category::Command => "command",
            Category::Wallet => "wallet",
            Category::Secret => "secret",
            Category::Base64 => "base64",
            Category::Format => "format",
            Category::UserAgent => "user-agent",
            Category::Other => "other",
        }
    }
}

/// One extracted string.
#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    /// File offset.
    pub offset: u64,
    /// Encoding.
    pub encoding: Encoding,
    /// Decoded text.
    pub text: String,
    /// Classification.
    pub category: Category,
}

fn printable(b: u8) -> bool {
    (0x20..0x7f).contains(&b) || b == b'\t'
}

/// Extract ASCII and UTF-16LE strings of at least `min_len` characters.
pub fn extract(data: &[u8], min_len: usize) -> Vec<FoundString> {
    let min_len = min_len.max(3);
    let mut out = Vec::new();

    // ASCII runs.
    let mut start = None;
    for (i, &b) in data.iter().enumerate() {
        if printable(b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take() {
            if i - s >= min_len {
                push(&mut out, s, Encoding::Ascii, &data[s..i]);
            }
        }
    }
    if let Some(s) = start {
        if data.len() - s >= min_len {
            push(&mut out, s, Encoding::Ascii, &data[s..]);
        }
    }

    // UTF-16LE runs: printable ASCII byte followed by 0x00, at either alignment.
    for align in 0..2 {
        let mut i = align;
        let mut run_start = None;
        let mut chars = Vec::new();
        while i + 1 < data.len() {
            let (lo, hi) = (data[i], data[i + 1]);
            if hi == 0 && printable(lo) {
                run_start.get_or_insert(i);
                chars.push(lo);
            } else {
                if let Some(s) = run_start.take() {
                    if chars.len() >= min_len {
                        push(&mut out, s, Encoding::Utf16Le, &chars);
                    }
                }
                chars.clear();
            }
            i += 2;
        }
        if let Some(s) = run_start {
            if chars.len() >= min_len {
                push(&mut out, s, Encoding::Utf16Le, &chars);
            }
        }
    }
    out.sort_by_key(|s| s.offset);
    out
}

fn push(out: &mut Vec<FoundString>, offset: usize, encoding: Encoding, bytes: &[u8]) {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let category = classify(&text);
    out.push(FoundString {
        offset: offset as u64,
        encoding,
        text,
        category,
    });
}

struct Patterns {
    url: Regex,
    ip: Regex,
    email: Regex,
    domain: Regex,
    registry: Regex,
    win_path: Regex,
    unix_path: Regex,
    command: Regex,
    wallet: Regex,
    secret: Regex,
    base64: Regex,
    format: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        url: Regex::new(r"(?i)\b(?:https?|ftp|wss?)://[a-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+").unwrap(),
        ip: Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?::\d{1,5})?\b").unwrap(),
        email: Regex::new(r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b").unwrap(),
        domain: Regex::new(r"(?i)^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|onion|co|me|de|uk|tk|cc|su|pw|app|dev|cloud)$").unwrap(),
        registry: Regex::new(r"(?i)\b(?:HKEY_[A-Z_]+|HK(?:LM|CU|CR|U|CC))\\|(?:^|\\)(?:Software|SYSTEM)\\(?:Microsoft|CurrentControlSet|Classes|Policies|Wow6432Node)\\").unwrap(),
        win_path: Regex::new(r"(?i)\b[a-z]:\\[^\x00-\x1f]+|%(?:appdata|temp|programdata|systemroot|userprofile|localappdata)%").unwrap(),
        unix_path: Regex::new(r"^(?:/(?:etc|bin|sbin|usr|var|tmp|dev|proc|home|root|opt|lib|system|data|Library|Users|Applications)\b)[\w./\-]*$").unwrap(),
        command: Regex::new(r"(?i)\b(?:cmd(?:\.exe)?\s+/[ck]|powershell(?:\.exe)?\s+-|/bin/(?:ba|z|da)?sh\b|wget\s+https?|curl\s+-|chmod\s+[0-7+]|schtasks|vssadmin|bcdedit|wevtutil|reg(?:\.exe)?\s+add|net\s+user|rundll32|regsvr32|mshta|certutil\s+-)").unwrap(),
        wallet: Regex::new(r"^(?:(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}|0x[a-fA-F0-9]{40}|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})$").unwrap(),
        secret: Regex::new(r"(?:AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{35}|gh[pousr]_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[0-9a-zA-Z]{24,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)").unwrap(),
        base64: Regex::new(r"^(?:[A-Za-z0-9+/]{4}){10,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$").unwrap(),
        format: Regex::new(r"%[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|z|j|t|L)?[diouxXeEfFgGsScpn]").unwrap(),
    })
}

/// Classify a string; the first matching (most specific) category wins.
pub fn classify(s: &str) -> Category {
    let p = patterns();
    let t = s.trim();
    if p.secret.is_match(t) {
        Category::Secret
    } else if p.url.is_match(t) {
        Category::Url
    } else if t.contains("Mozilla/") || t.starts_with("User-Agent:") {
        Category::UserAgent
    } else if p.registry.is_match(t) {
        Category::Registry
    } else if p.command.is_match(t) {
        Category::Command
    } else if p.email.is_match(t) {
        Category::Email
    } else if p.ip.is_match(t) && !looks_like_version(t) {
        Category::Ip
    } else if p.wallet.is_match(t) {
        Category::Wallet
    } else if p.win_path.is_match(t) || p.unix_path.is_match(t) {
        Category::Path
    } else if p.domain.is_match(t) {
        Category::Domain
    } else if t.len() >= 40 && p.base64.is_match(t) && t.chars().any(|c| c.is_ascii_digit()) {
        Category::Base64
    } else if p.format.is_match(t) {
        Category::Format
    } else {
        Category::Other
    }
}

fn looks_like_version(s: &str) -> bool {
    // "1.2.3.4" inside "GCC 1.2.3.4" or "v10.0.0.1" style strings are versions, not hosts.
    let lower = s.to_ascii_lowercase();
    ["version", "gcc", "clang", "glibc", "v1.", "v2.", "build"]
        .iter()
        .any(|k| lower.contains(k))
}

/// Strings that are worth surfacing to a human (non-`Other`).
pub fn interesting(all: &[FoundString]) -> impl Iterator<Item = &FoundString> {
    all.iter()
        .filter(|s| !matches!(s.category, Category::Other | Category::Format))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_ascii_and_utf16() {
        let mut d = b"\x00\x01hello world\x00\x02".to_vec();
        d.extend("wide!".encode_utf16().flat_map(|c| c.to_le_bytes()));
        d.extend([0, 0]);
        let s = extract(&d, 4);
        assert!(
            s.iter()
                .any(|x| x.text == "hello world" && x.encoding == Encoding::Ascii && x.offset == 2)
        );
        assert!(
            s.iter()
                .any(|x| x.text == "wide!" && x.encoding == Encoding::Utf16Le)
        );
    }

    #[test]
    fn classifies() {
        assert_eq!(classify("https://evil.example.com/gate.php"), Category::Url);
        assert_eq!(classify("192.168.10.5:4444"), Category::Ip);
        assert_eq!(classify("GCC: (GNU) 13.2.0.1 version"), Category::Other);
        assert_eq!(
            classify(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            Category::Registry
        );
        assert_eq!(classify(r"HKCU\Software\x"), Category::Registry);
        assert_eq!(classify("cmd.exe /c del %s"), Category::Command);
        assert_eq!(classify("/etc/passwd"), Category::Path);
        assert_eq!(classify(r"C:\Windows\System32\drivers"), Category::Path);
        // Built at runtime so the repository never contains a contiguous key-shaped literal.
        assert_eq!(
            classify(&format!("AKIA{}", "ABCDEFGHIJKLMNOP")),
            Category::Secret
        );
        assert_eq!(classify("admin@example.org"), Category::Email);
        assert_eq!(
            classify("Mozilla/5.0 (Windows NT 10.0)"),
            Category::UserAgent
        );
        assert_eq!(classify("Usage: %s <file>\n"), Category::Format);
        assert_eq!(classify("c2.badguys.xyz"), Category::Domain);
        assert_eq!(classify("just words here"), Category::Other);
    }
}
