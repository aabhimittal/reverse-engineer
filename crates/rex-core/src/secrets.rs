//! Secret / credential detection shared by every rex domain (binaries, bundles, source trees).

use regex::Regex;
use serde::Serialize;
use std::sync::OnceLock;

/// A secret-pattern hit.
#[derive(Debug, Clone, Serialize)]
pub struct SecretHit {
    /// Pattern name.
    pub kind: &'static str,
    /// Matched value (unmasked; mask with [`mask`] before display).
    pub value: String,
    /// 1-based line.
    pub line: u32,
    /// True when the credential is never meant to be public.
    pub high: bool,
}

fn patterns() -> &'static Vec<(&'static str, Regex, bool)> {
    static P: OnceLock<Vec<(&'static str, Regex, bool)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            ("AWS access key id", Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(), true),
            ("Google API key", Regex::new(r"\bAIza[0-9A-Za-z\-_]{35}\b").unwrap(), false),
            ("GitHub token", Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b").unwrap(), true),
            ("Slack token", Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b").unwrap(), true),
            ("Slack webhook", Regex::new(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+").unwrap(), true),
            ("Stripe secret key", Regex::new(r"\b(?:sk|rk)_live_[0-9a-zA-Z]{20,}\b").unwrap(), true),
            ("Stripe publishable key", Regex::new(r"\bpk_live_[0-9a-zA-Z]{20,}\b").unwrap(), false),
            ("Twilio API key", Regex::new(r"\bSK[0-9a-f]{32}\b").unwrap(), true),
            ("SendGrid API key", Regex::new(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b").unwrap(), true),
            ("Mailgun API key", Regex::new(r"\bkey-[0-9a-f]{32}\b").unwrap(), true),
            ("Sentry DSN", Regex::new(r"https://[0-9a-f]{32}@[a-z0-9.\-]+/\d+").unwrap(), false),
            ("Mapbox token", Regex::new(r"\b(?:pk|sk)\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b").unwrap(), false),
            ("OpenAI API key", Regex::new(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b").unwrap(), true),
            ("Anthropic API key", Regex::new(r"\bsk-ant-[A-Za-z0-9_\-]{32,}\b").unwrap(), true),
            ("Private key", Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----").unwrap(), true),
            ("JWT", Regex::new(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b").unwrap(), false),
            (
                "Generic secret assignment",
                Regex::new(r#"(?i)["']?(api[_-]?key|api[_-]?secret|client[_-]?secret|secret[_-]?key|private[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=.]{12,})["']"#).unwrap(),
                false,
            ),
        ]
    })
}

fn line_of(src: &str, byte: usize) -> u32 {
    (src.as_bytes()[..byte.min(src.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1) as u32
}

/// Scan text for credentials. Generic `key = "value"` assignments are kept only
/// when the value looks random (entropy) and isn't an obvious placeholder.
pub fn scan(src: &str) -> Vec<SecretHit> {
    let mut out: Vec<SecretHit> = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for (kind, re, high) in patterns() {
        for m in re.captures_iter(src) {
            let whole = m.get(0).expect("match");
            let mut high = *high;
            let value = if *kind == "Generic secret assignment" {
                let name = m
                    .get(1)
                    .map(|x| x.as_str().to_ascii_lowercase())
                    .unwrap_or_default();
                let value = m.get(2).map(|x| x.as_str()).unwrap_or_default().to_string();
                let v = value.to_ascii_lowercase();
                if crate::hash::entropy(value.as_bytes()) < 3.3
                    || [
                        "placeholder",
                        "example",
                        "xxxx",
                        "your",
                        "changeme",
                        "dummy",
                        "test",
                    ]
                    .iter()
                    .any(|p| v.contains(p))
                {
                    continue;
                }
                // A browser "api key" may be intentionally public; a *secret* never is.
                high = name.contains("secret") || name.contains("pass") || name.contains("private");
                value
            } else {
                m.get(1).unwrap_or(whole).as_str().to_string()
            };
            if seen.insert(value.clone()) {
                out.push(SecretHit {
                    kind,
                    value,
                    line: line_of(src, whole.start()),
                    high,
                });
            }
        }
    }
    out
}

/// Mask the middle of a secret so reports don't re-leak it.
pub fn mask(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_and_grades() {
        let aws = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        let src = format!(
            "let a = \"{aws}\";\nconst client_secret = \"Zq8r3TfL0pWm2xYb7Nc4\";\npassword = \"changeme123456\""
        );
        let hits = scan(&src);
        assert!(
            hits.iter()
                .any(|h| h.kind == "AWS access key id" && h.line == 1 && h.high)
        );
        assert!(
            hits.iter()
                .any(|h| h.kind == "Generic secret assignment" && h.line == 2 && h.high)
        );
        assert!(!hits.iter().any(|h| h.value.contains("changeme")));
        assert_eq!(mask("abcdefghijklmnop"), "abcdef…mnop (16 chars)");
    }
}
