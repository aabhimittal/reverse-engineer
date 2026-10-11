//! Security observations from captured HTTP traffic.
//!
//! These are *passive* checks over what the capture already contains. Nothing
//! is sent to the target.

use crate::har::{Har, split_url};
use rex_core::{Finding, Severity};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// A decoded (not verified) JSON Web Token.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Jwt {
    /// Header JSON.
    pub header: Value,
    /// Claims JSON.
    pub claims: Value,
}

/// Decode a JWT's header and payload. Signatures are **not** verified.
pub fn decode_jwt(token: &str) -> Option<Jwt> {
    let token = token
        .trim()
        .trim_start_matches("Bearer ")
        .trim_start_matches("bearer ");
    let mut parts = token.split('.');
    let (h, p) = (parts.next()?, parts.next()?);
    parts.next()?;
    if !h.starts_with("eyJ") {
        return None;
    }
    let header = serde_json::from_slice(&crate::b64::decode(h)?).ok()?;
    let claims = serde_json::from_slice(&crate::b64::decode(p)?).ok()?;
    Some(Jwt { header, claims })
}

/// Partially mask a credential for display.
pub fn mask(s: &str) -> String {
    rex_binary::analyzers::redact(s)
}

/// Run all traffic checks.
pub fn audit(har: &Har) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut cleartext: BTreeSet<String> = BTreeSet::new();
    let mut creds: BTreeSet<String> = BTreeSet::new();
    let mut jwts: BTreeMap<String, Jwt> = BTreeMap::new();
    let mut missing_hdr: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let mut weak_cookies: BTreeSet<String> = BTreeSet::new();
    let mut cors: BTreeSet<String> = BTreeSet::new();
    let mut disclosure: BTreeSet<String> = BTreeSet::new();
    let mut pii_in_url: BTreeSet<String> = BTreeSet::new();
    let mut errors: BTreeSet<String> = BTreeSet::new();

    for e in &har.log.entries {
        let Some((scheme, host, path, query)) = split_url(&e.request.url) else {
            continue;
        };
        let is_local =
            host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]");
        let has_auth =
            e.request.header("authorization").is_some() || e.request.header("cookie").is_some();
        if scheme == "http" && !is_local && (has_auth || e.request.post_data.is_some()) {
            cleartext.insert(format!("{} {}{}", e.request.method, host, path));
        }
        if let Some(a) = e.request.header("authorization") {
            creds.insert(format!("Authorization: {}", mask(a)));
            if let Some(j) = decode_jwt(a) {
                jwts.entry(a.to_string()).or_insert(j);
            }
        }
        for h in &e.request.headers {
            let n = h.name.to_ascii_lowercase();
            if n.contains("api-key") || n == "x-api-key" || n.contains("token") {
                creds.insert(format!("{}: {}", h.name, mask(&h.value)));
                if let Some(j) = decode_jwt(&h.value) {
                    jwts.entry(h.value.clone()).or_insert(j);
                }
            }
        }
        for q in &e.request.query_string {
            let n = q.name.to_ascii_lowercase();
            if matches!(
                n.as_str(),
                "api_key"
                    | "apikey"
                    | "key"
                    | "access_token"
                    | "token"
                    | "password"
                    | "secret"
                    | "client_secret"
                    | "sig"
                    | "signature"
            ) {
                creds.insert(format!(
                    "?{}={} (credential in URL, ends up in logs)",
                    q.name,
                    mask(&q.value)
                ));
            }
            if q.value.contains('@') && q.value.contains('.') {
                pii_in_url.insert(format!("{host}{path}?{}=…", q.name));
            }
        }
        if let Some(c) = e.request.header("cookie") {
            for kv in c.split(';') {
                let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                let kl = k.trim().to_ascii_lowercase();
                if ["sess", "auth", "token", "sid", "jwt"]
                    .iter()
                    .any(|x| kl.contains(x))
                {
                    creds.insert(format!("Cookie {}={}", k.trim(), mask(v.trim())));
                }
            }
        }
        if let Some(body) = e.request.post_data.as_ref().and_then(|p| p.text.as_deref()) {
            if let Ok(Value::Object(m)) = serde_json::from_str::<Value>(body) {
                for (k, v) in &m {
                    let kl = k.to_ascii_lowercase();
                    if kl.contains("password")
                        || kl.contains("secret")
                        || kl == "pin"
                        || kl == "otp"
                    {
                        creds.insert(format!(
                            "{} body field '{k}': {}",
                            path,
                            mask(v.as_str().unwrap_or(&v.to_string()))
                        ));
                    }
                }
            }
        }
        if query.to_ascii_lowercase().contains("password=") {
            creds.insert(format!("password in query string: {host}{path}"));
        }

        // Response-side checks.
        let r = &e.response;
        let mime = r.content.mime_type.to_ascii_lowercase();
        if mime.contains("html") && scheme == "https" {
            for (hdr, label) in [
                ("strict-transport-security", "Strict-Transport-Security"),
                ("content-security-policy", "Content-Security-Policy"),
                ("x-content-type-options", "X-Content-Type-Options"),
            ] {
                if r.header(hdr).is_none() {
                    missing_hdr.entry(label).or_default().insert(host.clone());
                }
            }
        }
        for c in r.headers_named("set-cookie") {
            let lower = c.to_ascii_lowercase();
            let name = c.split('=').next().unwrap_or("").trim().to_string();
            let mut missing = Vec::new();
            if scheme == "https" && !lower.contains("secure") {
                missing.push("Secure");
            }
            if !lower.contains("httponly") {
                missing.push("HttpOnly");
            }
            if !lower.contains("samesite") {
                missing.push("SameSite");
            }
            let sensitive = ["sess", "auth", "token", "sid", "jwt"]
                .iter()
                .any(|k| name.to_ascii_lowercase().contains(k));
            if sensitive && !missing.is_empty() {
                weak_cookies.insert(format!("{host}: {name} missing {}", missing.join(", ")));
            }
        }
        if let Some(acao) = r.header("access-control-allow-origin") {
            let creds_ok = r
                .header("access-control-allow-credentials")
                .is_some_and(|v| v.eq_ignore_ascii_case("true"));
            let origin = e.request.header("origin").unwrap_or("");
            if acao == "*" && creds_ok {
                cors.insert(format!("{host}: ACAO * with credentials"));
            } else if creds_ok && !origin.is_empty() && acao == origin && !origin.contains(&host) {
                cors.insert(format!(
                    "{host}: reflects Origin {origin} with credentials (verify allow-list)"
                ));
            }
        }
        for h in [
            "server",
            "x-powered-by",
            "x-aspnet-version",
            "x-aspnetmvc-version",
        ] {
            if let Some(v) = r.header(h) {
                if v.chars().any(|c| c.is_ascii_digit()) {
                    disclosure.insert(format!("{host}: {h}: {v}"));
                }
            }
        }
        if r.status >= 500 {
            if let Some(body) = r.body() {
                let b = body.to_ascii_lowercase();
                if [
                    "traceback (most recent call last)",
                    "stack trace",
                    "at java.",
                    "exception in thread",
                    "sqlstate",
                    "ora-0",
                    "syntax error at or near",
                ]
                .iter()
                .any(|k| b.contains(k))
                {
                    errors.insert(format!(
                        "{} {}{} → {}",
                        e.request.method, host, path, r.status
                    ));
                }
            }
        }
    }

    if !cleartext.is_empty() {
        out.push(
            Finding::new("WEB-CLEARTEXT", Severity::High, "transport", "Credentials or form data sent over plain HTTP")
                .describe("Anyone on the network path can read or modify these requests. Enforce HTTPS + HSTS.")
                .evidence_all(cleartext.into_iter().take(20)),
        );
    }
    if !creds.is_empty() {
        out.push(
            Finding::new("WEB-CAPTURE-CREDENTIALS", Severity::Medium, "secret", "Capture contains live credentials")
                .describe("HAR files include auth headers and cookies. Sanitise before sharing (values are masked here).")
                .evidence_all(creds.into_iter().take(20)),
        );
    }
    for (raw, j) in &jwts {
        let alg = j
            .header
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or("?")
            .to_string();
        let mut ev = vec![
            format!("header: {}", j.header),
            format!("claims: {}", summarize_claims(&j.claims)),
        ];
        ev.push(format!("token: {}", mask(raw)));
        if alg.eq_ignore_ascii_case("none") {
            out.push(
                Finding::new(
                    "WEB-JWT-ALG-NONE",
                    Severity::Critical,
                    "auth",
                    "JWT uses alg=none (unsigned)",
                )
                .describe("Servers that accept unsigned tokens let anyone forge identities.")
                .evidence_all(ev),
            );
            continue;
        }
        if let (Some(iat), Some(exp)) = (
            j.claims.get("iat").and_then(Value::as_i64),
            j.claims.get("exp").and_then(Value::as_i64),
        ) {
            let days = (exp - iat) / 86_400;
            if days > 30 {
                out.push(
                    Finding::new(
                        "WEB-JWT-LONG-LIVED",
                        Severity::Low,
                        "auth",
                        format!("JWT lifetime is {days} days"),
                    )
                    .describe("Long-lived bearer tokens widen the window for replay if leaked.")
                    .evidence_all(ev.clone()),
                );
            }
        } else if j.claims.get("exp").is_none() {
            out.push(
                Finding::new(
                    "WEB-JWT-NO-EXP",
                    Severity::Medium,
                    "auth",
                    "JWT has no expiry (exp) claim",
                )
                .evidence_all(ev.clone()),
            );
        }
        out.push(
            Finding::new("WEB-JWT", Severity::Info, "auth", format!("JWT observed ({alg})"))
                .describe("Decoded without verification. Review claims for roles/scopes that could be tampered with if validation is weak.")
                .evidence_all(ev),
        );
    }
    for (hdr, hosts) in missing_hdr {
        out.push(
            Finding::new(
                format!("WEB-MISSING-{}", hdr.to_ascii_uppercase().replace('-', "_")),
                Severity::Low,
                "headers",
                format!("HTML responses without {hdr}"),
            )
            .evidence_all(hosts),
        );
    }
    if !weak_cookies.is_empty() {
        out.push(
            Finding::new(
                "WEB-COOKIE-FLAGS",
                Severity::Low,
                "cookies",
                "Session cookies missing security attributes",
            )
            .evidence_all(weak_cookies),
        );
    }
    if !cors.is_empty() {
        out.push(
            Finding::new(
                "WEB-CORS",
                Severity::Medium,
                "cors",
                "Permissive CORS with credentials",
            )
            .describe("Other origins may be able to read authenticated responses.")
            .evidence_all(cors),
        );
    }
    if !disclosure.is_empty() {
        out.push(
            Finding::new(
                "WEB-VERSION-DISCLOSURE",
                Severity::Info,
                "headers",
                "Server software versions disclosed",
            )
            .evidence_all(disclosure),
        );
    }
    if !pii_in_url.is_empty() {
        out.push(
            Finding::new(
                "WEB-PII-IN-URL",
                Severity::Low,
                "privacy",
                "Email addresses in URLs",
            )
            .evidence_all(pii_in_url),
        );
    }
    if !errors.is_empty() {
        out.push(
            Finding::new(
                "WEB-VERBOSE-ERRORS",
                Severity::Medium,
                "errors",
                "Server errors leak stack traces or SQL errors",
            )
            .evidence_all(errors),
        );
    }
    out
}

fn summarize_claims(c: &Value) -> String {
    match c.as_object() {
        Some(m) => m
            .iter()
            .take(12)
            .map(|(k, v)| {
                let s = v.to_string();
                let s = if s.chars().count() > 40 {
                    format!("{}…", s.chars().take(40).collect::<String>())
                } else {
                    s
                };
                format!("{k}={s}")
            })
            .collect::<Vec<_>>()
            .join(", "),
        None => c.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_jwt() {
        // {"alg":"none","typ":"JWT"}.{"sub":"42","role":"admin"}.
        let t = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiJ9.";
        let j = decode_jwt(&format!("Bearer {t}")).unwrap();
        assert_eq!(j.header["alg"], "none");
        assert_eq!(j.claims["role"], "admin");
        assert!(decode_jwt("not.a.jwt").is_none());
    }
}
