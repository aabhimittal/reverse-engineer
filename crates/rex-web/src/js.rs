//! JavaScript bundle analysis and source-map unpacking.
//!
//! A production bundle is a city map with the street names removed:
//! minification renames every variable, but *string literals survive*. API
//! paths, hostnames, feature flags and, all too often, keys are still in
//! plain text. And if the site ships a source map, you get the original street
//! names back: the full, unminified source tree.

use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

/// A secret-pattern hit.
#[derive(Debug, Clone, Serialize)]
pub struct SecretHit {
    /// Pattern name.
    pub kind: &'static str,
    /// Matched text (unmasked; callers mask before display).
    pub value: String,
    /// 1-based line.
    pub line: u32,
    /// Severity hint.
    pub high: bool,
}

/// Result of analysing a bundle.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JsReport {
    /// Absolute URLs.
    pub urls: BTreeSet<String>,
    /// API-looking paths in string literals.
    pub paths: BTreeSet<String>,
    /// HTTP calls: (method, target).
    pub calls: BTreeSet<(String, String)>,
    /// GraphQL operation names.
    pub graphql: BTreeSet<String>,
    /// Secrets.
    pub secrets: Vec<SecretHit>,
    /// Frameworks / bundlers detected.
    pub frameworks: BTreeSet<&'static str>,
    /// Dangerous DOM sinks: (sink, count).
    pub sinks: Vec<(&'static str, usize)>,
    /// `process.env.X` / `import.meta.env.X` names.
    pub env_vars: BTreeSet<String>,
    /// Internal / non-production hosts referenced.
    pub internal_hosts: BTreeSet<String>,
    /// `sourceMappingURL` value, if present.
    pub source_map_url: Option<String>,
    /// Lines / bytes.
    pub lines: usize,
}

struct Pats {
    url: Regex,
    path: Regex,
    call: Regex,
    gql: Regex,
    env: Regex,
    smap: Regex,
    method: Regex,
    secrets: Vec<(&'static str, Regex, bool)>,
}

fn pats() -> &'static Pats {
    static P: OnceLock<Pats> = OnceLock::new();
    P.get_or_init(|| Pats {
        url: Regex::new(r#"(?i)\b(?:https?|wss?)://[a-z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>\\)\]{}]*)?"#).unwrap(),
        path: Regex::new(r#"["'`](/(?:api|v\d+|graphql|gql|rest|auth|oauth2?|admin|internal|private|user|users|account|accounts|login|logout|session|sessions|token|upload|download|search|payments?|checkout|orders?|ws|socket\.io)(?:/[A-Za-z0-9_\-.{}:$]*)*)/?(?:\?[^"'`]*)?["'`]"#).unwrap(),
        call: Regex::new(r#"(?:\bfetch|\baxios(?:\.(get|post|put|patch|delete|head))?|\$\.(get|post|ajax)|\.open)\(\s*(?:["'](GET|POST|PUT|PATCH|DELETE)["']\s*,\s*)?[`"']([^`"']{1,300})[`"']"#).unwrap(),
        gql: Regex::new(r"\b(query|mutation|subscription)\s+([A-Z][A-Za-z0-9_]{2,})\s*[({]").unwrap(),
        env: Regex::new(r"\b(?:process\.env|import\.meta\.env)\.([A-Z][A-Z0-9_]{2,})").unwrap(),
        smap: Regex::new(r"[#@]\s*sourceMappingURL=(\S+)").unwrap(),
        method: Regex::new(r#"(?i)\bmethod\s*:\s*["'`](get|post|put|patch|delete|head)["'`]"#).unwrap(),
        secrets: vec![
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
        ],
    })
}

fn line_of(src: &str, byte: usize) -> u32 {
    (memchr::memchr_iter(b'\n', &src.as_bytes()[..byte.min(src.len())]).count() + 1) as u32
}

fn shannon(s: &str) -> f64 {
    rex_core::hash::entropy(s.as_bytes())
}

fn is_internal_host(host: &str) -> bool {
    let h = host.split(':').next().unwrap_or(host);
    h == "localhost"
        || h.starts_with("127.")
        || h.starts_with("10.")
        || h.starts_with("192.168.")
        || (h.starts_with("172.")
            && h.split('.')
                .nth(1)
                .and_then(|o| o.parse::<u8>().ok())
                .is_some_and(|o| (16..=31).contains(&o)))
        || [".internal", ".local", ".corp", ".lan", ".intranet"]
            .iter()
            .any(|s| h.ends_with(s))
        || [
            "staging", "stage.", "dev.", "-dev.", "qa.", "uat.", "test.", "sandbox",
        ]
        .iter()
        .any(|s| h.contains(s))
}

/// Analyse JavaScript source text.
pub fn analyze(src: &str) -> JsReport {
    let p = pats();
    let mut r = JsReport {
        lines: src.lines().count(),
        ..Default::default()
    };
    for m in p.url.find_iter(src) {
        let u = m.as_str().trim_end_matches(['.', ',', ';']).to_string();
        if u.contains("www.w3.org")
            || u.contains("reactjs.org/docs/error-decoder")
            || u.contains("schemas.")
        {
            continue;
        }
        if let Some((_, host, _, _)) = crate::har::split_url(&u) {
            if is_internal_host(&host) {
                r.internal_hosts.insert(host);
            }
        }
        if r.urls.len() < 2000 {
            r.urls.insert(u);
        }
    }
    for c in p.path.captures_iter(src) {
        if r.paths.len() < 2000 {
            r.paths.insert(c[1].to_string());
        }
    }
    for c in p.call.captures_iter(src) {
        let method = c
            .get(1)
            .or(c.get(2))
            .or(c.get(3))
            .map(|m| m.as_str().to_ascii_uppercase())
            .unwrap_or_else(|| "GET".into());
        let mut method = if method == "AJAX" {
            "GET".into()
        } else {
            method
        };
        // fetch(url, { method: "POST" }): look a little way past the URL for an options object.
        if c.get(1).is_none() && c.get(3).is_none() {
            let end = c.get(0).expect("match").end();
            let tail = &src[end..src.len().min(end + 160)];
            let tail = tail.split(')').next().unwrap_or(tail);
            if let Some(mm) = p.method.captures(tail) {
                method = mm[1].to_ascii_uppercase();
            }
        }
        let target = c[4].to_string();
        if target.starts_with('/') || target.starts_with("http") || target.contains("${") {
            r.calls.insert((method, target));
        }
    }
    for c in p.gql.captures_iter(src) {
        r.graphql.insert(format!("{} {}", &c[1], &c[2]));
    }
    for c in p.env.captures_iter(src) {
        r.env_vars.insert(c[1].to_string());
    }
    r.source_map_url = p.smap.captures_iter(src).last().map(|c| c[1].to_string());

    let mut seen = BTreeSet::new();
    for (kind, re, high) in &p.secrets {
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
                if shannon(&value) < 3.3
                    || v.contains("placeholder")
                    || v.contains("example")
                    || v.contains("xxxx")
                    || v.contains("your")
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
                r.secrets.push(SecretHit {
                    kind,
                    value,
                    line: line_of(src, whole.start()),
                    high,
                });
            }
        }
    }

    const FRAMEWORKS: &[(&str, &[&str])] = &[
        (
            "React",
            &[
                "react.production.min",
                "__REACT_DEVTOOLS_GLOBAL_HOOK__",
                "react-dom",
                "_reactRootContainer",
            ],
        ),
        (
            "Next.js",
            &["__NEXT_DATA__", "/_next/static/", "next/router"],
        ),
        (
            "Vue",
            &["__VUE__", "__vue_app__", "Vue.component", "createVNode"],
        ),
        ("Nuxt", &["__NUXT__", "/_nuxt/"]),
        (
            "Angular",
            &["ng-version", "ɵɵdefineComponent", "@angular/core"],
        ),
        ("Svelte", &["svelte-", "SvelteComponent"]),
        ("jQuery", &["jQuery.fn", "jquery"]),
        ("webpack", &["__webpack_require__", "webpackChunk"]),
        ("Vite", &["import.meta.env", "/@vite/"]),
        (
            "Firebase",
            &[
                "firebaseapp.com",
                "firebase.initializeApp",
                "firestore.googleapis.com",
            ],
        ),
        ("Sentry", &["@sentry/", "Sentry.init"]),
        ("Apollo GraphQL", &["ApolloClient", "__APOLLO_STATE__"]),
        ("Socket.IO", &["socket.io", "io.connect("]),
    ];
    for (name, markers) in FRAMEWORKS {
        if markers.iter().any(|m| src.contains(m)) {
            r.frameworks.insert(name);
        }
    }
    const SINKS: &[(&str, &str)] = &[
        ("eval(", "eval("),
        ("new Function(", "new Function("),
        (".innerHTML=", ".innerHTML="),
        (".innerHTML =", ".innerHTML ="),
        (".outerHTML=", ".outerHTML="),
        ("document.write(", "document.write("),
        ("dangerouslySetInnerHTML", "dangerouslySetInnerHTML"),
        ("v-html", "v-html"),
        ("bypassSecurityTrust", "bypassSecurityTrust"),
        ("postMessage(", "postMessage("),
        ("setTimeout(\"", "setTimeout(\""),
    ];
    let mut sinks: Vec<(&'static str, usize)> = Vec::new();
    for (label, needle) in SINKS {
        let n = memchr::memmem::find_iter(src.as_bytes(), needle.as_bytes()).count();
        if n > 0 {
            let label = label.trim_end_matches(" =").trim_end_matches('=');
            match sinks.iter_mut().find(|(l, _)| *l == label) {
                Some(s) => s.1 += n,
                None => sinks.push((label, n)),
            }
        }
    }
    r.sinks = sinks;
    r
}

/// A parsed source map.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct SourceMap {
    /// Original source paths.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Original contents (parallel to `sources`).
    #[serde(default, rename = "sourcesContent")]
    pub sources_content: Vec<Option<String>>,
    /// Optional root.
    #[serde(default, rename = "sourceRoot")]
    pub source_root: Option<String>,
}

/// Parse a source map (JSON). Also accepts the `)]}'` XSSI prefix.
pub fn parse_source_map(data: &[u8]) -> rex_core::Result<SourceMap> {
    let data = data.strip_prefix(b")]}'").unwrap_or(data);
    serde_json::from_slice(data).map_err(|e| rex_core::Error::parse("source map", e.to_string()))
}

/// Decode an inline `data:application/json;base64,…` source map.
pub fn inline_source_map(url: &str) -> Option<Vec<u8>> {
    let rest = url.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    if meta.contains("base64") {
        crate::b64::decode(payload)
    } else {
        Some(crate::har::percent_decode(payload).into_bytes())
    }
}

/// Turn a source-map path like `webpack:///./src/../app/x.ts` into a safe
/// relative path (no `..`, no absolute roots, no drive letters).
pub fn safe_relative(p: &str) -> Option<PathBuf> {
    let mut s = p;
    for prefix in [
        "webpack://",
        "webpack-internal://",
        "file://",
        "ng://",
        "vite://",
        "rollup://",
    ] {
        if let Some(r) = s.strip_prefix(prefix) {
            s = r;
        }
    }
    let s = s.split(['?', '#']).next().unwrap_or(s).replace('\\', "/");
    let mut out = PathBuf::new();
    for comp in Path::new(&s).components() {
        match comp {
            Component::Normal(c) => {
                let c = c.to_string_lossy();
                let clean: String = c
                    .chars()
                    .map(|ch| {
                        if ch.is_control() || matches!(ch, ':' | '*' | '?' | '"' | '<' | '>' | '|')
                        {
                            '_'
                        } else {
                            ch
                        }
                    })
                    .collect();
                if !clean.is_empty() {
                    out.push(clean);
                }
            }
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    (out.components().count() > 0).then_some(out)
}

/// Write every embedded original source under `dir`. Returns (written, skipped-without-content).
pub fn unpack(map: &SourceMap, dir: &Path) -> std::io::Result<(Vec<PathBuf>, usize)> {
    let mut written = Vec::new();
    let mut missing = 0;
    for (i, src) in map.sources.iter().enumerate() {
        let Some(Some(content)) = map.sources_content.get(i) else {
            missing += 1;
            continue;
        };
        let Some(rel) = safe_relative(src) else {
            missing += 1;
            continue;
        };
        let path = dir.join(&rel);
        debug_assert!(path.starts_with(dir));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, content)?;
        written.push(path);
    }
    Ok((written, missing))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLE: &str = r#"!function(){"use strict";var e="https://api.example.com/v2",t=__webpack_require__(1);
fetch("/api/v2/users/"+id,{method:"GET"});axios.post("/api/v2/orders",{a:1});
const q=gql`query GetViewer { viewer { id } }`;var k="{AWS}";
var cfg={apiKey:"{GKEY}",password:"hunter2"};
el.innerHTML = x; eval(y); var s="http://staging.internal.example.local:8080/debug";
var env=process.env.REACT_APP_API_URL;
//# sourceMappingURL=app.js.map
}();"#;

    /// Key-shaped values are assembled at runtime so the repository itself never
    /// contains contiguous secret-looking literals (keeps secret scanners quiet).
    fn bundle() -> String {
        BUNDLE
            .replace("{AWS}", &format!("AKIA{}", "ABCDEFGHIJKLMNOP"))
            .replace(
                "{GKEY}",
                &format!("AIza{}", "SyA1234567890abcdefghijklmnopqrstuv"),
            )
    }

    #[test]
    fn analyzes_bundle() {
        let r = analyze(&bundle());
        assert!(r.urls.contains("https://api.example.com/v2"));
        assert!(r.paths.contains("/api/v2/orders"), "{:?}", r.paths);
        assert!(
            r.calls.contains(&("POST".into(), "/api/v2/orders".into())),
            "{:?}",
            r.calls
        );
        assert!(r.calls.contains(&("GET".into(), "/api/v2/users/".into())));
        assert!(r.graphql.contains("query GetViewer"));
        assert!(
            r.secrets
                .iter()
                .any(|s| s.kind == "AWS access key id" && s.line == 3)
        );
        assert!(r.secrets.iter().any(|s| s.kind == "Google API key"));
        assert!(
            !r.secrets.iter().any(|s| s.value == "hunter2"),
            "low-entropy/short values ignored"
        );
        assert!(r.frameworks.contains("webpack"));
        assert!(r.sinks.iter().any(|(s, n)| *s == ".innerHTML" && *n == 1));
        assert!(r.internal_hosts.iter().any(|h| h.contains("staging")));
        assert!(r.env_vars.contains("REACT_APP_API_URL"));
        assert_eq!(r.source_map_url.as_deref(), Some("app.js.map"));
    }

    #[test]
    fn safe_paths() {
        assert_eq!(
            safe_relative("webpack:///./src/App.tsx").unwrap(),
            PathBuf::from("src/App.tsx")
        );
        assert_eq!(
            safe_relative("../../../../etc/passwd").unwrap(),
            PathBuf::from("etc/passwd")
        );
        assert_eq!(
            safe_relative("/abs/x.js").unwrap(),
            PathBuf::from("abs/x.js")
        );
        assert_eq!(
            safe_relative("C:\\Users\\a\\b.js").unwrap(),
            PathBuf::from("C_/Users/a/b.js")
        );
        assert!(safe_relative("../..").is_none());
    }

    #[test]
    fn unpacks_sources_safely() {
        let map = parse_source_map(
            br#"{"version":3,"sources":["webpack:///src/a.js","../../evil.js","missing.js"],"sourcesContent":["A","B",null],"mappings":""}"#,
        )
        .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let (w, missing) = unpack(&map, dir.path()).unwrap();
        assert_eq!(w.len(), 2);
        assert_eq!(missing, 1);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("src/a.js")).unwrap(),
            "A"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("evil.js")).unwrap(),
            "B"
        );
        assert!(w.iter().all(|p| p.starts_with(dir.path())));
    }

    #[test]
    fn inline_maps() {
        let m =
            inline_source_map("data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozfQ==")
                .unwrap();
        assert_eq!(m, br#"{"version":3}"#);
    }
}
