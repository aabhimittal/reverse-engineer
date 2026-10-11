//! HAR (HTTP Archive) parsing and endpoint clustering.
//!
//! A HAR file is a flight recorder for a browser session: every request and
//! response, headers and bodies included. Export one from DevTools
//! (Network → "Save all as HAR"), mitmproxy, Burp, Charles or Proxyman.
//!
//! The hard part is *generalisation*: `/users/42`, `/users/97` and
//! `/users/1003` are one endpoint, `/users/{userId}`. We do it in two passes:
//!
//! 1. **Per-segment heuristics**: numbers, UUIDs, long hex strings, dates and
//!    opaque tokens are obviously identifiers.
//! 2. **Sibling clustering**: when several paths share every segment except
//!    one, and that position has many distinct values (`/repos/rust-lang/…`,
//!    `/repos/torvalds/…`), that position is a parameter too.

use crate::schema::{Shape, is_uuid};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

// ───────────────────────── raw HAR model (lenient) ─────────────────────────

/// Root.
#[derive(Debug, Deserialize)]
pub struct Har {
    /// The log.
    pub log: Log,
}

/// Log.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Log {
    /// Entries.
    pub entries: Vec<Entry>,
    /// Creator (tool that produced the HAR).
    pub creator: Option<Creator>,
}

/// Creator.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Creator {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
}

/// One exchange.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Entry {
    /// Request.
    pub request: Request,
    /// Response.
    pub response: Response,
    /// Resource type (Chrome extension field).
    #[serde(rename = "_resourceType")]
    pub resource_type: Option<String>,
}

/// Name/value pair.
#[derive(Debug, Deserialize, Default, Clone)]
#[serde(default)]
pub struct NameValue {
    /// Name.
    pub name: String,
    /// Value.
    pub value: String,
}

/// Request.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Request {
    /// Method.
    pub method: String,
    /// Absolute URL.
    pub url: String,
    /// Headers.
    pub headers: Vec<NameValue>,
    /// Query parameters.
    #[serde(rename = "queryString")]
    pub query_string: Vec<NameValue>,
    /// Body.
    #[serde(rename = "postData")]
    pub post_data: Option<PostData>,
    /// Cookies.
    pub cookies: Vec<NameValue>,
}

/// Request body.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct PostData {
    /// MIME type.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Body text.
    pub text: Option<String>,
    /// Form params.
    pub params: Vec<NameValue>,
}

/// Response.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Response {
    /// Status code.
    pub status: i64,
    /// Headers.
    pub headers: Vec<NameValue>,
    /// Content.
    pub content: Content,
}

/// Response body.
#[derive(Debug, Deserialize, Default)]
#[serde(default)]
pub struct Content {
    /// MIME type.
    #[serde(rename = "mimeType")]
    pub mime_type: String,
    /// Text (possibly base64).
    pub text: Option<String>,
    /// `base64` when `text` is encoded.
    pub encoding: Option<String>,
    /// Size.
    pub size: i64,
}

impl Request {
    /// Header lookup (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
}

impl Response {
    /// Header lookup (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
    /// All values of a header.
    pub fn headers_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.headers
            .iter()
            .filter(move |h| h.name.eq_ignore_ascii_case(name))
            .map(|h| h.value.as_str())
    }
    /// Decoded body text.
    pub fn body(&self) -> Option<String> {
        let t = self.content.text.as_ref()?;
        if self.content.encoding.as_deref() == Some("base64") {
            crate::b64::decode(t).map(|b| String::from_utf8_lossy(&b).into_owned())
        } else {
            Some(t.clone())
        }
    }
}

/// Parse HAR JSON.
pub fn parse(data: &[u8]) -> rex_core::Result<Har> {
    let data = data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(data);
    serde_json::from_slice(data).map_err(|e| rex_core::Error::parse("HAR", e.to_string()))
}

// ───────────────────────── URL helpers ─────────────────────────

/// Split an absolute URL into (scheme, host, path, query).
pub fn split_url(url: &str) -> Option<(String, String, String, String)> {
    let (scheme, rest) = url.split_once("://")?;
    let (hostpart, pathq) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let pathq = pathq.split('#').next().unwrap_or("/");
    let (path, query) = pathq.split_once('?').unwrap_or((pathq, ""));
    let host = hostpart
        .rsplit('@')
        .next()
        .unwrap_or(hostpart)
        .to_ascii_lowercase();
    Some((
        scheme.to_ascii_lowercase(),
        host,
        path.to_string(),
        query.to_string(),
    ))
}

/// Percent-decode (lossy).
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Static assets we skip by default.
pub fn is_static_asset(path: &str, mime: &str) -> bool {
    const EXT: &[&str] = &[
        ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".map", ".mp4", ".webm", ".mp3", ".wasm",
        ".html", ".htm",
    ];
    let p = path.to_ascii_lowercase();
    let m = mime.to_ascii_lowercase();
    EXT.iter().any(|e| p.ends_with(e))
        || m.starts_with("image/")
        || m.starts_with("font/")
        || m.starts_with("video/")
        || m.starts_with("audio/")
        || m.contains("javascript")
        || m.contains("text/css")
        || m.contains("text/html")
}

// ───────────────────────── path templating ─────────────────────────

/// Parameter type inferred from observed values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParamKind {
    /// Integer id.
    Integer,
    /// UUID.
    Uuid,
    /// Hex digest / object id.
    Hex,
    /// Date.
    Date,
    /// Opaque token.
    Token,
    /// Free-form slug.
    Slug,
}

/// Classify a single path segment as an identifier, if it obviously is one.
pub fn classify_segment(seg: &str) -> Option<ParamKind> {
    if seg.is_empty() {
        return None;
    }
    if seg.bytes().all(|c| c.is_ascii_digit()) {
        return Some(ParamKind::Integer);
    }
    if is_uuid(seg) {
        return Some(ParamKind::Uuid);
    }
    if seg.len() >= 16
        && seg.bytes().all(|c| c.is_ascii_hexdigit())
        && seg.bytes().any(|c| c.is_ascii_digit())
    {
        return Some(ParamKind::Hex);
    }
    if crate::schema::detect_format(seg) == Some(crate::schema::StrFormat::Date) {
        return Some(ParamKind::Date);
    }
    let digits = seg.bytes().filter(u8::is_ascii_digit).count();
    let alnum = seg
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    if seg.len() >= 20 && alnum && digits >= 3 && seg.bytes().any(|c| c.is_ascii_uppercase()) {
        return Some(ParamKind::Token);
    }
    // e.g. "u_8f3k2", "ord-12345": mostly digits with a short prefix.
    if alnum && seg.len() >= 6 && digits * 2 >= seg.len() {
        return Some(ParamKind::Token);
    }
    None
}

/// `users` → `user`, `categories` → `category`.
pub fn singular(word: &str) -> String {
    let w = word.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if let Some(s) = w.strip_suffix("ies") {
        format!("{s}y")
    } else if w.ends_with("sses")
        || w.ends_with("xes")
        || w.ends_with("ches")
        || w.ends_with("shes")
    {
        w[..w.len() - 2].to_string()
    } else if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") {
        w[..w.len() - 1].to_string()
    } else {
        w.to_string()
    }
}

fn camel(word: &str) -> String {
    let mut out = String::new();
    let mut up = false;
    for c in word.chars() {
        if c == '-' || c == '_' || c == '.' {
            up = true;
        } else if up {
            out.extend(c.to_uppercase());
            up = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// A path segment: literal text or a named parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Seg {
    /// Literal text.
    Lit(String),
    /// Parameter `{name}`.
    Param(String),
}

fn param_name(prev: Option<&Seg>, used: &mut BTreeSet<String>) -> String {
    let base = match prev {
        Some(Seg::Lit(l)) if !l.is_empty() && classify_segment(l).is_none() => {
            format!("{}Id", camel(&singular(l)))
        }
        _ => "id".to_string(),
    };
    let base = if base == "Id" { "id".to_string() } else { base };
    let mut name = base.clone();
    let mut n = 2;
    while !used.insert(name.clone()) {
        name = format!("{base}{n}");
        n += 1;
    }
    name
}

/// First-pass template for one path.
pub fn template_segments(path: &str) -> Vec<Seg> {
    let mut used = BTreeSet::new();
    let mut out: Vec<Seg> = Vec::new();
    for raw in path.split('/').skip(1) {
        let seg = percent_decode(raw);
        if classify_segment(&seg).is_some() {
            let name = param_name(out.last(), &mut used);
            out.push(Seg::Param(name));
        } else {
            out.push(Seg::Lit(seg));
        }
    }
    out
}

/// Render segments as an OpenAPI path.
pub fn render(segs: &[Seg]) -> String {
    if segs.is_empty() {
        return "/".into();
    }
    let mut s = String::new();
    for seg in segs {
        s.push('/');
        match seg {
            Seg::Lit(l) => s.push_str(l),
            Seg::Param(p) => {
                s.push('{');
                s.push_str(p);
                s.push('}');
            }
        }
    }
    s
}

/// Does a literal look like data (an identifier/slug) rather than a resource name?
fn data_like(v: &str) -> bool {
    let is_version =
        v.len() <= 4 && v.starts_with('v') && v[1..].bytes().all(|c| c.is_ascii_digit());
    !is_version
        && v.bytes().any(|c| {
            c.is_ascii_digit()
                || matches!(c, b'-' | b'.' | b'_' | b'@' | b'~')
                || c.is_ascii_uppercase()
        })
}

/// Second pass: generalise positions where siblings under the same prefix
/// carry many distinct *values*.
///
/// A position becomes a parameter when, under a shared prefix, there are at
/// least `min_distinct` distinct literals **and** either
/// * the literals look like data (`rust-lang`, `v8.2`, `John_Doe`), or
/// * the previous position is a parameter and each literal occurs under
///   exactly one parent value (1:1 co-variation, e.g. `{owner}/{repo}`), which
///   distinguishes data from sub-resources such as `/users/{id}/orders`.
///
/// Takes the raw (percent-decoded) segments of each path and returns one
/// template per input, in order.
pub fn cluster(raw: &[Vec<String>], min_distinct: usize) -> Vec<Vec<Seg>> {
    let mut cur: Vec<Vec<Seg>> = raw
        .iter()
        .map(|segs| template_segments(&format!("/{}", segs.join("/"))))
        .collect();
    let max_len = cur.iter().map(Vec::len).max().unwrap_or(0);
    for pos in 1..max_len {
        let mut groups: BTreeMap<(usize, Vec<Seg>), Vec<usize>> = BTreeMap::new();
        for (i, p) in cur.iter().enumerate() {
            if pos < p.len() && matches!(p[pos], Seg::Lit(_)) {
                groups
                    .entry((p.len(), p[..pos].to_vec()))
                    .or_default()
                    .push(i);
            }
        }
        for ((_, prefix), idxs) in groups {
            let values: BTreeSet<&str> = idxs.iter().map(|&i| raw[i][pos].as_str()).collect();
            if values.len() < min_distinct {
                continue;
            }
            let covary = matches!(prefix.last(), Some(Seg::Param(_))) && {
                let mut parents_of: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
                for &i in &idxs {
                    parents_of
                        .entry(raw[i][pos].as_str())
                        .or_default()
                        .insert(raw[i][pos - 1].as_str());
                }
                let parents: BTreeSet<&str> =
                    idxs.iter().map(|&i| raw[i][pos - 1].as_str()).collect();
                parents.len() >= min_distinct && parents_of.values().all(|p| p.len() == 1)
            };
            // Forward co-variation: every value has its own distinct child segment
            // (`/repos/torvalds/linux`, `/repos/golang/go`), i.e. the pair is data.
            let covary_fwd = values.len() >= min_distinct.max(4) && {
                let mut children: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
                let mut all_children = BTreeSet::new();
                let mut has_child = true;
                for &i in &idxs {
                    match raw[i].get(pos + 1) {
                        Some(c) => {
                            children
                                .entry(raw[i][pos].as_str())
                                .or_default()
                                .insert(c.as_str());
                            all_children.insert(c.as_str());
                        }
                        None => has_child = false,
                    }
                }
                has_child
                    && children.values().all(|c| c.len() == 1)
                    && all_children.len() == children.len()
            };
            let mostly_data = values.iter().filter(|v| data_like(v)).count() * 2 > values.len();
            if !(covary || covary_fwd || mostly_data) {
                continue;
            }
            let mut used: BTreeSet<String> = prefix
                .iter()
                .filter_map(|s| {
                    if let Seg::Param(p) = s {
                        Some(p.clone())
                    } else {
                        None
                    }
                })
                .collect();
            let name = match prefix.last() {
                Some(Seg::Lit(_)) => param_name(prefix.last(), &mut used),
                _ => {
                    let mut n = format!("param{pos}");
                    let mut k = 2;
                    while used.contains(&n) {
                        n = format!("param{pos}_{k}");
                        k += 1;
                    }
                    n
                }
            };
            for &i in &idxs {
                cur[i][pos] = Seg::Param(name.clone());
            }
        }
    }
    cur
}

// ───────────────────────── endpoint aggregation ─────────────────────────

/// Aggregated knowledge about one parameter.
#[derive(Debug, Clone, Default)]
pub struct ParamInfo {
    /// Times present.
    pub count: usize,
    /// Shape of observed values (parsed as JSON scalar where possible).
    pub shape: Shape,
}

/// Aggregated knowledge about one `METHOD path` pair.
#[derive(Debug, Clone, Default)]
pub struct Endpoint {
    /// HTTP method (upper case).
    pub method: String,
    /// Templated path.
    pub path: String,
    /// Concrete examples seen.
    pub examples: BTreeSet<String>,
    /// Hosts (`scheme://host`).
    pub servers: BTreeSet<String>,
    /// Number of calls.
    pub count: usize,
    /// Path parameter values by name.
    pub path_params: BTreeMap<String, ParamInfo>,
    /// Query parameters.
    pub query: BTreeMap<String, ParamInfo>,
    /// Interesting request headers (API keys etc.).
    pub headers: BTreeMap<String, ParamInfo>,
    /// Request bodies by content type.
    pub request_bodies: BTreeMap<String, Shape>,
    /// Responses: status → (content type → shape).
    pub responses: BTreeMap<i64, BTreeMap<String, Shape>>,
    /// Auth schemes observed (names from [`crate::openapi::auth_scheme`]).
    pub auth: BTreeSet<String>,
}

fn scalar_value(s: &str) -> serde_json::Value {
    if let Ok(i) = s.parse::<i64>() {
        return serde_json::json!(i);
    }
    if let Ok(f) = s.parse::<f64>() {
        if f.is_finite() && s.contains('.') {
            return serde_json::json!(f);
        }
    }
    match s {
        "true" => serde_json::json!(true),
        "false" => serde_json::json!(false),
        _ => serde_json::json!(s),
    }
}

/// Options for endpoint extraction.
#[derive(Debug, Clone)]
pub struct ExtractOptions {
    /// Include static assets (JS, CSS, images, HTML).
    pub include_static: bool,
    /// Restrict to hosts containing any of these substrings (empty = all).
    pub hosts: Vec<String>,
    /// Minimum distinct values for sibling clustering.
    pub min_distinct: usize,
}

impl Default for ExtractOptions {
    fn default() -> Self {
        Self {
            include_static: false,
            hosts: Vec::new(),
            min_distinct: 3,
        }
    }
}

const SKIP_HEADERS: &[&str] = &[
    "accept",
    "accept-encoding",
    "accept-language",
    "cache-control",
    "connection",
    "content-length",
    "content-type",
    "cookie",
    "host",
    "origin",
    "pragma",
    "referer",
    "user-agent",
    "authorization",
    "if-none-match",
    "if-modified-since",
    "dnt",
    "te",
    "upgrade-insecure-requests",
    "priority",
];

fn content_type(mime: &str) -> String {
    let m = mime
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if m.is_empty() {
        "application/octet-stream".into()
    } else {
        m
    }
}

/// Turn HAR entries into templated endpoints.
pub fn extract(har: &Har, opts: &ExtractOptions) -> Vec<Endpoint> {
    struct Raw<'a> {
        e: &'a Entry,
        scheme: String,
        host: String,
        segs: Vec<String>,
        raw_path: String,
        query: String,
    }
    let mut raws = Vec::new();
    for e in &har.log.entries {
        let Some((scheme, host, path, query)) = split_url(&e.request.url) else {
            continue;
        };
        if !matches!(scheme.as_str(), "http" | "https") {
            continue;
        }
        if !opts.hosts.is_empty() && !opts.hosts.iter().any(|h| host.contains(h.as_str())) {
            continue;
        }
        if !opts.include_static && is_static_asset(&path, &e.response.content.mime_type) {
            continue;
        }
        if e.request.method.eq_ignore_ascii_case("OPTIONS") {
            continue; // CORS preflight noise
        }
        let segs: Vec<String> = path.split('/').skip(1).map(percent_decode).collect();
        raws.push(Raw {
            e,
            scheme,
            host,
            segs,
            raw_path: path,
            query,
        });
    }
    let all: Vec<Vec<String>> = raws.iter().map(|r| r.segs.clone()).collect();
    let templates = cluster(&all, opts.min_distinct.max(2));

    let mut eps: BTreeMap<(String, String), Endpoint> = BTreeMap::new();
    for (r, segs) in raws.iter().zip(templates) {
        let path = render(&segs);
        let method = r.e.request.method.to_ascii_uppercase();
        let ep = eps
            .entry((path.clone(), method.clone()))
            .or_insert_with(|| Endpoint {
                method: method.clone(),
                path: path.clone(),
                ..Default::default()
            });
        ep.count += 1;
        if ep.examples.len() < 5 {
            ep.examples.insert(r.raw_path.clone());
        }
        ep.servers.insert(format!("{}://{}", r.scheme, r.host));
        // Path params: zip concrete segments with the template.
        for (raw, seg) in r.raw_path.split('/').skip(1).zip(segs.iter()) {
            if let Seg::Param(name) = seg {
                let p = ep.path_params.entry(name.clone()).or_default();
                p.count += 1;
                p.shape.observe(&scalar_value(&percent_decode(raw)));
            }
        }
        // Query params: prefer the HAR's parsed list, fall back to the URL.
        let mut q: Vec<(String, String)> =
            r.e.request
                .query_string
                .iter()
                .map(|nv| (nv.name.clone(), nv.value.clone()))
                .collect();
        if q.is_empty() && !r.query.is_empty() {
            q = r
                .query
                .split('&')
                .filter(|kv| !kv.is_empty())
                .map(|kv| {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    (percent_decode(k), percent_decode(v))
                })
                .collect();
        }
        for (k, v) in q {
            let p = ep.query.entry(k).or_default();
            p.count += 1;
            p.shape.observe(&scalar_value(&v));
        }
        for h in &r.e.request.headers {
            let n = h.name.to_ascii_lowercase();
            if n.starts_with(':') || n.starts_with("sec-") || SKIP_HEADERS.contains(&n.as_str()) {
                continue;
            }
            if n.starts_with("x-") || n.contains("key") || n.contains("token") || n.contains("auth")
            {
                let p = ep.headers.entry(h.name.clone()).or_default();
                p.count += 1;
                p.shape.observe(&serde_json::json!(h.value));
            }
        }
        if let Some(scheme) = crate::openapi::auth_scheme(&r.e.request) {
            ep.auth.insert(scheme);
        }
        if let Some(pd) = &r.e.request.post_data {
            let ct = content_type(&pd.mime_type);
            let shape = ep.request_bodies.entry(ct.clone()).or_default();
            match pd.text.as_deref() {
                Some(t) if ct.contains("json") => {
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
                        shape.observe(&v);
                    }
                }
                Some(t) if ct.contains("x-www-form-urlencoded") => {
                    let obj: serde_json::Map<String, serde_json::Value> = t
                        .split('&')
                        .filter_map(|kv| kv.split_once('='))
                        .map(|(k, v)| (percent_decode(k), scalar_value(&percent_decode(v))))
                        .collect();
                    shape.observe(&serde_json::Value::Object(obj));
                }
                _ if !pd.params.is_empty() => {
                    let obj: serde_json::Map<String, serde_json::Value> = pd
                        .params
                        .iter()
                        .map(|p| (p.name.clone(), scalar_value(&p.value)))
                        .collect();
                    shape.observe(&serde_json::Value::Object(obj));
                }
                _ => {}
            }
        }
        let status = r.e.response.status;
        if status > 0 {
            let ct = content_type(&r.e.response.content.mime_type);
            let by_ct = ep.responses.entry(status).or_default();
            let shape = by_ct.entry(ct.clone()).or_default();
            if ct.contains("json") {
                if let Some(v) =
                    r.e.response
                        .body()
                        .and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok())
                {
                    shape.observe(&v);
                }
            }
        }
    }
    eps.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments() {
        assert_eq!(classify_segment("123"), Some(ParamKind::Integer));
        assert_eq!(
            classify_segment("123e4567-e89b-12d3-a456-426614174000"),
            Some(ParamKind::Uuid)
        );
        assert_eq!(
            classify_segment("5f8d0d55b54764421b7156c3"),
            Some(ParamKind::Hex)
        );
        assert_eq!(classify_segment("2024-01-31"), Some(ParamKind::Date));
        assert_eq!(classify_segment("ord-123456"), Some(ParamKind::Token));
        assert_eq!(classify_segment("users"), None);
        assert_eq!(classify_segment("v1"), None);
        assert_eq!(classify_segment("me"), None);
    }

    #[test]
    fn singulars() {
        assert_eq!(singular("users"), "user");
        assert_eq!(singular("categories"), "category");
        assert_eq!(singular("boxes"), "box");
        assert_eq!(singular("address"), "address");
        assert_eq!(singular("status"), "statu"); // known limitation, harmless for naming
    }

    #[test]
    fn templates() {
        assert_eq!(
            render(&template_segments("/api/v1/users/42/orders/7")),
            "/api/v1/users/{userId}/orders/{orderId}"
        );
        assert_eq!(render(&template_segments("/")), "/");
        assert_eq!(
            render(&template_segments("/items/9/9")),
            "/items/{itemId}/{id}"
        );
    }

    fn run(paths: &[&str]) -> BTreeSet<String> {
        let raw: Vec<Vec<String>> = paths
            .iter()
            .map(|p| p.split('/').skip(1).map(String::from).collect())
            .collect();
        cluster(&raw, 3).iter().map(|s| render(s)).collect()
    }

    #[test]
    fn clusters_owner_repo_pairs() {
        let out = run(&[
            "/repos/rust-lang/rust",
            "/repos/torvalds/linux",
            "/repos/golang/go",
            "/repos/nodejs/node",
        ]);
        assert_eq!(
            out,
            BTreeSet::from(["/repos/{repoId}/{param2}".to_string()])
        );
    }

    #[test]
    fn keeps_resource_names_and_subresources() {
        assert_eq!(run(&["/api/users", "/api/orders", "/api/items"]).len(), 3);
        let out = run(&[
            "/users/1/orders",
            "/users/1/profile",
            "/users/2/orders",
            "/users/2/profile",
            "/users/3/settings",
        ]);
        assert!(out.contains("/users/{userId}/orders"), "{out:?}");
        assert!(out.contains("/users/{userId}/profile"), "{out:?}");
        assert_eq!(
            run(&["/api/v1/x", "/api/v2/x", "/api/v3/x"]).len(),
            3,
            "versions stay literal"
        );
    }

    #[test]
    fn clusters_slugs_with_data_shape() {
        let out = run(&["/blog/hello-world", "/blog/rust-2024", "/blog/why-rex"]);
        assert_eq!(out, BTreeSet::from(["/blog/{blogId}".to_string()]));
    }

    #[test]
    fn url_split_and_decode() {
        let (s, h, p, q) =
            split_url("https://user@API.example.com:8443/a/b%20c?x=1&y=2#frag").unwrap();
        assert_eq!(
            (s.as_str(), h.as_str(), p.as_str(), q.as_str()),
            ("https", "api.example.com:8443", "/a/b%20c", "x=1&y=2")
        );
        assert_eq!(percent_decode("b%20c+d%zz"), "b c d%zz");
    }
}
