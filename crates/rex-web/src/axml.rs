//! Android binary XML ("AXML") decoder, plus an `AndroidManifest.xml` model.
//!
//! In an APK, XML is compiled into a compact chunked binary: a string pool,
//! a resource-id map, then a stream of start/end-element events whose names
//! and values are indices into the pool. Analogy: a book where every word
//! has been replaced by its page number in the dictionary at the front. We
//! read the dictionary first, then re-expand the text.

use rex_core::{Error, Result};
use serde::Serialize;
use std::fmt::Write;

const RES_STRING_POOL: u16 = 0x0001;
const RES_XML: u16 = 0x0003;
const RES_XML_START_NS: u16 = 0x0100;
const RES_XML_END_NS: u16 = 0x0101;
const RES_XML_START_ELEMENT: u16 = 0x0102;
const RES_XML_END_ELEMENT: u16 = 0x0103;
const RES_XML_CDATA: u16 = 0x0104;
const RES_XML_RESOURCE_MAP: u16 = 0x0180;
const ANDROID_NS: &str = "http://schemas.android.com/apk/res/android";

/// An attribute.
#[derive(Debug, Clone, Serialize)]
pub struct Attr {
    /// Namespace prefix (`android`) or empty.
    pub prefix: String,
    /// Local name.
    pub name: String,
    /// Rendered value.
    pub value: String,
}

/// An element.
#[derive(Debug, Clone, Serialize)]
pub struct Element {
    /// Tag name.
    pub name: String,
    /// Attributes.
    pub attrs: Vec<Attr>,
    /// Children.
    pub children: Vec<Element>,
    /// Text content (CDATA).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub text: String,
}

impl Element {
    /// Attribute by local name (any namespace).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }
    /// Depth-first iterator over descendants named `tag`.
    pub fn find_all<'a>(&'a self, tag: &'a str) -> Vec<&'a Element> {
        let mut out = Vec::new();
        let mut stack = vec![self];
        while let Some(e) = stack.pop() {
            if e.name == tag {
                out.push(e);
            }
            for c in e.children.iter().rev() {
                stack.push(c);
            }
        }
        out
    }
    /// Serialise as indented XML.
    pub fn to_xml(&self) -> String {
        let mut o = String::from("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
        self.write(&mut o, 0, true);
        o
    }
    fn write(&self, o: &mut String, depth: usize, root: bool) {
        let pad = "    ".repeat(depth);
        let _ = write!(o, "{pad}<{}", self.name);
        if root && self.attrs.iter().any(|a| a.prefix == "android") {
            let _ = write!(o, " xmlns:android=\"{ANDROID_NS}\"");
        }
        for a in &self.attrs {
            let n = if a.prefix.is_empty() {
                a.name.clone()
            } else {
                format!("{}:{}", a.prefix, a.name)
            };
            let _ = write!(o, "\n{pad}    {n}=\"{}\"", xml_escape(&a.value));
        }
        if self.children.is_empty() && self.text.is_empty() {
            o.push_str(" />\n");
            return;
        }
        o.push_str(">\n");
        if !self.text.is_empty() {
            let _ = writeln!(o, "{pad}    {}", xml_escape(&self.text));
        }
        for c in &self.children {
            c.write(o, depth + 1, false);
        }
        let _ = writeln!(o, "{pad}</{}>", self.name);
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

struct Reader<'a> {
    d: &'a [u8],
}

impl Reader<'_> {
    fn u16(&self, o: usize) -> Result<u16> {
        self.d
            .get(o..o + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| Error::parse("AXML", format!("truncated at {o:#x}")))
    }
    fn u32(&self, o: usize) -> Result<u32> {
        self.d
            .get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| Error::parse("AXML", format!("truncated at {o:#x}")))
    }
}

/// Parse a string pool chunk starting at `off`.
pub(crate) fn string_pool(d: &[u8], off: usize) -> Result<Vec<String>> {
    let r = Reader { d };
    let count = r.u32(off + 8)? as usize;
    let flags = r.u32(off + 16)?;
    let strings_start = r.u32(off + 20)? as usize;
    let header = r.u16(off + 2)? as usize;
    let utf8 = flags & (1 << 8) != 0;
    if count > 1_000_000 {
        return Err(Error::parse("AXML", "absurd string count"));
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let so = r.u32(off + header + i * 4)? as usize;
        let p = off + strings_start + so;
        let s = if utf8 {
            // utf16 length then utf8 length, each 1 or 2 bytes.
            let mut q = p;
            let skip_len = |q: &mut usize| -> Result<usize> {
                let b0 = *d
                    .get(*q)
                    .ok_or_else(|| Error::parse("AXML", "bad utf8 len"))?
                    as usize;
                *q += 1;
                if b0 & 0x80 != 0 {
                    let b1 = *d
                        .get(*q)
                        .ok_or_else(|| Error::parse("AXML", "bad utf8 len"))?
                        as usize;
                    *q += 1;
                    Ok(((b0 & 0x7f) << 8) | b1)
                } else {
                    Ok(b0)
                }
            };
            let _u16len = skip_len(&mut q)?;
            let len = skip_len(&mut q)?;
            String::from_utf8_lossy(d.get(q..q + len).unwrap_or(&[])).into_owned()
        } else {
            let mut len = r.u16(p)? as usize;
            let mut q = p + 2;
            if len & 0x8000 != 0 {
                len = ((len & 0x7fff) << 16) | r.u16(q)? as usize;
                q += 2;
            }
            let units: Vec<u16> = (0..len.min(1 << 20))
                .map_while(|i| r.u16(q + i * 2).ok())
                .collect();
            String::from_utf16_lossy(&units)
        };
        out.push(s);
    }
    Ok(out)
}

/// Well-known `android:` attribute resource ids, for manifests whose string
/// pool names were stripped by obfuscators.
fn android_attr_name(id: u32) -> Option<&'static str> {
    Some(match id {
        0x0101_0000 => "theme",
        0x0101_0001 => "label",
        0x0101_0002 => "icon",
        0x0101_0003 => "name",
        0x0101_0006 => "permission",
        0x0101_000f => "debuggable",
        0x0101_0010 => "exported",
        0x0101_0018 => "authorities",
        0x0101_001b => "grantUriPermissions",
        0x0101_0020 => "enabled",
        0x0101_0024 => "protectionLevel",
        0x0101_0027 => "scheme",
        0x0101_0028 => "host",
        0x0101_002a => "path",
        0x0101_002b => "pathPrefix",
        0x0101_002c => "pathPattern",
        0x0101_020c => "minSdkVersion",
        0x0101_021b => "versionCode",
        0x0101_021c => "versionName",
        0x0101_0270 => "targetSdkVersion",
        0x0101_0280 => "allowBackup",
        0x0101_04ec => "usesCleartextTraffic",
        0x0101_0527 => "networkSecurityConfig",
        _ => return None,
    })
}

fn render_value(dtype: u8, data: u32, raw: Option<&str>, strings: &[String]) -> String {
    match dtype {
        0x03 => raw
            .map(str::to_string)
            .or_else(|| strings.get(data as usize).cloned())
            .unwrap_or_default(),
        0x01 => format!("@0x{data:08x}"),
        0x02 => format!("?0x{data:08x}"),
        0x04 => f32::from_bits(data).to_string(),
        0x05 => format!("dimension(0x{data:x})"),
        0x06 => format!("fraction(0x{data:x})"),
        0x10 => (data as i32).to_string(),
        0x11 => format!("0x{data:x}"),
        0x12 => (data != 0).to_string(),
        0x1c..=0x1f => format!("#{data:08x}"),
        0x00 => String::new(),
        _ => raw
            .map(str::to_string)
            .unwrap_or_else(|| format!("0x{data:x}")),
    }
}

/// Decode binary XML into an element tree.
pub fn parse(d: &[u8]) -> Result<Element> {
    let r = Reader { d };
    if r.u16(0)? != RES_XML {
        return Err(Error::parse("AXML", "not a binary XML document"));
    }
    let header = r.u16(2)? as usize;
    let total = (r.u32(4)? as usize).min(d.len());
    let mut off = header;
    let mut strings: Vec<String> = Vec::new();
    let mut res_ids: Vec<u32> = Vec::new();
    let mut ns_uri_to_prefix: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<Element> = vec![Element {
        name: "#document".into(),
        attrs: vec![],
        children: vec![],
        text: String::new(),
    }];
    let s = |strings: &Vec<String>, idx: u32| -> String {
        if idx == u32::MAX {
            String::new()
        } else {
            strings.get(idx as usize).cloned().unwrap_or_default()
        }
    };
    let mut guard = 0usize;
    while off + 8 <= total {
        guard += 1;
        if guard > 2_000_000 {
            break;
        }
        let ty = r.u16(off)?;
        let hsize = r.u16(off + 2)? as usize;
        let size = r.u32(off + 4)? as usize;
        if size < 8 || off + size > d.len() {
            break;
        }
        match ty {
            RES_STRING_POOL => strings = string_pool(d, off)?,
            RES_XML_RESOURCE_MAP => {
                res_ids = (0..(size - hsize) / 4)
                    .filter_map(|i| r.u32(off + hsize + i * 4).ok())
                    .collect();
            }
            RES_XML_START_NS => {
                let prefix = s(&strings, r.u32(off + 16)?);
                let uri = s(&strings, r.u32(off + 20)?);
                ns_uri_to_prefix.push((uri, prefix));
            }
            RES_XML_END_NS => {}
            RES_XML_START_ELEMENT => {
                let ext = off + hsize;
                let name = s(&strings, r.u32(ext + 4)?);
                let attr_start = r.u16(ext + 8)? as usize;
                let attr_size = (r.u16(ext + 10)? as usize).max(20);
                let attr_count = r.u16(ext + 12)? as usize;
                let mut attrs = Vec::with_capacity(attr_count);
                for i in 0..attr_count.min(1024) {
                    let a = ext + attr_start + i * attr_size;
                    let ns = r.u32(a)?;
                    let name_idx = r.u32(a + 4)?;
                    let raw = r.u32(a + 8)?;
                    let dtype = *d.get(a + 15).unwrap_or(&0);
                    let data = r.u32(a + 16)?;
                    let mut aname = s(&strings, name_idx);
                    if aname.is_empty() {
                        if let Some(n) = res_ids
                            .get(name_idx as usize)
                            .and_then(|id| android_attr_name(*id))
                        {
                            aname = n.to_string();
                        }
                    }
                    let ns_uri = s(&strings, ns);
                    let prefix = if ns_uri.is_empty() {
                        String::new()
                    } else {
                        ns_uri_to_prefix
                            .iter()
                            .rev()
                            .find(|(u, _)| *u == ns_uri)
                            .map(|(_, p)| p.clone())
                            .unwrap_or_else(|| {
                                if ns_uri == ANDROID_NS {
                                    "android".into()
                                } else {
                                    "ns".into()
                                }
                            })
                    };
                    let raw_s = (raw != u32::MAX).then(|| s(&strings, raw));
                    attrs.push(Attr {
                        prefix,
                        name: aname,
                        value: render_value(dtype, data, raw_s.as_deref(), &strings),
                    });
                }
                stack.push(Element {
                    name,
                    attrs,
                    children: vec![],
                    text: String::new(),
                });
            }
            RES_XML_END_ELEMENT => {
                if stack.len() > 1 {
                    let e = stack.pop().expect("non-empty");
                    stack.last_mut().expect("parent").children.push(e);
                }
            }
            RES_XML_CDATA => {
                let t = s(&strings, r.u32(off + hsize)?);
                if let Some(top) = stack.last_mut() {
                    top.text.push_str(&t);
                }
            }
            _ => {}
        }
        off += size;
    }
    // Close anything left open (truncated documents).
    while stack.len() > 1 {
        let e = stack.pop().expect("non-empty");
        stack.last_mut().expect("parent").children.push(e);
    }
    let doc = stack.pop().expect("document");
    doc.children
        .into_iter()
        .next()
        .ok_or_else(|| Error::parse("AXML", "no root element"))
}

/// A component (activity, service, receiver, provider).
#[derive(Debug, Clone, Serialize)]
pub struct Component {
    /// `activity`, `service`, `receiver`, `provider`, `activity-alias`.
    pub kind: String,
    /// Class name.
    pub name: String,
    /// Effective exported state.
    pub exported: bool,
    /// Whether `exported` was implicit (intent filter on targetSdk < 31).
    pub implicit_export: bool,
    /// Guarding permission.
    pub permission: Option<String>,
    /// Intent-filter actions.
    pub actions: Vec<String>,
    /// Deep-link URIs (`scheme://host/path`).
    pub deep_links: Vec<String>,
}

/// Summary of an `AndroidManifest.xml`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Manifest {
    /// Package name.
    pub package: String,
    /// Version code.
    pub version_code: String,
    /// Version name.
    pub version_name: String,
    /// Minimum SDK.
    pub min_sdk: Option<u32>,
    /// Target SDK.
    pub target_sdk: Option<u32>,
    /// Requested permissions.
    pub permissions: Vec<String>,
    /// Custom permissions defined by the app: (name, protectionLevel).
    pub defined_permissions: Vec<(String, String)>,
    /// `android:debuggable`.
    pub debuggable: bool,
    /// `android:allowBackup` (None = unspecified).
    pub allow_backup: Option<bool>,
    /// `android:usesCleartextTraffic` (None = unspecified).
    pub cleartext: Option<bool>,
    /// Has a network security config.
    pub network_security_config: bool,
    /// Application class.
    pub application_class: Option<String>,
    /// Components.
    pub components: Vec<Component>,
}

fn qualify(pkg: &str, name: &str) -> String {
    if name.starts_with('.') {
        format!("{pkg}{name}")
    } else if !name.contains('.') && !pkg.is_empty() {
        format!("{pkg}.{name}")
    } else {
        name.to_string()
    }
}

impl Manifest {
    /// Extract the security-relevant model from a decoded manifest.
    pub fn from_xml(root: &Element) -> Manifest {
        let mut m = Manifest {
            package: root.attr("package").unwrap_or("").to_string(),
            version_code: root.attr("versionCode").unwrap_or("").to_string(),
            version_name: root.attr("versionName").unwrap_or("").to_string(),
            ..Default::default()
        };
        if let Some(sdk) = root.find_all("uses-sdk").first() {
            m.min_sdk = sdk.attr("minSdkVersion").and_then(|v| v.parse().ok());
            m.target_sdk = sdk.attr("targetSdkVersion").and_then(|v| v.parse().ok());
        }
        for tag in ["uses-permission", "uses-permission-sdk-23"] {
            for p in root.find_all(tag) {
                if let Some(n) = p.attr("name") {
                    m.permissions.push(n.to_string());
                }
            }
        }
        for p in root.find_all("permission") {
            if let Some(n) = p.attr("name") {
                m.defined_permissions.push((
                    n.to_string(),
                    p.attr("protectionLevel").unwrap_or("normal").to_string(),
                ));
            }
        }
        let target = m.target_sdk.unwrap_or(m.min_sdk.unwrap_or(1));
        if let Some(app) = root.find_all("application").first() {
            m.debuggable = app.attr("debuggable") == Some("true");
            m.allow_backup = app.attr("allowBackup").map(|v| v == "true");
            m.cleartext = app.attr("usesCleartextTraffic").map(|v| v == "true");
            m.network_security_config = app.attr("networkSecurityConfig").is_some();
            m.application_class = app.attr("name").map(|n| qualify(&m.package, n));
            for kind in [
                "activity",
                "activity-alias",
                "service",
                "receiver",
                "provider",
            ] {
                for c in app.find_all(kind) {
                    let filters = c.find_all("intent-filter");
                    let explicit = c.attr("exported").map(|v| v == "true");
                    let implicit = match kind {
                        "provider" => target < 17,
                        _ => !filters.is_empty() && target < 31,
                    };
                    let mut actions = Vec::new();
                    let mut links = Vec::new();
                    for f in &filters {
                        for a in f.find_all("action") {
                            if let Some(n) = a.attr("name") {
                                actions.push(n.to_string());
                            }
                        }
                        for d in f.find_all("data") {
                            if let Some(s) = d.attr("scheme") {
                                let host = d.attr("host").unwrap_or("*");
                                let path = d
                                    .attr("path")
                                    .or(d.attr("pathPrefix"))
                                    .or(d.attr("pathPattern"))
                                    .unwrap_or("");
                                links.push(format!("{s}://{host}{path}"));
                            }
                        }
                    }
                    m.components.push(Component {
                        kind: kind.to_string(),
                        name: qualify(&m.package, c.attr("name").unwrap_or("?")),
                        exported: explicit.unwrap_or(implicit),
                        implicit_export: explicit.is_none() && implicit,
                        permission: c.attr("permission").map(str::to_string),
                        actions,
                        deep_links: links,
                    });
                }
            }
        }
        m
    }
}

/// Build a small binary-XML document (used by tests and the `labs/` generator).
#[doc(hidden)]
pub mod builder {
    /// Minimal AXML writer: UTF-16 string pool, android namespace, elements with typed attributes.
    pub struct AxmlBuilder {
        strings: Vec<String>,
        body: Vec<u8>,
    }

    /// Attribute value for the builder.
    pub enum Val<'a> {
        /// String.
        Str(&'a str),
        /// Decimal integer.
        Int(i32),
        /// Boolean.
        Bool(bool),
    }

    impl Default for AxmlBuilder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl AxmlBuilder {
        /// New document with the android namespace declared.
        pub fn new() -> Self {
            let mut b = Self {
                strings: Vec::new(),
                body: Vec::new(),
            };
            let p = b.idx("android");
            let u = b.idx(super::ANDROID_NS);
            b.node(0x0100, &[p, u]);
            b
        }
        fn idx(&mut self, s: &str) -> u32 {
            if let Some(i) = self.strings.iter().position(|x| x == s) {
                return i as u32;
            }
            self.strings.push(s.to_string());
            (self.strings.len() - 1) as u32
        }
        fn node(&mut self, ty: u16, ext: &[u32]) {
            let size = 16 + ext.len() * 4;
            self.body.extend(ty.to_le_bytes());
            self.body.extend(16u16.to_le_bytes());
            self.body.extend((size as u32).to_le_bytes());
            self.body.extend(1u32.to_le_bytes()); // line
            self.body.extend(u32::MAX.to_le_bytes()); // comment
            for e in ext {
                self.body.extend(e.to_le_bytes());
            }
        }
        /// Open an element. Attribute names are in the android namespace unless prefixed with `!`.
        pub fn start(&mut self, name: &str, attrs: &[(&str, Val)]) -> &mut Self {
            let ns_uri = self.idx(super::ANDROID_NS);
            let n = self.idx(name);
            let mut a = Vec::new();
            for (k, v) in attrs {
                let (ns, k) = match k.strip_prefix('!') {
                    Some(k) => (u32::MAX, k),
                    None => (ns_uri, *k),
                };
                let kn = self.idx(k);
                let (raw, ty, data) = match v {
                    Val::Str(s) => {
                        let i = self.idx(s);
                        (i, 0x03u8, i)
                    }
                    Val::Int(i) => (u32::MAX, 0x10, *i as u32),
                    Val::Bool(b) => (u32::MAX, 0x12, if *b { u32::MAX } else { 0 }),
                };
                a.push((ns, kn, raw, ty, data));
            }
            let size = 16 + 20 + a.len() * 20;
            self.body.extend(0x0102u16.to_le_bytes());
            self.body.extend(16u16.to_le_bytes());
            self.body.extend((size as u32).to_le_bytes());
            self.body.extend(1u32.to_le_bytes());
            self.body.extend(u32::MAX.to_le_bytes());
            self.body.extend(u32::MAX.to_le_bytes()); // ns
            self.body.extend(n.to_le_bytes());
            self.body.extend(20u16.to_le_bytes()); // attributeStart
            self.body.extend(20u16.to_le_bytes()); // attributeSize
            self.body.extend((a.len() as u16).to_le_bytes());
            self.body.extend([0u8; 6]);
            for (ns, kn, raw, ty, data) in a {
                self.body.extend(ns.to_le_bytes());
                self.body.extend(kn.to_le_bytes());
                self.body.extend(raw.to_le_bytes());
                self.body.extend(8u16.to_le_bytes());
                self.body.push(0);
                self.body.push(ty);
                self.body.extend(data.to_le_bytes());
            }
            self
        }
        /// Close an element.
        pub fn end(&mut self, name: &str) -> &mut Self {
            let n = self.idx(name);
            self.node(0x0103, &[u32::MAX, n]);
            self
        }
        /// Finish and serialise.
        pub fn finish(&self) -> Vec<u8> {
            let mut pool_strings = Vec::new();
            let mut offsets = Vec::new();
            for s in &self.strings {
                offsets.push(pool_strings.len() as u32);
                let units: Vec<u16> = s.encode_utf16().collect();
                pool_strings.extend((units.len() as u16).to_le_bytes());
                for u in units {
                    pool_strings.extend(u.to_le_bytes());
                }
                pool_strings.extend([0, 0]);
            }
            while pool_strings.len() % 4 != 0 {
                pool_strings.push(0);
            }
            let header = 28usize;
            let strings_start = header + offsets.len() * 4;
            let pool_size = strings_start + pool_strings.len();
            let mut pool = Vec::new();
            pool.extend(0x0001u16.to_le_bytes());
            pool.extend((header as u16).to_le_bytes());
            pool.extend((pool_size as u32).to_le_bytes());
            pool.extend((offsets.len() as u32).to_le_bytes());
            pool.extend(0u32.to_le_bytes());
            pool.extend(0u32.to_le_bytes()); // flags: UTF-16
            pool.extend((strings_start as u32).to_le_bytes());
            pool.extend(0u32.to_le_bytes());
            for o in offsets {
                pool.extend(o.to_le_bytes());
            }
            pool.extend(pool_strings);
            let total = 8 + pool.len() + self.body.len();
            let mut out = Vec::new();
            out.extend(0x0003u16.to_le_bytes());
            out.extend(8u16.to_le_bytes());
            out.extend((total as u32).to_le_bytes());
            out.extend(pool);
            out.extend(&self.body);
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::builder::{AxmlBuilder, Val};
    use super::*;

    pub(crate) fn sample_manifest() -> Vec<u8> {
        let mut b = AxmlBuilder::new();
        b.start(
            "manifest",
            &[
                ("!package", Val::Str("com.example.rexlab")),
                ("versionCode", Val::Int(7)),
                ("versionName", Val::Str("1.2.3")),
            ],
        )
        .start(
            "uses-sdk",
            &[
                ("minSdkVersion", Val::Int(21)),
                ("targetSdkVersion", Val::Int(29)),
            ],
        )
        .end("uses-sdk")
        .start(
            "uses-permission",
            &[("name", Val::Str("android.permission.INTERNET"))],
        )
        .end("uses-permission")
        .start(
            "uses-permission",
            &[("name", Val::Str("android.permission.READ_SMS"))],
        )
        .end("uses-permission")
        .start(
            "application",
            &[
                ("debuggable", Val::Bool(true)),
                ("usesCleartextTraffic", Val::Bool(true)),
                ("name", Val::Str(".App")),
            ],
        )
        .start("activity", &[("name", Val::Str(".MainActivity"))])
        .start("intent-filter", &[])
        .start(
            "action",
            &[("name", Val::Str("android.intent.action.VIEW"))],
        )
        .end("action")
        .start(
            "data",
            &[("scheme", Val::Str("rexlab")), ("host", Val::Str("open"))],
        )
        .end("data")
        .end("intent-filter")
        .end("activity")
        .start(
            "service",
            &[
                ("name", Val::Str(".SyncService")),
                ("exported", Val::Bool(false)),
            ],
        )
        .end("service")
        .start(
            "provider",
            &[
                ("name", Val::Str(".Files")),
                ("exported", Val::Bool(true)),
                ("authorities", Val::Str("com.example.rexlab.files")),
            ],
        )
        .end("provider")
        .end("application")
        .end("manifest");
        b.finish()
    }

    #[test]
    fn roundtrip_manifest() {
        let data = sample_manifest();
        assert_eq!(
            rex_core::detect_bytes(&data, None),
            rex_core::ArtifactKind::AndroidBinaryXml
        );
        let root = parse(&data).unwrap();
        assert_eq!(root.name, "manifest");
        let xml = root.to_xml();
        assert!(xml.contains("android:versionName=\"1.2.3\""), "{xml}");
        assert!(xml.contains("xmlns:android="));
        let m = Manifest::from_xml(&root);
        assert_eq!(m.package, "com.example.rexlab");
        assert_eq!(m.version_code, "7");
        assert_eq!(m.target_sdk, Some(29));
        assert!(m.debuggable);
        assert_eq!(m.cleartext, Some(true));
        assert_eq!(
            m.application_class.as_deref(),
            Some("com.example.rexlab.App")
        );
        let main = m.components.iter().find(|c| c.kind == "activity").unwrap();
        assert!(
            main.exported && main.implicit_export,
            "intent filter + targetSdk 29"
        );
        assert_eq!(main.deep_links, vec!["rexlab://open"]);
        assert!(
            !m.components
                .iter()
                .find(|c| c.kind == "service")
                .unwrap()
                .exported
        );
        assert!(
            m.components
                .iter()
                .find(|c| c.kind == "provider")
                .unwrap()
                .exported
        );
        assert_eq!(m.permissions.len(), 2);
    }

    #[test]
    fn truncated_is_error_not_panic() {
        let data = sample_manifest();
        for cut in (0..data.len()).step_by(7) {
            let _ = parse(&data[..cut]);
        }
        assert!(parse(b"\x03\x00\x08\x00\xff\xff\xff\xff").is_err());
    }
}
