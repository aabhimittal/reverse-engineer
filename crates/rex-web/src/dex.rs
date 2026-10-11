//! Dalvik Executable (DEX) parser and risk analysis.
//!
//! A DEX file is the compiled Java/Kotlin code of an Android app. Its layout
//! is a set of *ID tables* (strings, types, prototypes, fields, methods) that
//! everything else refers to by index. Analogy: a phone book. The class
//! definitions don't contain names, just entry numbers; resolving them
//! through the tables gives `Lcom/example/MainActivity;->onCreate`.
//!
//! The method-reference table is gold for triage: every API the app *calls*
//! (even in code paths you never trigger) is listed there.

use rex_core::{Error, Result, Severity};
use serde::Serialize;
use std::collections::BTreeMap;

/// A class definition.
#[derive(Debug, Clone, Serialize)]
pub struct Class {
    /// Java name (`com.example.Main`).
    pub name: String,
    /// Superclass Java name.
    pub superclass: String,
    /// Implemented interfaces (Java names).
    pub interfaces: Vec<String>,
    /// Source file attribute.
    pub source_file: Option<String>,
    /// Access flags.
    pub access: u32,
    /// Methods defined (direct + virtual).
    pub methods: u32,
}

/// A referenced method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct MethodRef {
    /// Declaring class descriptor (`Ljava/lang/Runtime;`).
    pub class: String,
    /// Method name.
    pub name: String,
}

/// A parsed DEX file.
#[derive(Debug, Clone, Serialize)]
pub struct Dex {
    /// Version string ("035", "039" …).
    pub version: String,
    /// Header checksum matches Adler-32 of the file.
    pub checksum_ok: bool,
    /// Header SHA-1 signature matches.
    pub signature_ok: bool,
    /// String table.
    #[serde(skip)]
    pub strings: Vec<String>,
    /// Type descriptors.
    #[serde(skip)]
    pub types: Vec<String>,
    /// Method references.
    #[serde(skip)]
    pub methods: Vec<MethodRef>,
    /// Defined classes.
    pub classes: Vec<Class>,
}

struct R<'a>(&'a [u8]);

impl R<'_> {
    fn u16(&self, o: usize) -> Result<u16> {
        self.0
            .get(o..o + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or_else(|| Error::parse("DEX", format!("truncated at {o:#x}")))
    }
    fn u32(&self, o: usize) -> Result<u32> {
        self.0
            .get(o..o + 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .ok_or_else(|| Error::parse("DEX", format!("truncated at {o:#x}")))
    }
    fn uleb(&self, o: &mut usize) -> Result<u32> {
        let mut v = 0u32;
        for i in 0..5 {
            let b = *self
                .0
                .get(*o)
                .ok_or_else(|| Error::parse("DEX", "truncated uleb128"))?;
            *o += 1;
            v |= ((b & 0x7f) as u32) << (7 * i);
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(Error::parse("DEX", "uleb128 too long"))
    }
}

/// Adler-32.
pub fn adler32(d: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in d.chunks(5552) {
        for &x in chunk {
            a += x as u32;
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

/// `Lcom/example/Foo;` → `com.example.Foo`; arrays/primitives pass through.
pub fn java_name(desc: &str) -> String {
    match desc.strip_prefix('L').and_then(|d| d.strip_suffix(';')) {
        Some(n) => n.replace('/', "."),
        None => desc.to_string(),
    }
}

fn mutf8(b: &[u8]) -> String {
    // Modified UTF-8 differs from UTF-8 only for NUL (C0 80) and surrogate pairs.
    let fixed: Vec<u8> = if b.windows(2).any(|w| w == [0xc0, 0x80]) {
        let mut v = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == 0xc0 && b.get(i + 1) == Some(&0x80) {
                v.push(0);
                i += 2;
            } else {
                v.push(b[i]);
                i += 1;
            }
        }
        v
    } else {
        b.to_vec()
    };
    String::from_utf8_lossy(&fixed).into_owned()
}

const MAX_TABLE: usize = 4_000_000;

/// Parse a DEX file.
pub fn parse(d: &[u8]) -> Result<Dex> {
    if !d.starts_with(b"dex\n") || d.len() < 0x70 {
        return Err(Error::parse("DEX", "bad magic or too short"));
    }
    let r = R(d);
    let version = String::from_utf8_lossy(&d[4..7]).into_owned();
    let checksum_ok = r.u32(8)? == adler32(&d[12..]);
    let signature_ok = d[12..32] == hex_to_bytes(&rex_core::hash::sha1_hex(&d[32..]))[..];
    let table = |size_off: usize| -> Result<(usize, usize)> {
        let n = r.u32(size_off)? as usize;
        let off = r.u32(size_off + 4)? as usize;
        if n > MAX_TABLE {
            return Err(Error::parse("DEX", "table too large"));
        }
        Ok((n, off))
    };
    let (ns, so) = table(0x38)?;
    let (nt, to) = table(0x40)?;
    let (nm, mo) = table(0x58)?;
    let (nc, co) = table(0x60)?;

    let mut strings = Vec::with_capacity(ns);
    for i in 0..ns {
        let mut p = r.u32(so + i * 4)? as usize;
        let _utf16_len = r.uleb(&mut p)?;
        let end = memchr::memchr(0, d.get(p..).unwrap_or(&[]))
            .map(|e| p + e)
            .unwrap_or(d.len());
        strings.push(mutf8(&d[p..end]));
    }
    let s = |i: u32| strings.get(i as usize).cloned().unwrap_or_default();
    let types: Vec<String> = (0..nt)
        .map(|i| r.u32(to + i * 4).map(s))
        .collect::<Result<_>>()?;
    let t = |i: u32| types.get(i as usize).cloned().unwrap_or_default();
    let methods: Vec<MethodRef> = (0..nm)
        .map(|i| {
            let base = mo + i * 8;
            Ok(MethodRef {
                class: t(r.u16(base)? as u32),
                name: s(r.u32(base + 4)?),
            })
        })
        .collect::<Result<_>>()?;
    let mut classes = Vec::with_capacity(nc);
    for i in 0..nc {
        let b = co + i * 32;
        let cls = r.u32(b)?;
        let access = r.u32(b + 4)?;
        let sup = r.u32(b + 8)?;
        let ifs = r.u32(b + 12)? as usize;
        let src = r.u32(b + 16)?;
        let data = r.u32(b + 24)? as usize;
        let mut interfaces = Vec::new();
        if ifs != 0 {
            let n = r.u32(ifs)? as usize;
            for k in 0..n.min(256) {
                interfaces.push(java_name(&t(r.u16(ifs + 4 + k * 2)? as u32)));
            }
        }
        let mut nmeth = 0;
        if data != 0 {
            let mut p = data;
            let _sf = r.uleb(&mut p)?;
            let _if = r.uleb(&mut p)?;
            let dm = r.uleb(&mut p)?;
            let vm = r.uleb(&mut p)?;
            nmeth = dm.saturating_add(vm);
        }
        classes.push(Class {
            name: java_name(&t(cls)),
            superclass: if sup == u32::MAX {
                String::new()
            } else {
                java_name(&t(sup))
            },
            interfaces,
            source_file: (src != u32::MAX).then(|| s(src)),
            access,
            methods: nmeth,
        });
    }
    Ok(Dex {
        version,
        checksum_ok,
        signature_ok,
        strings,
        types,
        methods,
        classes,
    })
}

fn hex_to_bytes(h: &str) -> Vec<u8> {
    (0..h.len() / 2)
        .filter_map(|i| u8::from_str_radix(&h[i * 2..i * 2 + 2], 16).ok())
        .collect()
}

/// A risky API usage pattern.
#[derive(Debug, Clone, Serialize)]
pub struct ApiHit {
    /// Rule id.
    pub id: &'static str,
    /// Description.
    pub what: &'static str,
    /// Severity.
    pub severity: Severity,
    /// ATT&CK for Mobile technique.
    pub attack: &'static str,
    /// Matched references.
    pub refs: Vec<String>,
}

type ApiRule = (
    &'static str,
    &'static str,
    Severity,
    &'static str,
    &'static [(&'static str, &'static str)],
);

/// (id, description, severity, technique, [(class descriptor, method or "*")]).
pub static API_RULES: &[ApiRule] = &[
    (
        "APK-DYNAMIC-CODE",
        "loads code at runtime (DexClassLoader)",
        Severity::Medium,
        "T1407",
        &[
            ("Ldalvik/system/DexClassLoader;", "<init>"),
            ("Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
            ("Ldalvik/system/PathClassLoader;", "<init>"),
        ],
    ),
    (
        "APK-EXEC",
        "executes shell commands",
        Severity::Medium,
        "T1623.001",
        &[
            ("Ljava/lang/Runtime;", "exec"),
            ("Ljava/lang/ProcessBuilder;", "start"),
        ],
    ),
    (
        "APK-SMS-SEND",
        "sends SMS messages",
        Severity::High,
        "T1582",
        &[
            ("Landroid/telephony/SmsManager;", "sendTextMessage"),
            ("Landroid/telephony/SmsManager;", "sendMultipartTextMessage"),
        ],
    ),
    (
        "APK-SMS-READ",
        "reads SMS content provider",
        Severity::High,
        "T1636.004",
        &[
            ("Landroid/provider/Telephony$Sms;", "*"),
            ("Landroid/telephony/SmsMessage;", "createFromPdu"),
        ],
    ),
    (
        "APK-WEBVIEW-JS-BRIDGE",
        "exposes Java objects to WebView JavaScript",
        Severity::Medium,
        "T1631",
        &[("Landroid/webkit/WebView;", "addJavascriptInterface")],
    ),
    (
        "APK-REFLECTION",
        "uses reflection to invoke methods",
        Severity::Low,
        "T1406",
        &[
            ("Ljava/lang/reflect/Method;", "invoke"),
            ("Ljava/lang/Class;", "forName"),
        ],
    ),
    (
        "APK-DEVICE-ID",
        "reads device identifiers (IMEI / phone number)",
        Severity::Medium,
        "T1426",
        &[
            ("Landroid/telephony/TelephonyManager;", "getDeviceId"),
            ("Landroid/telephony/TelephonyManager;", "getImei"),
            ("Landroid/telephony/TelephonyManager;", "getLine1Number"),
            ("Landroid/telephony/TelephonyManager;", "getSubscriberId"),
        ],
    ),
    (
        "APK-LOCATION",
        "accesses location",
        Severity::Low,
        "T1430",
        &[
            ("Landroid/location/LocationManager;", "getLastKnownLocation"),
            (
                "Landroid/location/LocationManager;",
                "requestLocationUpdates",
            ),
            (
                "Lcom/google/android/gms/location/FusedLocationProviderClient;",
                "*",
            ),
        ],
    ),
    (
        "APK-AUDIO-RECORD",
        "records audio",
        Severity::Medium,
        "T1429",
        &[
            ("Landroid/media/MediaRecorder;", "setAudioSource"),
            ("Landroid/media/AudioRecord;", "startRecording"),
        ],
    ),
    (
        "APK-CAMERA",
        "uses the camera",
        Severity::Low,
        "T1512",
        &[
            ("Landroid/hardware/Camera;", "open"),
            ("Landroid/hardware/camera2/CameraManager;", "openCamera"),
        ],
    ),
    (
        "APK-INSTALLED-APPS",
        "enumerates installed applications",
        Severity::Low,
        "T1418",
        &[
            (
                "Landroid/content/pm/PackageManager;",
                "getInstalledPackages",
            ),
            (
                "Landroid/content/pm/PackageManager;",
                "getInstalledApplications",
            ),
        ],
    ),
    (
        "APK-DEVICE-ADMIN",
        "uses device administration APIs",
        Severity::High,
        "T1626.001",
        &[
            ("Landroid/app/admin/DevicePolicyManager;", "lockNow"),
            ("Landroid/app/admin/DevicePolicyManager;", "resetPassword"),
            ("Landroid/app/admin/DevicePolicyManager;", "wipeData"),
        ],
    ),
    (
        "APK-OVERLAY",
        "draws overlays over other apps",
        Severity::Medium,
        "T1417.002",
        &[("Landroid/view/WindowManager;", "addView")],
    ),
    (
        "APK-CRYPTO",
        "uses javax.crypto ciphers",
        Severity::Info,
        "T1521",
        &[("Ljavax/crypto/Cipher;", "getInstance")],
    ),
    (
        "APK-NATIVE",
        "loads native libraries",
        Severity::Info,
        "T1575",
        &[
            ("Ljava/lang/System;", "loadLibrary"),
            ("Ljava/lang/System;", "load"),
        ],
    ),
    (
        "APK-CLIPBOARD",
        "reads the clipboard",
        Severity::Low,
        "T1414",
        &[("Landroid/content/ClipboardManager;", "getPrimaryClip")],
    ),
    (
        "APK-ACCESSIBILITY",
        "implements an accessibility service API",
        Severity::High,
        "T1453",
        &[
            ("Landroid/accessibilityservice/AccessibilityService;", "*"),
            (
                "Landroid/view/accessibility/AccessibilityNodeInfo;",
                "performAction",
            ),
        ],
    ),
    (
        "APK-CONTACTS",
        "queries contacts",
        Severity::Medium,
        "T1636.003",
        &[
            ("Landroid/provider/ContactsContract$Contacts;", "*"),
            (
                "Landroid/provider/ContactsContract$CommonDataKinds$Phone;",
                "*",
            ),
        ],
    ),
];

/// Match method references against [`API_RULES`].
pub fn risky_apis(dex: &Dex) -> Vec<ApiHit> {
    let mut out = Vec::new();
    for (id, what, sev, attack, pats) in API_RULES {
        let mut refs: Vec<String> = dex
            .methods
            .iter()
            .filter(|m| {
                pats.iter()
                    .any(|(c, n)| m.class == *c && (*n == "*" || m.name == *n))
            })
            .map(|m| format!("{}->{}", java_name(&m.class), m.name))
            .collect();
        // Subclassing counts too (e.g. extends AccessibilityService).
        for c in &dex.classes {
            for (cls, n) in pats.iter() {
                if *n == "*" && (java_name(cls) == c.superclass) {
                    refs.push(format!("{} extends {}", c.name, c.superclass));
                }
            }
        }
        refs.sort();
        refs.dedup();
        if !refs.is_empty() {
            out.push(ApiHit {
                id,
                what,
                severity: *sev,
                attack,
                refs,
            });
        }
    }
    out
}

/// Classes implementing TLS trust interfaces (frequent source of "accept all certificates" bugs).
pub fn custom_trust(dex: &Dex) -> Vec<String> {
    dex.classes
        .iter()
        .filter(|c| {
            c.interfaces.iter().any(|i| {
                i == "javax.net.ssl.X509TrustManager" || i == "javax.net.ssl.HostnameVerifier"
            }) && !c.name.starts_with("okhttp3.")
                && !c.name.starts_with("com.android.")
        })
        .map(|c| format!("{} implements {}", c.name, c.interfaces.join(", ")))
        .collect()
}

/// Package histogram (first `depth` components) and obfuscation ratio.
pub fn package_stats(dex: &Dex, depth: usize) -> (Vec<(String, usize)>, f64) {
    let mut hist: BTreeMap<String, usize> = BTreeMap::new();
    let mut short = 0usize;
    for c in &dex.classes {
        let parts: Vec<&str> = c.name.split('.').collect();
        let pkg = parts[..parts.len().saturating_sub(1)]
            .iter()
            .take(depth)
            .copied()
            .collect::<Vec<_>>()
            .join(".");
        *hist
            .entry(if pkg.is_empty() {
                "(default)".into()
            } else {
                pkg
            })
            .or_default() += 1;
        let simple = parts.last().copied().unwrap_or("");
        let simple = simple.split('$').next().unwrap_or(simple);
        if simple.len() <= 2 {
            short += 1;
        }
    }
    let mut v: Vec<(String, usize)> = hist.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let ratio = if dex.classes.is_empty() {
        0.0
    } else {
        short as f64 / dex.classes.len() as f64
    };
    (v, ratio)
}

/// Minimal DEX writer for tests and lab generation.
#[doc(hidden)]
pub mod builder {
    use super::adler32;

    fn uleb(v: u32, out: &mut Vec<u8>) {
        let mut v = v;
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }

    /// Build a DEX with the given classes (descriptor, super, interfaces), method refs
    /// (class descriptor, name) and extra strings. Produces a structurally valid file
    /// with correct checksum and signature (no code items).
    pub fn build(
        classes: &[(&str, &str, &[&str])],
        method_refs: &[(&str, &str)],
        extra_strings: &[&str],
    ) -> Vec<u8> {
        let mut strings: Vec<String> = Vec::new();
        let add = |s: &str, strings: &mut Vec<String>| {
            if !strings.iter().any(|x| x == s) {
                strings.push(s.to_string());
            }
        };
        for (c, sup, ifs) in classes {
            add(c, &mut strings);
            add(sup, &mut strings);
            for i in ifs.iter() {
                add(i, &mut strings);
            }
        }
        for (c, n) in method_refs {
            add(c, &mut strings);
            add(n, &mut strings);
        }
        add("V", &mut strings);
        for s in extra_strings {
            add(s, &mut strings);
        }
        strings.sort(); // DEX requires sorted strings
        let sidx = |s: &str| strings.iter().position(|x| x == s).expect("string") as u32;
        let mut types: Vec<String> = Vec::new();
        for (c, sup, ifs) in classes {
            for t in [c, sup].into_iter().chain(ifs.iter()) {
                if !types.contains(&t.to_string()) {
                    types.push(t.to_string());
                }
            }
        }
        for (c, _) in method_refs {
            if !types.contains(&c.to_string()) {
                types.push(c.to_string());
            }
        }
        if !types.contains(&"V".to_string()) {
            types.push("V".into());
        }
        types.sort_by_key(|t| sidx(t));
        let tidx = |t: &str| types.iter().position(|x| x == t).expect("type") as u16;

        let header = 0x70usize;
        let string_ids_off = header;
        let type_ids_off = string_ids_off + strings.len() * 4;
        let proto_ids_off = type_ids_off + types.len() * 4;
        let method_ids_off = proto_ids_off + 12;
        let class_defs_off = method_ids_off + method_refs.len() * 8;
        let data_off = class_defs_off + classes.len() * 32;

        let mut data = Vec::new();
        // interfaces type_lists
        let mut iface_offs = Vec::new();
        for (_, _, ifs) in classes {
            if ifs.is_empty() {
                iface_offs.push(0u32);
                continue;
            }
            while (data_off + data.len()) % 4 != 0 {
                data.push(0);
            }
            iface_offs.push((data_off + data.len()) as u32);
            data.extend((ifs.len() as u32).to_le_bytes());
            for i in ifs.iter() {
                data.extend(tidx(i).to_le_bytes());
            }
        }
        let mut string_data_offs = Vec::new();
        for s in &strings {
            string_data_offs.push((data_off + data.len()) as u32);
            uleb(s.encode_utf16().count() as u32, &mut data);
            data.extend(s.as_bytes());
            data.push(0);
        }
        let file_size = data_off + data.len();

        let mut out = vec![0u8; header];
        out[0..8].copy_from_slice(b"dex\n035\0");
        out[0x20..0x24].copy_from_slice(&(file_size as u32).to_le_bytes());
        out[0x24..0x28].copy_from_slice(&(header as u32).to_le_bytes());
        out[0x28..0x2c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let put = |out: &mut Vec<u8>, o: usize, n: usize, off: usize| {
            out[o..o + 4].copy_from_slice(&(n as u32).to_le_bytes());
            out[o + 4..o + 8].copy_from_slice(&(if n == 0 { 0 } else { off } as u32).to_le_bytes());
        };
        put(&mut out, 0x38, strings.len(), string_ids_off);
        put(&mut out, 0x40, types.len(), type_ids_off);
        put(&mut out, 0x48, 1, proto_ids_off);
        put(&mut out, 0x58, method_refs.len(), method_ids_off);
        put(&mut out, 0x60, classes.len(), class_defs_off);
        put(&mut out, 0x68, data.len(), data_off);
        for o in &string_data_offs {
            out.extend(o.to_le_bytes());
        }
        for t in &types {
            out.extend(sidx(t).to_le_bytes());
        }
        // one proto: ()V
        out.extend(sidx("V").to_le_bytes());
        out.extend((tidx("V") as u32).to_le_bytes());
        out.extend(0u32.to_le_bytes());
        for (c, n) in method_refs {
            out.extend(tidx(c).to_le_bytes());
            out.extend(0u16.to_le_bytes());
            out.extend(sidx(n).to_le_bytes());
        }
        for (i, (c, sup, _)) in classes.iter().enumerate() {
            out.extend((tidx(c) as u32).to_le_bytes());
            out.extend(1u32.to_le_bytes()); // public
            out.extend((tidx(sup) as u32).to_le_bytes());
            out.extend(iface_offs[i].to_le_bytes());
            out.extend(u32::MAX.to_le_bytes());
            out.extend([0u8; 12]);
        }
        out.extend(data);
        let sig = rex_core::hash::sha1_hex(&out[32..]);
        for i in 0..20 {
            out[12 + i] = u8::from_str_radix(&sig[i * 2..i * 2 + 2], 16).expect("hex");
        }
        let ck = adler32(&out[12..]);
        out[8..12].copy_from_slice(&ck.to_le_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn sample() -> Vec<u8> {
        let fake_key = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        builder::build(
            &[
                (
                    "Lcom/example/rexlab/MainActivity;",
                    "Landroid/app/Activity;",
                    &[],
                ),
                (
                    "Lcom/example/rexlab/a/b;",
                    "Ljava/lang/Object;",
                    &["Ljavax/net/ssl/X509TrustManager;"],
                ),
                (
                    "Lcom/example/rexlab/Spy;",
                    "Landroid/accessibilityservice/AccessibilityService;",
                    &[],
                ),
            ],
            &[
                ("Landroid/telephony/SmsManager;", "sendTextMessage"),
                ("Ldalvik/system/DexClassLoader;", "<init>"),
                ("Ljava/lang/Runtime;", "exec"),
            ],
            &["https://c2.example.net/api/report", &fake_key],
        )
    }

    #[test]
    fn parses_and_validates() {
        let d = sample();
        assert_eq!(
            rex_core::detect_bytes(&d, None),
            rex_core::ArtifactKind::Dex
        );
        let dex = parse(&d).unwrap();
        assert_eq!(dex.version, "035");
        assert!(dex.checksum_ok && dex.signature_ok);
        assert_eq!(dex.classes.len(), 3);
        let a = dex
            .classes
            .iter()
            .find(|c| c.name == "com.example.rexlab.a.b")
            .unwrap();
        assert_eq!(a.interfaces, vec!["javax.net.ssl.X509TrustManager"]);
        assert!(
            dex.strings
                .contains(&"https://c2.example.net/api/report".to_string())
        );

        let ids: Vec<&str> = risky_apis(&dex).iter().map(|h| h.id).collect();
        assert!(ids.contains(&"APK-SMS-SEND"));
        assert!(ids.contains(&"APK-DYNAMIC-CODE"));
        assert!(ids.contains(&"APK-EXEC"));
        assert!(ids.contains(&"APK-ACCESSIBILITY"), "via superclass");
        assert_eq!(custom_trust(&dex).len(), 1);
        let (pk, ratio) = package_stats(&dex, 3);
        assert_eq!(
            pk[0],
            ("com.example.rexlab".to_string(), 3),
            "a.b rolls up at depth 3"
        );
        assert!(ratio > 0.3);
    }

    #[test]
    fn detects_tampering_and_truncation() {
        let mut d = sample();
        let n = d.len();
        d[n - 3] ^= 1;
        let dex = parse(&d).unwrap();
        assert!(!dex.checksum_ok && !dex.signature_ok);
        for cut in (0..n).step_by(11) {
            let _ = parse(&d[..cut]);
        }
    }

    #[test]
    fn adler() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }
}
