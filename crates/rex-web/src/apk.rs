//! Android APK analysis: manifest, code, native libraries, signing, frameworks.
//!
//! An APK is a zip file with a known layout. Analogy: a shipping container
//! with a manifest taped to the door. `AndroidManifest.xml` tells you what
//! the app *claims* (permissions, entry points), `classes*.dex` is what it
//! *does*, and `lib/<abi>/*.so` is native code that DEX analysis can't see.

use crate::axml::{self, Manifest};
use crate::dex::{self, ApiHit};
use rex_core::{Error, Result};
use serde::Serialize;
use std::io::{Cursor, Read};

const MAX_ENTRY: u64 = 256 << 20; // zip-bomb guard per entry

/// One zip entry.
#[derive(Debug, Clone, Serialize)]
pub struct Entry {
    /// Path inside the archive.
    pub name: String,
    /// Uncompressed size.
    pub size: u64,
    /// Compressed size.
    pub compressed: u64,
}

/// A native library and its hardening.
#[derive(Debug, Clone, Serialize)]
pub struct NativeLib {
    /// ABI directory (`arm64-v8a`).
    pub abi: String,
    /// File name.
    pub name: String,
    /// Size.
    pub size: u64,
    /// Mitigations: (name, status label).
    pub mitigations: Vec<(String, String)>,
    /// Interesting imports (exec, dlopen, ptrace …).
    pub notable_imports: Vec<String>,
}

/// Analysis result.
#[derive(Debug, Clone, Serialize)]
pub struct Apk {
    /// Entries.
    pub entries: Vec<Entry>,
    /// Decoded manifest XML.
    pub manifest_xml: Option<String>,
    /// Manifest model.
    pub manifest: Option<Manifest>,
    /// DEX files: (name, classes, methods refs, checksum ok).
    pub dex_files: Vec<(String, usize, usize, bool)>,
    /// Risky API usage across all DEX files.
    pub apis: Vec<ApiHit>,
    /// Classes implementing custom TLS trust.
    pub custom_trust: Vec<String>,
    /// Top packages.
    pub packages: Vec<(String, usize)>,
    /// Fraction of classes with ≤ 2-character names (obfuscation).
    pub obfuscation_ratio: f64,
    /// Interesting DEX strings: (category, value).
    pub strings: Vec<(String, String)>,
    /// Native libraries.
    pub native_libs: Vec<NativeLib>,
    /// Signing schemes detected.
    pub signing: Vec<String>,
    /// Signed with the Android debug certificate.
    pub debug_cert: bool,
    /// Frameworks (Flutter, React Native, Xamarin, Unity, Cordova …).
    pub frameworks: Vec<String>,
    /// Files likely to contain configuration or secrets.
    pub config_files: Vec<String>,
    /// JavaScript bundle (React Native / Cordova) analysis summary.
    pub js_bundle: Option<crate::js::JsReport>,
}

fn read_entry(z: &mut zip::ZipArchive<Cursor<&[u8]>>, i: usize) -> Option<Vec<u8>> {
    let f = z.by_index(i).ok()?;
    let mut out = Vec::new();
    f.take(MAX_ENTRY).read_to_end(&mut out).ok()?;
    Some(out)
}

/// Analyse an APK held in memory.
pub fn analyze(data: &[u8]) -> Result<Apk> {
    let mut z =
        zip::ZipArchive::new(Cursor::new(data)).map_err(|e| Error::parse("APK", e.to_string()))?;
    let mut entries = Vec::new();
    for i in 0..z.len() {
        if let Ok(f) = z.by_index(i) {
            let name = f.name().map(|n| n.to_string()).unwrap_or_default();
            entries.push(Entry {
                name,
                size: f.size(),
                compressed: f.compressed_size(),
            });
        }
    }
    let idx = |name: &str, entries: &[Entry]| entries.iter().position(|e| e.name == name);

    let mut apk = Apk {
        entries: Vec::new(),
        manifest_xml: None,
        manifest: None,
        dex_files: Vec::new(),
        apis: Vec::new(),
        custom_trust: Vec::new(),
        packages: Vec::new(),
        obfuscation_ratio: 0.0,
        strings: Vec::new(),
        native_libs: Vec::new(),
        signing: Vec::new(),
        debug_cert: false,
        frameworks: Vec::new(),
        config_files: Vec::new(),
        js_bundle: None,
    };

    if let Some(i) = idx("AndroidManifest.xml", &entries) {
        if let Some(bytes) = read_entry(&mut z, i) {
            if let Ok(root) = axml::parse(&bytes) {
                apk.manifest_xml = Some(root.to_xml());
                apk.manifest = Some(Manifest::from_xml(&root));
            } else if bytes.starts_with(b"<?xml") || bytes.starts_with(b"<manifest") {
                apk.manifest_xml = Some(String::from_utf8_lossy(&bytes).into_owned());
            }
        }
    }

    // DEX
    let mut all_hits: Vec<ApiHit> = Vec::new();
    let mut packages: std::collections::BTreeMap<String, usize> = Default::default();
    let mut short_names = 0.0;
    let mut total_classes = 0usize;
    let mut seen_strings = std::collections::BTreeSet::new();
    for (i, e) in entries.iter().enumerate() {
        let is_dex =
            e.name.starts_with("classes") && e.name.ends_with(".dex") && !e.name.contains('/');
        if !is_dex {
            continue;
        }
        let Some(bytes) = read_entry(&mut z, i) else {
            continue;
        };
        let Ok(d) = dex::parse(&bytes) else { continue };
        apk.dex_files.push((
            e.name.clone(),
            d.classes.len(),
            d.methods.len(),
            d.checksum_ok,
        ));
        for h in dex::risky_apis(&d) {
            match all_hits.iter_mut().find(|x| x.id == h.id) {
                Some(x) => {
                    x.refs.extend(h.refs);
                    x.refs.sort();
                    x.refs.dedup();
                }
                None => all_hits.push(h),
            }
        }
        apk.custom_trust.extend(dex::custom_trust(&d));
        let (pk, ratio) = dex::package_stats(&d, 3);
        for (p, n) in pk {
            *packages.entry(p).or_default() += n;
        }
        short_names += ratio * d.classes.len() as f64;
        total_classes += d.classes.len();
        for s in &d.strings {
            if s.len() < 6 || s.len() > 300 || seen_strings.len() > 5000 {
                continue;
            }
            let cat = rex_binary::strings::classify(s);
            use rex_binary::strings::Category::*;
            if matches!(cat, Url | Ip | Secret | Command | Email) && seen_strings.insert(s.clone())
            {
                apk.strings.push((cat.as_str().to_string(), s.clone()));
            }
            let lower = s.to_ascii_lowercase();
            if [
                "/system/xbin/su",
                "superuser.apk",
                "com.topjohnwu.magisk",
                "test-keys",
            ]
            .iter()
            .any(|k| lower.contains(k))
                && seen_strings.insert(format!("root:{s}"))
            {
                apk.strings.push(("root-detection".into(), s.clone()));
            }
            if ["goldfish", "ranchu", "generic_x86", "sdk_gphone"]
                .iter()
                .any(|k| lower == *k || lower.contains(&format!("/{k}")))
                && seen_strings.insert(format!("emu:{s}"))
            {
                apk.strings.push(("emulator-detection".into(), s.clone()));
            }
        }
    }
    apk.apis = all_hits;
    let mut pk: Vec<(String, usize)> = packages.into_iter().collect();
    pk.sort_by_key(|p| std::cmp::Reverse(p.1));
    pk.truncate(25);
    apk.packages = pk;
    apk.obfuscation_ratio = if total_classes > 0 {
        short_names / total_classes as f64
    } else {
        0.0
    };

    // Native libraries
    for (i, e) in entries.iter().enumerate() {
        let Some(rest) = e.name.strip_prefix("lib/") else {
            continue;
        };
        let Some((abi, name)) = rest.split_once('/') else {
            continue;
        };
        if !name.ends_with(".so") {
            continue;
        }
        let mut lib = NativeLib {
            abi: abi.into(),
            name: name.into(),
            size: e.size,
            mitigations: vec![],
            notable_imports: vec![],
        };
        if let Some(bytes) = read_entry(&mut z, i) {
            if let Ok(b) = rex_binary::Binary::parse(&bytes) {
                lib.mitigations = b
                    .mitigations
                    .iter()
                    .map(|m| (m.name.to_string(), m.status.label().to_string()))
                    .collect();
                lib.notable_imports = b
                    .imports
                    .iter()
                    .map(|i| i.name.clone())
                    .filter(|n| {
                        matches!(
                            n.as_str(),
                            "execve"
                                | "execl"
                                | "system"
                                | "popen"
                                | "dlopen"
                                | "ptrace"
                                | "fork"
                                | "mprotect"
                                | "inotify_add_watch"
                        )
                    })
                    .collect();
            }
        }
        apk.native_libs.push(lib);
    }

    // Signing
    if entries.iter().any(|e| {
        e.name.starts_with("META-INF/")
            && (e.name.ends_with(".RSA") || e.name.ends_with(".DSA") || e.name.ends_with(".EC"))
    }) {
        apk.signing.push("v1 (JAR)".into());
        for (i, e) in entries.iter().enumerate() {
            if e.name.starts_with("META-INF/")
                && (e.name.ends_with(".RSA") || e.name.ends_with(".DSA") || e.name.ends_with(".EC"))
            {
                if let Some(b) = read_entry(&mut z, i) {
                    if memchr::memmem::find(&b, b"Android Debug").is_some() {
                        apk.debug_cert = true;
                    }
                }
            }
        }
    }
    if let Some(pos) = memchr::memmem::rfind(data, b"APK Sig Block 42") {
        let block = &data[pos.saturating_sub(1 << 20)..pos];
        let mut schemes = vec![];
        if memchr::memmem::find(block, &0x7109_871au32.to_le_bytes()).is_some() {
            schemes.push("v2");
        }
        if memchr::memmem::find(block, &0xf053_68c0u32.to_le_bytes()).is_some() {
            schemes.push("v3");
        }
        if memchr::memmem::find(block, &0x1b93_ad61u32.to_le_bytes()).is_some() {
            schemes.push("v3.1");
        }
        if schemes.is_empty() {
            schemes.push("v2+ (APK Signing Block)");
        }
        apk.signing.extend(schemes.into_iter().map(String::from));
        if memchr::memmem::find(block, b"Android Debug").is_some() {
            apk.debug_cert = true;
        }
    }

    // Frameworks
    let has = |p: &str| entries.iter().any(|e| e.name.contains(p));
    for (name, marker) in [
        ("Flutter", "libflutter.so"),
        ("React Native", "index.android.bundle"),
        ("React Native (Hermes)", "libhermes.so"),
        ("Xamarin / .NET", "assemblies/"),
        ("Unity", "libunity.so"),
        ("Unity IL2CPP", "libil2cpp.so"),
        ("Cordova / Capacitor", "assets/www/"),
        ("Kotlin", "kotlin/"),
        ("Jetpack Compose", "androidx.compose"),
        ("Firebase", "firebase-"),
    ] {
        if has(marker) {
            apk.frameworks.push(name.into());
        }
    }
    for e in &entries {
        let l = e.name.to_ascii_lowercase();
        if (l.starts_with("assets/") || l.starts_with("res/raw/"))
            && (l.ends_with(".json")
                || l.ends_with(".env")
                || l.ends_with(".properties")
                || l.ends_with(".yaml")
                || l.ends_with(".yml")
                || l.ends_with(".xml")
                || l.ends_with(".conf")
                || l.ends_with(".pem")
                || l.ends_with(".p12")
                || l.ends_with(".bks"))
        {
            apk.config_files.push(e.name.clone());
        }
    }
    if let Some(i) = idx("assets/index.android.bundle", &entries) {
        if let Some(b) = read_entry(&mut z, i) {
            if !b.starts_with(&[0xc6, 0x1f, 0xbc, 0x03]) {
                // Plain JS (not Hermes bytecode).
                apk.js_bundle = Some(crate::js::analyze(&String::from_utf8_lossy(&b)));
            }
        }
    }
    apk.entries = entries;
    Ok(apk)
}

/// Permissions that grant access to sensitive data or capabilities.
pub fn dangerous_permission(p: &str) -> Option<(rex_core::Severity, &'static str)> {
    use rex_core::Severity::*;
    let name = p.rsplit('.').next().unwrap_or(p);
    Some(match name {
        "SEND_SMS" | "RECEIVE_SMS" | "READ_SMS" | "RECEIVE_MMS" | "RECEIVE_WAP_PUSH" => {
            (High, "SMS access (premium fraud / OTP theft)")
        }
        "BIND_ACCESSIBILITY_SERVICE" => (
            High,
            "accessibility service (screen reading / input injection)",
        ),
        "BIND_DEVICE_ADMIN" => (High, "device admin"),
        "REQUEST_INSTALL_PACKAGES" => (Medium, "can install other apps"),
        "SYSTEM_ALERT_WINDOW" => (Medium, "overlays (phishing / tapjacking)"),
        "READ_CALL_LOG"
        | "WRITE_CALL_LOG"
        | "PROCESS_OUTGOING_CALLS"
        | "CALL_PHONE"
        | "ANSWER_PHONE_CALLS" => (Medium, "call access"),
        "READ_CONTACTS" | "WRITE_CONTACTS" | "GET_ACCOUNTS" => (Medium, "contacts / accounts"),
        "RECORD_AUDIO" => (Medium, "microphone"),
        "CAMERA" => (Low, "camera"),
        "ACCESS_FINE_LOCATION" | "ACCESS_BACKGROUND_LOCATION" => {
            (Medium, "precise / background location")
        }
        "ACCESS_COARSE_LOCATION" => (Low, "approximate location"),
        "READ_PHONE_STATE" | "READ_PHONE_NUMBERS" => (Low, "phone identity"),
        "MANAGE_EXTERNAL_STORAGE" | "READ_EXTERNAL_STORAGE" | "WRITE_EXTERNAL_STORAGE" => {
            (Low, "shared storage")
        }
        "QUERY_ALL_PACKAGES" => (Low, "enumerates installed apps"),
        "PACKAGE_USAGE_STATS" => (Medium, "app usage history"),
        "BIND_NOTIFICATION_LISTENER_SERVICE" => (High, "reads all notifications (OTP theft)"),
        "READ_MEDIA_IMAGES" | "READ_MEDIA_VIDEO" => (Low, "media library"),
        _ => return None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// Build a tiny APK in memory from the AXML/DEX builders.
    pub fn sample_apk() -> Vec<u8> {
        use crate::axml::builder::{AxmlBuilder, Val};
        let mut m = AxmlBuilder::new();
        m.start(
            "manifest",
            &[
                ("!package", Val::Str("com.example.rexlab")),
                ("versionCode", Val::Int(3)),
                ("versionName", Val::Str("0.3")),
            ],
        )
        .start(
            "uses-sdk",
            &[
                ("minSdkVersion", Val::Int(21)),
                ("targetSdkVersion", Val::Int(30)),
            ],
        )
        .end("uses-sdk")
        .start(
            "uses-permission",
            &[("name", Val::Str("android.permission.SEND_SMS"))],
        )
        .end("uses-permission")
        .start(
            "application",
            &[
                ("debuggable", Val::Bool(true)),
                ("allowBackup", Val::Bool(true)),
            ],
        )
        .start("receiver", &[("name", Val::Str(".BootReceiver"))])
        .start("intent-filter", &[])
        .start(
            "action",
            &[("name", Val::Str("android.intent.action.BOOT_COMPLETED"))],
        )
        .end("action")
        .end("intent-filter")
        .end("receiver")
        .end("application")
        .end("manifest");
        let dex = crate::dex::builder::build(
            &[("Lcom/example/rexlab/Main;", "Landroid/app/Activity;", &[])],
            &[("Landroid/telephony/SmsManager;", "sendTextMessage")],
            &["http://10.0.2.2:8080/collect"],
        );
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("AndroidManifest.xml", opts).unwrap();
        w.write_all(&m.finish()).unwrap();
        w.start_file("classes.dex", opts).unwrap();
        w.write_all(&dex).unwrap();
        w.start_file("assets/config.json", opts).unwrap();
        w.write_all(br#"{"apiKey":"x"}"#).unwrap();
        w.start_file("META-INF/CERT.RSA", opts).unwrap();
        w.write_all(b"....CN=Android Debug, O=Android, C=US....")
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn analyzes_sample_apk() {
        let data = sample_apk();
        assert_eq!(
            rex_core::detect_bytes(&data, Some("x.apk")),
            rex_core::ArtifactKind::Apk
        );
        let apk = analyze(&data).unwrap();
        let m = apk.manifest.as_ref().unwrap();
        assert_eq!(m.package, "com.example.rexlab");
        assert!(m.debuggable);
        let recv = &m.components[0];
        assert!(recv.exported && recv.implicit_export);
        assert_eq!(apk.dex_files.len(), 1);
        assert!(apk.dex_files[0].3, "checksum ok");
        assert!(apk.apis.iter().any(|h| h.id == "APK-SMS-SEND"));
        assert!(
            apk.strings
                .iter()
                .any(|(c, s)| c == "url" && s.contains("10.0.2.2"))
        );
        assert!(apk.debug_cert);
        assert_eq!(apk.signing, vec!["v1 (JAR)"]);
        assert_eq!(apk.config_files, vec!["assets/config.json"]);
        assert!(dangerous_permission("android.permission.SEND_SMS").is_some());
    }

    #[test]
    fn rejects_non_zip() {
        assert!(analyze(b"not a zip").is_err());
    }
}
