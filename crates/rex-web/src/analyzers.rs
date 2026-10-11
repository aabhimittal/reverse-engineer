//! [`rex_core::Analyzer`] implementations for web traffic, JavaScript and Android.

use crate::{apk, audit, axml, dex, har, js, openapi, yaml};
use rex_core::{
    AnalysisOptions, Analyzer, AnalyzerOutput, Artifact, ArtifactKind, Finding, Location, Registry,
    Result, Section, Severity,
};

/// Register all web/mobile analyzers.
pub fn register(r: &mut Registry) {
    r.register(HarAnalyzer)
        .register(JsAnalyzer)
        .register(SourceMapAnalyzer)
        .register(ApkAnalyzer)
        .register(DexAnalyzer)
        .register(AxmlAnalyzer);
}

fn mask(s: &str) -> String {
    rex_binary::analyzers::redact(s)
}

// ───────────────────────────── HAR ─────────────────────────────

/// HAR → endpoints, OpenAPI and traffic audit.
pub struct HarAnalyzer;

impl Analyzer for HarAnalyzer {
    fn name(&self) -> &'static str {
        "web.har"
    }
    fn description(&self) -> &'static str {
        "HTTP Archive → endpoint inventory, inferred OpenAPI 3.1 spec and passive security audit"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Har
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let h = har::parse(a.data())?;
        let eps = har::extract(&h, &har::ExtractOptions::default());
        let spec = openapi::build(&h, &eps, None);
        let mut out = AnalyzerOutput::new();
        let hosts: std::collections::BTreeMap<String, usize> =
            h.log.entries.iter().fold(Default::default(), |mut m, e| {
                if let Some((_, host, _, _)) = har::split_url(&e.request.url) {
                    *m.entry(host).or_default() += 1;
                }
                m
            });
        out.section(Section::kv(
            "web.har.overview",
            "Traffic overview",
            [
                ("Requests".to_string(), h.log.entries.len().to_string()),
                ("Hosts".to_string(), hosts.len().to_string()),
                (
                    "API endpoints (templated)".to_string(),
                    eps.len().to_string(),
                ),
                (
                    "Captured with".to_string(),
                    h.log
                        .creator
                        .as_ref()
                        .map(|c| format!("{} {}", c.name, c.version))
                        .unwrap_or_default(),
                ),
            ],
        ));
        let mut host_rows: Vec<Vec<String>> = hosts
            .iter()
            .map(|(h, n)| vec![h.clone(), n.to_string()])
            .collect();
        host_rows.sort_by(|x, y| {
            y[1].parse::<usize>()
                .unwrap_or(0)
                .cmp(&x[1].parse::<usize>().unwrap_or(0))
        });
        out.section(Section::table(
            "web.har.hosts",
            "Hosts",
            &["host", "requests"],
            host_rows,
            opts.max_rows,
        ));
        let rows = eps
            .iter()
            .map(|e| {
                vec![
                    e.method.clone(),
                    e.path.clone(),
                    e.count.to_string(),
                    e.responses
                        .keys()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    e.query.keys().cloned().collect::<Vec<_>>().join(","),
                    e.auth
                        .iter()
                        .map(|a| a.split(':').next().unwrap_or(a).to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                ]
            })
            .collect();
        out.section(Section::table(
            "web.endpoints",
            "API endpoints",
            &["method", "path", "calls", "status", "query params", "auth"],
            rows,
            opts.max_rows.max(200),
        ));
        out.section(
            Section::code(
                "web.openapi",
                "Inferred OpenAPI 3.1 (rex web har2openapi -o api.yaml)",
                "yaml",
                yaml::to_yaml(&spec),
            )
            .with_data(&spec),
        );
        for f in audit::audit(&h) {
            out.finding(f);
        }
        Ok(out)
    }
}

// ───────────────────────────── JavaScript ─────────────────────────────

/// JS bundle analysis.
pub struct JsAnalyzer;

impl Analyzer for JsAnalyzer {
    fn name(&self) -> &'static str {
        "web.js"
    }
    fn description(&self) -> &'static str {
        "JavaScript bundle → API endpoints, secrets, frameworks, DOM sinks, internal hosts, source maps"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::JavaScript
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let src = String::from_utf8_lossy(a.data());
        let r = js::analyze(&src);
        Ok(js_output(&r, a.name(), opts))
    }
}

/// Render a [`js::JsReport`] as sections + findings (shared with APK bundle analysis).
pub fn js_output(r: &js::JsReport, file: &str, opts: &AnalysisOptions) -> AnalyzerOutput {
    let mut out = AnalyzerOutput::new();
    out.section(Section::kv(
        "web.js.overview",
        "Bundle overview",
        [
            ("Lines".to_string(), r.lines.to_string()),
            (
                "Frameworks".to_string(),
                r.frameworks.iter().copied().collect::<Vec<_>>().join(", "),
            ),
            ("URLs".to_string(), r.urls.len().to_string()),
            ("API paths".to_string(), r.paths.len().to_string()),
            ("HTTP call sites".to_string(), r.calls.len().to_string()),
            (
                "Source map".to_string(),
                match &r.source_map_url {
                    Some(u) if u.starts_with("data:") => "inline (data: URI)".into(),
                    Some(u) => u.clone(),
                    None => "none".into(),
                },
            ),
        ],
    ));
    let mut rows: Vec<Vec<String>> = r
        .calls
        .iter()
        .map(|(m, t)| vec![m.clone(), t.clone(), "call".into()])
        .collect();
    rows.extend(
        r.paths
            .iter()
            .filter(|p| !r.calls.iter().any(|(_, t)| t == *p))
            .map(|p| vec!["?".into(), p.clone(), "string".into()]),
    );
    rows.extend(
        r.graphql
            .iter()
            .map(|g| vec!["GRAPHQL".into(), g.clone(), "operation".into()]),
    );
    out.section(Section::table(
        "web.js.endpoints",
        "API endpoints referenced",
        &["method", "target", "source"],
        rows,
        opts.max_rows.max(200),
    ));
    out.section(Section::table(
        "web.js.urls",
        "Absolute URLs",
        &["url"],
        r.urls.iter().map(|u| vec![u.clone()]).collect(),
        opts.max_rows,
    ));
    if !r.env_vars.is_empty() {
        out.section(Section::table(
            "web.js.env",
            "Build-time environment variables",
            &["name"],
            r.env_vars.iter().map(|e| vec![e.clone()]).collect(),
            0,
        ));
    }
    let hi: Vec<&js::SecretHit> = r.secrets.iter().filter(|s| s.high).collect();
    let lo: Vec<&js::SecretHit> = r.secrets.iter().filter(|s| !s.high).collect();
    if !hi.is_empty() {
        out.finding(
            Finding::new("JS-SECRET", Severity::High, "secret", "Secret credentials shipped to the browser")
                .describe("Anything in a client bundle is public. Revoke and rotate these, then move them server-side.")
                .evidence_all(hi.iter().map(|s| format!("line {}: {}: {}", s.line, s.kind, mask(&s.value))))
                .attack("T1552.001")
                .at(Location { file: Some(file.into()), line: Some(hi[0].line), ..Default::default() }),
        );
    }
    if !lo.is_empty() {
        out.finding(
            Finding::new("JS-KEY", Severity::Low, "secret", "API keys / tokens in bundle (verify scope restrictions)")
                .describe("Browser-side keys (Google Maps, Firebase, Stripe publishable) are expected but must be restricted by referrer/domain.")
                .evidence_all(lo.iter().map(|s| format!("line {}: {}: {}", s.line, s.kind, mask(&s.value))))
                .at(Location { file: Some(file.into()), line: Some(lo[0].line), ..Default::default() }),
        );
    }
    if !r.internal_hosts.is_empty() {
        out.finding(
            Finding::new(
                "JS-INTERNAL-HOSTS",
                Severity::Low,
                "recon",
                "Internal / non-production hosts referenced",
            )
            .evidence_all(r.internal_hosts.iter().cloned()),
        );
    }
    let dangerous: Vec<String> = r
        .sinks
        .iter()
        .filter(|(s, _)| !matches!(*s, "postMessage("))
        .map(|(s, n)| format!("{s} ×{n}"))
        .collect();
    if !dangerous.is_empty() {
        out.finding(
            Finding::new(
                "JS-DOM-SINKS",
                Severity::Info,
                "dom-xss",
                "DOM XSS sinks present (review data flow into them)",
            )
            .evidence_all(dangerous),
        );
    }
    if let Some(u) = &r.source_map_url {
        out.finding(
            Finding::new("JS-SOURCEMAP", Severity::Low, "exposure", "Source map referenced: original source may be recoverable")
                .describe("Fetch the map and run `rex web sourcemap <map> -o src/` to rebuild the source tree.")
                .evidence(if u.starts_with("data:") { "inline data: URI".into() } else { u.clone() }),
        );
    }
    out
}

/// Source map → recovered file list.
pub struct SourceMapAnalyzer;

impl Analyzer for SourceMapAnalyzer {
    fn name(&self) -> &'static str {
        "web.sourcemap"
    }
    fn description(&self) -> &'static str {
        "JavaScript source map → original file tree (extract with `rex web sourcemap -o`)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::SourceMap
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let m = js::parse_source_map(a.data())?;
        let with_content = m.sources_content.iter().filter(|c| c.is_some()).count();
        let mut out = AnalyzerOutput::new();
        out.section(Section::kv(
            "web.sourcemap.overview",
            "Source map",
            [
                ("Sources".to_string(), m.sources.len().to_string()),
                (
                    "With embedded content".to_string(),
                    with_content.to_string(),
                ),
            ],
        ));
        let rows = m
            .sources
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let size = m
                    .sources_content
                    .get(i)
                    .and_then(|c| c.as_ref())
                    .map(|c| c.len().to_string())
                    .unwrap_or_else(|| "-".into());
                vec![s.clone(), size]
            })
            .collect();
        out.section(Section::table(
            "web.sourcemap.sources",
            "Original sources",
            &["path", "bytes"],
            rows,
            opts.max_rows.max(200),
        ));
        let mut combined = String::new();
        for c in m.sources_content.iter().flatten() {
            combined.push_str(c);
            combined.push('\n');
        }
        let r = js::analyze(&combined);
        if !r.secrets.is_empty() {
            out.finding(
                Finding::new(
                    "JS-SOURCEMAP-SECRET",
                    Severity::High,
                    "secret",
                    "Secrets in original sources",
                )
                .evidence_all(
                    r.secrets
                        .iter()
                        .map(|s| format!("{}: {}", s.kind, mask(&s.value))),
                ),
            );
        }
        if with_content > 0 {
            out.finding(Finding::new(
                "JS-SOURCEMAP-EXPOSED",
                Severity::Medium,
                "exposure",
                format!("{with_content} original source files exposed"),
            ));
        }
        Ok(out)
    }
}

// ───────────────────────────── Android ─────────────────────────────

/// Full APK analysis.
pub struct ApkAnalyzer;

impl Analyzer for ApkAnalyzer {
    fn name(&self) -> &'static str {
        "mobile.apk"
    }
    fn description(&self) -> &'static str {
        "Android APK → manifest, exported components, permissions, risky APIs, native lib hardening, signing"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Apk
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let x = apk::analyze(a.data())?;
        let mut out = AnalyzerOutput::new();
        let mut kv: Vec<(String, String)> = Vec::new();
        if let Some(m) = &x.manifest {
            kv.extend([
                ("Package".to_string(), m.package.clone()),
                (
                    "Version".to_string(),
                    format!("{} ({})", m.version_name, m.version_code),
                ),
                (
                    "SDK".to_string(),
                    format!("min {} / target {}", opt(m.min_sdk), opt(m.target_sdk)),
                ),
                (
                    "Application class".to_string(),
                    m.application_class.clone().unwrap_or_default(),
                ),
                ("Components".to_string(), m.components.len().to_string()),
                ("Permissions".to_string(), m.permissions.len().to_string()),
            ]);
        }
        kv.push((
            "DEX files".into(),
            x.dex_files
                .iter()
                .map(|d| format!("{} ({} classes)", d.0, d.1))
                .collect::<Vec<_>>()
                .join(", "),
        ));
        kv.push(("Native libraries".into(), x.native_libs.len().to_string()));
        kv.push((
            "Signing".into(),
            if x.signing.is_empty() {
                "unsigned".into()
            } else {
                x.signing.join(", ")
            },
        ));
        kv.push(("Frameworks".into(), x.frameworks.join(", ")));
        kv.push((
            "Obfuscation".into(),
            format!(
                "{:.0}% short class names{}",
                x.obfuscation_ratio * 100.0,
                if x.obfuscation_ratio > 0.4 {
                    " (likely R8/ProGuard)"
                } else {
                    ""
                }
            ),
        ));
        out.section(Section::kv("mobile.apk.overview", "APK overview", kv).with_data(&x));

        if let Some(m) = &x.manifest {
            let rows = m
                .components
                .iter()
                .map(|c| {
                    vec![
                        c.kind.clone(),
                        c.name.clone(),
                        if c.exported {
                            if c.implicit_export {
                                "yes (implicit)".into()
                            } else {
                                "yes".into()
                            }
                        } else {
                            "no".into()
                        },
                        c.permission.clone().unwrap_or_default(),
                        c.actions
                            .iter()
                            .map(|a| a.rsplit('.').next().unwrap_or(a).to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        c.deep_links.join(" "),
                    ]
                })
                .collect();
            out.section(Section::table(
                "mobile.components",
                "Components",
                &[
                    "kind",
                    "name",
                    "exported",
                    "permission",
                    "actions",
                    "deep links",
                ],
                rows,
                opts.max_rows.max(100),
            ));
            let rows = m
                .permissions
                .iter()
                .map(|p| {
                    let (sev, why) = apk::dangerous_permission(p)
                        .map(|(s, w)| (s.to_string(), w.to_string()))
                        .unwrap_or_default();
                    vec![p.clone(), sev, why]
                })
                .collect();
            out.section(Section::table(
                "mobile.permissions",
                "Permissions",
                &["permission", "risk", "why"],
                rows,
                0,
            ));
            manifest_findings(m, &mut out);
        }
        if let Some(xml) = &x.manifest_xml {
            out.section(Section::code(
                "mobile.manifest",
                "AndroidManifest.xml (decoded)",
                "xml",
                xml.clone(),
            ));
        }
        let rows = x
            .apis
            .iter()
            .map(|h| {
                vec![
                    h.severity.to_string(),
                    h.what.to_string(),
                    h.attack.to_string(),
                    h.refs
                        .iter()
                        .take(3)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("; "),
                ]
            })
            .collect();
        out.section(Section::table(
            "mobile.apis",
            "Risky API usage (DEX)",
            &["severity", "behaviour", "ATT&CK", "references"],
            rows,
            0,
        ));
        for h in &x.apis {
            out.finding(
                Finding::new(h.id, h.severity, "capability", h.what)
                    .evidence_all(h.refs.iter().take(10).cloned())
                    .attack(h.attack),
            );
        }
        if !x.custom_trust.is_empty() {
            out.finding(
                Finding::new("APK-CUSTOM-TRUST", Severity::Medium, "tls", "Custom TLS TrustManager / HostnameVerifier")
                    .describe("Frequently implemented as 'trust everything', which defeats TLS. Inspect checkServerTrusted / verify.")
                    .evidence_all(x.custom_trust.iter().cloned()),
            );
        }
        if !x.strings.is_empty() {
            out.section(Section::table(
                "mobile.strings",
                "Interesting strings (DEX)",
                &["category", "value"],
                x.strings
                    .iter()
                    .map(|(c, v)| vec![c.clone(), if c == "secret" { mask(v) } else { v.clone() }])
                    .collect(),
                opts.max_rows.max(100),
            ));
            let secrets: Vec<_> = x.strings.iter().filter(|(c, _)| c == "secret").collect();
            if !secrets.is_empty() {
                out.finding(
                    Finding::new(
                        "APK-HARDCODED-SECRET",
                        Severity::High,
                        "secret",
                        "Hard-coded credentials in DEX",
                    )
                    .evidence_all(secrets.iter().map(|(_, v)| mask(v))),
                );
            }
        }
        if !x.native_libs.is_empty() {
            let rows = x
                .native_libs
                .iter()
                .map(|l| {
                    let get = |n: &str| {
                        l.mitigations
                            .iter()
                            .find(|(k, _)| k == n)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_default()
                    };
                    vec![
                        l.abi.clone(),
                        l.name.clone(),
                        l.size.to_string(),
                        get("NX"),
                        get("RELRO"),
                        get("Stack canary"),
                        l.notable_imports.join(","),
                    ]
                })
                .collect();
            out.section(Section::table(
                "mobile.native",
                "Native libraries",
                &[
                    "abi",
                    "library",
                    "size",
                    "NX",
                    "RELRO",
                    "canary",
                    "notable imports",
                ],
                rows,
                opts.max_rows,
            ));
        }
        if x.debug_cert {
            out.finding(
                Finding::new("APK-DEBUG-CERT", Severity::High, "signing", "Signed with the Android debug certificate")
                    .describe("Debug builds should never ship: the debug key is public, so anyone can sign 'updates'."),
            );
        }
        if x.signing.is_empty() {
            out.finding(Finding::new(
                "APK-UNSIGNED",
                Severity::Medium,
                "signing",
                "APK is not signed",
            ));
        }
        if !x.config_files.is_empty() {
            out.finding(
                Finding::new(
                    "APK-CONFIG-FILES",
                    Severity::Info,
                    "recon",
                    "Bundled configuration files (check for secrets / endpoints)",
                )
                .evidence_all(x.config_files.iter().cloned()),
            );
        }
        if let Some(js) = &x.js_bundle {
            let o = js_output(js, "assets/index.android.bundle", opts);
            for mut s in o.sections {
                s.id = format!("mobile.rn.{}", s.id);
                s.title = format!("React Native bundle: {}", s.title);
                out.section(s);
            }
            for f in o.findings {
                out.finding(f);
            }
        }
        Ok(out)
    }
}

fn opt(v: Option<u32>) -> String {
    v.map(|v| v.to_string()).unwrap_or_else(|| "?".into())
}

fn manifest_findings(m: &axml::Manifest, out: &mut AnalyzerOutput) {
    if m.debuggable {
        out.finding(
            Finding::new(
                "APK-DEBUGGABLE",
                Severity::High,
                "manifest",
                "android:debuggable=\"true\"",
            )
            .describe(
                "Any user with ADB can attach a debugger, read app data and run code as the app.",
            ),
        );
    }
    if m.allow_backup != Some(false) && m.target_sdk.unwrap_or(0) < 31 {
        out.finding(
            Finding::new("APK-ALLOW-BACKUP", Severity::Low, "manifest", "App data can be extracted via adb backup")
                .describe("allowBackup is true or unset (defaults to true). Set it to false or define backup rules."),
        );
    }
    if m.cleartext == Some(true)
        || (m.cleartext.is_none() && m.target_sdk.unwrap_or(0) < 28 && !m.network_security_config)
    {
        out.finding(
            Finding::new(
                "APK-CLEARTEXT",
                Severity::Medium,
                "manifest",
                "Cleartext HTTP traffic permitted",
            )
            .describe(
                "usesCleartextTraffic=true, or targetSdk < 28 without a network security config.",
            ),
        );
    }
    let exported: Vec<&axml::Component> = m
        .components
        .iter()
        .filter(|c| {
            c.exported
                && c.permission.is_none()
                && !c.actions.iter().any(|a| a == "android.intent.action.MAIN")
        })
        .collect();
    if !exported.is_empty() {
        out.finding(
            Finding::new("APK-EXPORTED", Severity::Medium, "manifest", format!("{} exported component(s) without permission", exported.len()))
                .describe("Other apps can start/bind/query these. Validate all intent input or protect with a signature permission.")
                .evidence_all(exported.iter().map(|c| format!("{} {}{}", c.kind, c.name, if c.implicit_export { " (implicit)" } else { "" }))),
        );
    }
    let links: Vec<String> = m
        .components
        .iter()
        .flat_map(|c| c.deep_links.iter().cloned())
        .collect();
    if !links.is_empty() {
        out.finding(
            Finding::new(
                "APK-DEEP-LINKS",
                Severity::Info,
                "attack-surface",
                "Deep links registered",
            )
            .evidence_all(links),
        );
    }
    let mut dangerous: Vec<(Severity, String)> = m
        .permissions
        .iter()
        .filter_map(|p| apk::dangerous_permission(p).map(|(s, w)| (s, format!("{p}: {w}"))))
        .collect();
    dangerous.sort_by_key(|d| std::cmp::Reverse(d.0));
    if let Some(top) = dangerous.first().map(|d| d.0) {
        out.finding(
            Finding::new(
                "APK-DANGEROUS-PERMISSIONS",
                top,
                "permissions",
                format!("{} sensitive permission(s) requested", dangerous.len()),
            )
            .evidence_all(dangerous.into_iter().map(|d| d.1)),
        );
    }
    for (name, level) in &m.defined_permissions {
        if level.contains("normal") || level == "0" {
            out.finding(
                Finding::new(
                    "APK-WEAK-CUSTOM-PERMISSION",
                    Severity::Low,
                    "permissions",
                    "Custom permission with normal protection level",
                )
                .evidence(format!("{name} ({level})")),
            );
        }
    }
    if m.min_sdk.is_some_and(|v| v < 23) {
        out.finding(Finding::new(
            "APK-OLD-MIN-SDK",
            Severity::Info,
            "platform",
            format!(
                "minSdkVersion {} (pre-Android 6 security model)",
                opt(m.min_sdk)
            ),
        ));
    }
}

/// Standalone DEX.
pub struct DexAnalyzer;

impl Analyzer for DexAnalyzer {
    fn name(&self) -> &'static str {
        "mobile.dex"
    }
    fn description(&self) -> &'static str {
        "Dalvik bytecode → classes, packages, obfuscation, risky API references"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Dex
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let d = dex::parse(a.data())?;
        let (pk, ratio) = dex::package_stats(&d, 3);
        let mut out = AnalyzerOutput::new();
        out.section(Section::kv(
            "mobile.dex.overview",
            "DEX overview",
            [
                ("Version".to_string(), d.version.clone()),
                (
                    "Checksum / signature".to_string(),
                    format!("{} / {}", ok(d.checksum_ok), ok(d.signature_ok)),
                ),
                ("Strings".to_string(), d.strings.len().to_string()),
                ("Types".to_string(), d.types.len().to_string()),
                ("Method refs".to_string(), d.methods.len().to_string()),
                ("Classes".to_string(), d.classes.len().to_string()),
                (
                    "Short class names".to_string(),
                    format!("{:.0}%", ratio * 100.0),
                ),
            ],
        ));
        out.section(Section::table(
            "mobile.dex.packages",
            "Packages",
            &["package", "classes"],
            pk.into_iter()
                .map(|(p, n)| vec![p, n.to_string()])
                .collect(),
            opts.max_rows,
        ));
        out.section(Section::table(
            "mobile.dex.classes",
            "Classes",
            &["class", "extends", "implements", "methods", "source"],
            d.classes
                .iter()
                .map(|c| {
                    vec![
                        c.name.clone(),
                        c.superclass.clone(),
                        c.interfaces.join(", "),
                        c.methods.to_string(),
                        c.source_file.clone().unwrap_or_default(),
                    ]
                })
                .collect(),
            opts.max_rows,
        ));
        for h in dex::risky_apis(&d) {
            out.finding(
                Finding::new(h.id, h.severity, "capability", h.what)
                    .evidence_all(h.refs.into_iter().take(10))
                    .attack(h.attack),
            );
        }
        if !d.checksum_ok {
            out.finding(Finding::new(
                "DEX-BAD-CHECKSUM",
                Severity::Medium,
                "integrity",
                "DEX checksum mismatch (modified after build)",
            ));
        }
        Ok(out)
    }
}

fn ok(b: bool) -> &'static str {
    if b { "valid" } else { "INVALID" }
}

/// Standalone binary XML.
pub struct AxmlAnalyzer;

impl Analyzer for AxmlAnalyzer {
    fn name(&self) -> &'static str {
        "mobile.axml"
    }
    fn description(&self) -> &'static str {
        "Android binary XML → readable XML (+ manifest audit when it is AndroidManifest.xml)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::AndroidBinaryXml
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let root = axml::parse(a.data())?;
        let mut out = AnalyzerOutput::new();
        out.section(Section::code(
            "mobile.axml",
            "Decoded XML",
            "xml",
            root.to_xml(),
        ));
        if root.name == "manifest" {
            manifest_findings(&axml::Manifest::from_xml(&root), &mut out);
        }
        Ok(out)
    }
}
