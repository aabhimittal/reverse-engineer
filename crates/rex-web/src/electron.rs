//! Electron app triage: the analyzer for `app.asar`.
//!
//! An Electron app is a browser (renderer) plus a Node.js process (main) glued by IPC. Most of
//! the interesting security questions are answered by three things this module looks for:
//! how each window is configured, which IPC channels the main process exposes, and what is
//! bundled (secrets, source maps, native addons).

use crate::asar::{self, Archive};
use regex::Regex;
use rex_core::secrets;
use rex_core::{
    AnalysisOptions, Analyzer, AnalyzerOutput, Artifact, ArtifactKind, Finding, Result, Section,
    Severity,
};
use std::collections::BTreeMap;
use std::sync::OnceLock;

const MAX_FILE: usize = 4 << 20;
const MAX_TOTAL: usize = 128 << 20;

/// A risky `BrowserWindow` / `webPreferences` setting.
struct Setting {
    id: &'static str,
    severity: Severity,
    title: &'static str,
    why: &'static str,
    re: &'static str,
}

const SETTINGS: &[Setting] = &[
    Setting {
        id: "ELECTRON-NODE-INTEGRATION",
        severity: Severity::High,
        title: "nodeIntegration enabled in a renderer",
        why: "Any script that runs in that window (an XSS, a third-party tag, a remote page) gets full Node.js: file system, child_process, the lot. It turns a web bug into remote code execution.",
        re: r"nodeIntegration\s*:\s*(?:true|!0)\b",
    },
    Setting {
        id: "ELECTRON-NO-CONTEXT-ISOLATION",
        severity: Severity::High,
        title: "contextIsolation disabled",
        why: "Preload scripts and page scripts share one JavaScript world, so the page can tamper with the preload's objects and reach whatever it exposes.",
        re: r"contextIsolation\s*:\s*(?:false|!1)\b",
    },
    Setting {
        id: "ELECTRON-WEB-SECURITY-OFF",
        severity: Severity::High,
        title: "webSecurity disabled",
        why: "Turns off the same-origin policy for that window, so any content it loads can read any other origin.",
        re: r"webSecurity\s*:\s*(?:false|!1)\b",
    },
    Setting {
        id: "ELECTRON-INSECURE-CONTENT",
        severity: Severity::Medium,
        title: "allowRunningInsecureContent enabled",
        why: "HTTPS pages may load scripts over plain HTTP, which a network attacker can rewrite.",
        re: r"allowRunningInsecureContent\s*:\s*(?:true|!0)\b",
    },
    Setting {
        id: "ELECTRON-SANDBOX-OFF",
        severity: Severity::Medium,
        title: "Renderer sandbox disabled",
        why: "The Chromium sandbox is the second wall after a renderer bug; without it a renderer compromise reaches the operating system directly.",
        re: r"\bsandbox\s*:\s*(?:false|!1)\b|--no-sandbox",
    },
    Setting {
        id: "ELECTRON-REMOTE-MODULE",
        severity: Severity::Medium,
        title: "Remote module enabled",
        why: "Lets renderers call main-process objects directly, which makes every renderer bug a main-process bug.",
        re: r"enableRemoteModule\s*:\s*(?:true|!0)\b",
    },
    Setting {
        id: "ELECTRON-NODE-IN-WORKER",
        severity: Severity::Medium,
        title: "Node.js enabled in workers or sub-frames",
        why: "Widens the set of scripts that get Node.js beyond the top-level page.",
        re: r"nodeIntegrationIn(?:Worker|SubFrames)\s*:\s*(?:true|!0)\b",
    },
    Setting {
        id: "ELECTRON-LOADS-HTTP",
        severity: Severity::Medium,
        title: "Window loads a page over plain HTTP",
        why: "With any privileged window settings, content fetched over HTTP can be replaced on the wire.",
        re: r#"loadURL\(\s*["'`]http://"#,
    },
    Setting {
        id: "ELECTRON-OPEN-EXTERNAL",
        severity: Severity::Medium,
        title: "shell.openExternal called with a non-literal URL",
        why: "openExternal hands the string to the OS. If an attacker influences it, file:// and custom schemes become command execution on some platforms. Check that every call site validates the scheme.",
        re: r#"shell\.openExternal\(\s*[^'"`\s)]"#,
    },
];

fn compiled() -> &'static Vec<(&'static Setting, Regex)> {
    static C: OnceLock<Vec<(&'static Setting, Regex)>> = OnceLock::new();
    C.get_or_init(|| {
        SETTINGS
            .iter()
            .map(|s| (s, Regex::new(s.re).expect("static regex")))
            .collect()
    })
}

fn ipc_re() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(
            r#"ipcMain\s*\.\s*(handle|handleOnce|on|once)\(\s*["'`]([A-Za-z0-9_:.\-/]{1,80})["'`]"#,
        )
        .expect("static regex")
    })
}

fn is_text(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [
        ".js",
        ".cjs",
        ".mjs",
        ".json",
        ".html",
        ".env",
        ".yml",
        ".yaml",
        ".ts",
        ".txt",
        ".cfg",
        ".ini",
        ".toml",
        ".properties",
    ]
    .iter()
    .any(|e| p.ends_with(e))
        || p.rsplit('/').next().is_some_and(|n| n.starts_with(".env"))
}

fn is_native(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    [".node", ".dll", ".so", ".dylib", ".exe"]
        .iter()
        .any(|e| p.ends_with(e))
}

fn is_js(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".js") || p.ends_with(".cjs") || p.ends_with(".mjs")
}

/// `node_modules/<pkg>` (or `@scope/pkg`) at any depth, with version if its package.json is readable.
fn dependencies(a: &Archive<'_>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for e in &a.entries {
        let Some(rest) = e
            .path
            .strip_prefix("node_modules/")
            .filter(|_| e.path.ends_with("/package.json"))
        else {
            continue;
        };
        let parts: Vec<&str> = rest.split('/').collect();
        let (name, depth) = if parts.first().is_some_and(|p| p.starts_with('@')) {
            (parts[..2.min(parts.len())].join("/"), 3)
        } else {
            (parts[0].to_string(), 2)
        };
        if parts.len() != depth {
            continue;
        }
        let version = a
            .read(e)
            .filter(|b| b.len() < 256 << 10)
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .and_then(|v| v.get("version").and_then(|v| v.as_str()).map(String::from))
            .unwrap_or_else(|| "?".into());
        out.insert(name, version);
    }
    out
}

/// Electron app archives.
pub struct ElectronAnalyzer;

impl Analyzer for ElectronAnalyzer {
    fn name(&self) -> &'static str {
        "electron.asar"
    }
    fn description(&self) -> &'static str {
        "Electron app.asar → file tree, IPC surface, window security settings, secrets, native addons, dependencies"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Asar
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let ar = asar::parse(a.data())?;
        let mut out = AnalyzerOutput::new();

        let total: u64 = ar.entries.iter().map(|e| e.size).sum();
        let unpacked: Vec<_> = ar.entries.iter().filter(|e| e.unpacked).collect();
        let links: Vec<_> = ar.entries.iter().filter(|e| e.link.is_some()).collect();
        let hashed = ar.entries.iter().filter(|e| e.integrity).count();

        let pkg = ar
            .find("package.json")
            .and_then(|e| ar.read(e))
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok());
        let field = |k: &str| {
            pkg.as_ref()
                .and_then(|p| p.get(k))
                .and_then(|v| v.as_str())
                .map(String::from)
        };
        let mut kv: Vec<(String, String)> = Vec::new();
        if let Some(n) = field("name") {
            kv.push(("App".into(), n));
        }
        if let Some(v) = field("version") {
            kv.push(("Version".into(), v));
        }
        if let Some(m) = field("main") {
            kv.push(("Main process entry".into(), m));
        }
        kv.extend([
            ("Files".to_string(), ar.entries.len().to_string()),
            ("Directories".into(), ar.dirs.to_string()),
            ("Packed size".into(), format!("{total} bytes")),
            (
                "Unpacked outside the archive".into(),
                unpacked.len().to_string(),
            ),
            ("Symlinks".into(), links.len().to_string()),
            (
                "Entries with integrity hashes".into(),
                format!("{hashed} of {}", ar.entries.len()),
            ),
        ]);
        out.section(Section::kv(
            "electron.overview",
            "Electron app overview",
            kv,
        ));

        let mut by_size: Vec<_> = ar.entries.iter().collect();
        by_size.sort_by(|x, y| y.size.cmp(&x.size).then(x.path.cmp(&y.path)));
        out.section(Section::table(
            "electron.files",
            "Largest files",
            &["path", "bytes"],
            by_size
                .iter()
                .map(|e| vec![e.path.clone(), e.size.to_string()])
                .collect(),
            opts.max_rows.min(20),
        ));

        let deps = dependencies(&ar);
        if !deps.is_empty() {
            out.section(Section::table(
                "electron.dependencies",
                "Bundled dependencies (audit these against an advisory database)",
                &["package", "version"],
                deps.iter()
                    .map(|(n, v)| vec![n.clone(), v.clone()])
                    .collect(),
                opts.max_rows,
            ));
        }

        // Scan text files once, collecting window settings, IPC channels and secrets.
        let mut seen = 0usize;
        let mut settings: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        let mut ipc: BTreeMap<String, (String, String)> = BTreeMap::new();
        let mut secret_hits: Vec<(bool, String)> = Vec::new();
        let mut preload: Vec<String> = Vec::new();
        for e in &ar.entries {
            if !is_text(&e.path) || e.size as usize > MAX_FILE {
                continue;
            }
            let Some(bytes) = ar.read(e) else { continue };
            seen += bytes.len();
            if seen > MAX_TOTAL {
                break;
            }
            let text = String::from_utf8_lossy(bytes);
            if is_js(&e.path) {
                for (s, re) in compiled() {
                    for m in re.find_iter(&text).take(3) {
                        if s.id == "ELECTRON-LOADS-HTTP"
                            && ["localhost", "127.", "[::1]"]
                                .iter()
                                .any(|l| text[m.end()..].starts_with(l))
                        {
                            continue;
                        }
                        settings.entry(s.id).or_default().push(format!(
                            "{} @{:#x}",
                            e.path,
                            m.start()
                        ));
                    }
                }
                for c in ipc_re().captures_iter(&text).take(500) {
                    ipc.entry(c[2].to_string())
                        .or_insert_with(|| (c[1].to_string(), e.path.clone()));
                }
                if text.contains("preload") && text.contains("webPreferences") {
                    preload.push(e.path.clone());
                }
            }
            if !e.path.starts_with("node_modules/") {
                for h in secrets::scan(&text).into_iter().take(10) {
                    secret_hits.push((
                        h.high,
                        format!("{}: {} {}", e.path, h.kind, secrets::mask(&h.value)),
                    ));
                }
            }
        }

        if !ipc.is_empty() {
            out.section(Section::table(
                "electron.ipc",
                "IPC channels exposed by the main process (each is an RPC a renderer can call)",
                &["channel", "kind", "defined in"],
                ipc.iter()
                    .map(|(c, (k, f))| vec![c.clone(), k.clone(), f.clone()])
                    .collect(),
                opts.max_rows,
            ));
        }

        for (s, _) in compiled() {
            if let Some(ev) = settings.remove(s.id) {
                out.finding(
                    Finding::new(s.id, s.severity, "electron", s.title)
                        .describe(s.why)
                        .evidence_all(ev),
                );
            }
        }

        if !secret_hits.is_empty() {
            let high = secret_hits.iter().any(|(h, _)| *h);
            out.finding(
                Finding::new(
                    "ELECTRON-SECRETS",
                    if high { Severity::High } else { Severity::Medium },
                    "secret",
                    "Credentials embedded in the app",
                )
                .describe("Anything in the archive is readable by every user who installs the app. Values are masked here.")
                .attack("T1552.001")
                .evidence_all(secret_hits.into_iter().map(|(_, s)| s)),
            );
        }

        let maps: Vec<_> = ar
            .entries
            .iter()
            .filter(|e| e.path.ends_with(".map"))
            .map(|e| e.path.clone())
            .collect();
        if !maps.is_empty() {
            out.finding(
                Finding::new(
                    "ELECTRON-SOURCEMAPS",
                    Severity::Low,
                    "exposure",
                    "Source maps shipped in the archive",
                )
                .describe("Original, unminified source can be recovered. Run `rex web sourcemap <file.map>`.")
                .evidence_all(maps),
            );
        }

        let native: Vec<_> = ar
            .entries
            .iter()
            .filter(|e| is_native(&e.path))
            .map(|e| format!("{}{}", e.path, if e.unpacked { " (unpacked)" } else { "" }))
            .collect();
        if !native.is_empty() {
            out.finding(
                Finding::new(
                    "ELECTRON-NATIVE-CODE",
                    Severity::Info,
                    "native",
                    "Native code bundled with the app",
                )
                .describe("Native addons run outside the JavaScript sandbox. Extract with `rex web asar` or find them under app.asar.unpacked/ and run `rex analyze` on each.")
                .evidence_all(native),
            );
        }

        let escaping: Vec<_> = ar
            .entries
            .iter()
            .filter(|e| {
                e.path.split('/').any(|s| s == ".." || s.contains('\\'))
                    || e.link
                        .as_deref()
                        .is_some_and(|l| l.starts_with('/') || l.split('/').any(|s| s == ".."))
            })
            .map(|e| format!("{} -> {}", e.path, e.link.as_deref().unwrap_or("")))
            .collect();
        if !escaping.is_empty() {
            out.finding(
                Finding::new(
                    "ELECTRON-PATH-ESCAPE",
                    Severity::Medium,
                    "integrity",
                    "Archive contains entries that point outside it",
                )
                .describe("Legitimate builds do not do this. Extractors that trust the header can be tricked into writing elsewhere (`rex` refuses these).")
                .evidence_all(escaping),
            );
        }

        if hashed == 0 && !ar.entries.is_empty() {
            out.finding(
                Finding::new(
                    "ELECTRON-NO-INTEGRITY",
                    Severity::Low,
                    "hardening",
                    "Archive has no integrity hashes",
                )
                .describe("Anyone who can write to the install directory can swap in modified JavaScript and it will run with the app's identity and permissions. Electron can verify the archive only when the EnableEmbeddedAsarIntegrityValidation fuse is on and a hash is embedded in the executable; check the app binary's fuses."),
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asar::tests::build;
    use rex_core::Registry;

    fn run(files: &[(&str, &[u8])]) -> rex_core::Report {
        let a = Artifact::from_bytes("app.asar", build(files));
        let mut r = Registry::new();
        r.register(ElectronAnalyzer);
        r.run(&a, &AnalysisOptions::default(), &[])
    }

    #[test]
    fn flags_dangerous_window_settings_and_lists_ipc() {
        let rep = run(&[
            ("package.json", br#"{"name":"demo","version":"1.2.3","main":"main.js"}"#),
            (
                "main.js",
                b"new BrowserWindow({webPreferences:{nodeIntegration:true,contextIsolation:false,preload:p}});\n\
                  ipcMain.handle('fs:read', (e, p) => fs.readFileSync(p));\n\
                  ipcMain.on('open-link', (e, u) => shell.openExternal(u));\n\
                  win.loadURL('http://example.test/app');",
            ),
            ("node_modules/left-pad/package.json", br#"{"name":"left-pad","version":"1.3.0"}"#),
            ("node_modules/@scope/pkg/package.json", br#"{"version":"0.0.1"}"#),
            ("node_modules/left-pad/lib/nested/package.json", br#"{"version":"9"}"#),
            ("native/addon.node", b"\x7fELF"),
            ("dist/app.js.map", b"{}"),
        ]);
        let ids: Vec<&str> = rep.findings.iter().map(|f| f.id.as_str()).collect();
        for want in [
            "ELECTRON-NODE-INTEGRATION",
            "ELECTRON-NO-CONTEXT-ISOLATION",
            "ELECTRON-OPEN-EXTERNAL",
            "ELECTRON-LOADS-HTTP",
            "ELECTRON-NATIVE-CODE",
            "ELECTRON-SOURCEMAPS",
            "ELECTRON-NO-INTEGRITY",
        ] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
        assert!(!ids.contains(&"ELECTRON-WEB-SECURITY-OFF"));
        let ipc = rep.section("electron.ipc").expect("ipc table");
        let text = serde_json::to_string(ipc).unwrap();
        assert!(text.contains("fs:read") && text.contains("open-link"));
        let deps = serde_json::to_string(rep.section("electron.dependencies").unwrap()).unwrap();
        assert!(deps.contains("left-pad") && deps.contains("@scope/pkg"));
        assert!(
            !deps.contains("\"9\""),
            "nested package.json is not a top-level dependency"
        );
        let ov = serde_json::to_string(rep.section("electron.overview").unwrap()).unwrap();
        assert!(ov.contains("demo") && ov.contains("1.2.3"));
    }

    #[test]
    fn hardened_app_is_quiet() {
        let rep = run(&[(
            "main.js",
            b"new BrowserWindow({webPreferences:{nodeIntegration:false,contextIsolation:true,sandbox:true}});\
              win.loadURL('https://example.test'); shell.openExternal('https://example.test/help');",
        )]);
        assert!(
            rep.findings.iter().all(|f| f.id == "ELECTRON-NO-INTEGRITY"),
            "{:?}",
            rep.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn secrets_are_masked() {
        let key = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        let src = format!("const k = '{key}';");
        let rep = run(&[("config.js", src.as_bytes())]);
        let f = rep
            .findings
            .iter()
            .find(|f| f.id == "ELECTRON-SECRETS")
            .expect("secret finding");
        let ev = f.evidence.join("\n");
        assert!(ev.contains("config.js") && !ev.contains(&key), "{ev}");
    }
}
