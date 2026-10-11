//! [`rex_core::Analyzer`] implementations for binaries and firmware.

use crate::model::{Binary, MitigationStatus};
use crate::{capabilities, carve, fingerprint, functions, packer, strings};
use rex_core::{
    AnalysisOptions, Analyzer, AnalyzerOutput, Artifact, ArtifactKind, Finding, Location, Registry,
    Result, Section, Severity, hash,
};

fn native(a: &Artifact) -> bool {
    a.kind().is_native_binary()
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// Register all binary analyzers.
pub fn register(r: &mut Registry) {
    r.register(Info)
        .register(Hashes)
        .register(Checksec)
        .register(Packer)
        .register(Capabilities)
        .register(Strings)
        .register(Functions)
        .register(Entropy)
        .register(Carve);
    #[cfg(feature = "yara")]
    r.register(Yara);
}

// ───────────────────────────── info ─────────────────────────────

/// Headers, sections, imports, exports.
pub struct Info;

impl Analyzer for Info {
    fn name(&self) -> &'static str {
        "binary.info"
    }
    fn description(&self) -> &'static str {
        "Format headers, sections, libraries, imports and exports (ELF/PE/Mach-O)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a)
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let b = Binary::parse(a.data())?;
        let mut out = AnalyzerOutput::new();
        let mut kv: Vec<(String, String)> = vec![
            (
                "Format".into(),
                format!("{} {}-bit", b.format.as_str(), b.bits),
            ),
            ("Architecture".into(), b.arch.name()),
            (
                "Endianness".into(),
                if b.little_endian { "little" } else { "big" }.into(),
            ),
            ("Type".into(), b.file_type.clone()),
            ("Entry point".into(), hex(b.entry)),
            ("Image base".into(), hex(b.image_base)),
            ("Sections".into(), b.sections.len().to_string()),
            (
                "Imports".into(),
                format!("{} from {} libraries", b.imports.len(), b.libraries.len()),
            ),
            ("Exports".into(), b.exports.len().to_string()),
            (
                "Symbols".into(),
                format!(
                    "{}{}",
                    b.symbols.len(),
                    if b.stripped { " (stripped)" } else { "" }
                ),
            ),
        ];
        if let Some(i) = &b.interpreter {
            kv.push(("Interpreter".into(), i.clone()));
        }
        kv.extend(b.extras.iter().cloned());
        if let Some(o) = b.overlay_offset {
            kv.push((
                "Overlay".into(),
                format!("{} bytes at {:#x}", a.size() - o, o),
            ));
        }
        out.section(Section::kv("binary.overview", "Binary overview", kv).with_data(&b));

        let rows = b
            .sections
            .iter()
            .map(|s| {
                vec![
                    s.name.clone(),
                    hex(s.addr),
                    hex(s.size),
                    hex(s.offset),
                    s.perms.to_string(),
                    format!("{:.2}", s.entropy),
                    hash::sparkline(&[s.entropy], 8.0),
                ]
            })
            .collect();
        out.section(Section::table(
            "binary.sections",
            "Sections",
            &["name", "address", "size", "offset", "perms", "entropy", ""],
            rows,
            0,
        ));
        if !b.libraries.is_empty() {
            out.section(Section::table(
                "binary.libraries",
                "Linked libraries",
                &["library"],
                b.libraries.iter().map(|l| vec![l.clone()]).collect(),
                0,
            ));
        }
        let rows = b
            .imports
            .iter()
            .map(|i| {
                vec![
                    i.library.clone().unwrap_or_default(),
                    i.name.clone(),
                    i.slot.map(hex).unwrap_or_default(),
                ]
            })
            .collect();
        out.section(Section::table(
            "binary.imports",
            "Imports",
            &["library", "function", "slot"],
            rows,
            opts.max_rows,
        ));
        if !b.exports.is_empty() {
            let rows = b
                .exports
                .iter()
                .map(|s| vec![hex(s.addr), s.display().to_string(), s.size.to_string()])
                .collect();
            out.section(Section::table(
                "binary.exports",
                "Exports",
                &["address", "name", "size"],
                rows,
                opts.max_rows,
            ));
        }

        for s in b.sections.iter().filter(|s| s.perms.w && s.perms.x) {
            out.finding(
                Finding::new("BIN-RWX-SECTION", Severity::High, "memory", format!("Section '{}' is writable and executable", s.name))
                    .describe("W^X violation: code can be modified at runtime. Typical of packers, JITs and self-modifying malware.")
                    .evidence(format!("{} {} @ {:#x}", s.name, s.perms, s.addr))
                    .at(Location { address: Some(s.addr), offset: Some(s.offset), ..Default::default() }),
            );
        }
        if let Some(o) = b.overlay_offset {
            let size = a.size() - o;
            let ent = hash::entropy(&a.data()[o as usize..]);
            out.finding(
                Finding::new("BIN-OVERLAY", if ent > 7.0 { Severity::Medium } else { Severity::Low }, "structure", "Data appended after the image (overlay)")
                    .describe("Installers, self-extracting archives and droppers append payloads after the last section. Run `rex carve` on it.")
                    .evidence(format!("{size} bytes at {o:#x}, entropy {ent:.2}"))
                    .at(Location { offset: Some(o), ..Default::default() }),
            );
        }
        if b.stripped && b.format != crate::model::BinFormat::Pe {
            out.finding(Finding::new("BIN-STRIPPED", Severity::Info, "structure", "Symbols are stripped").describe(
                "No local symbol table. rex will still recover functions by following control flow from the entry point.",
            ));
        }
        Ok(out)
    }
}

// ───────────────────────────── hashes ─────────────────────────────

/// Cryptographic, import and fuzzy hashes.
pub struct Hashes;

impl Analyzer for Hashes {
    fn name(&self) -> &'static str {
        "binary.hashes"
    }
    fn description(&self) -> &'static str {
        "MD5/SHA-1/SHA-256, imphash, import-set hash and TLSH fuzzy hash"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() != ArtifactKind::Directory && !a.data().is_empty()
    }
    fn priority(&self) -> i32 {
        15
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let bin = if native(a) {
            Binary::parse(a.data()).ok()
        } else {
            None
        };
        let fp = fingerprint::compute(a.data(), bin.as_ref());
        let mut kv = vec![
            ("MD5", fp.md5.clone()),
            ("SHA-1", fp.sha1.clone()),
            ("SHA-256", fp.sha256.clone()),
            ("Entropy", format!("{:.3} bits/byte", a.entropy())),
        ];
        if let Some(t) = &fp.tlsh {
            kv.push(("TLSH", t.clone()));
        }
        if let Some(i) = &fp.imphash {
            kv.push(("imphash", i.clone()));
        }
        if let Some(i) = &fp.import_set_md5 {
            kv.push(("Import-set MD5", i.clone()));
        }
        let mut out = AnalyzerOutput::new();
        out.section(Section::kv("binary.hashes", "Fingerprints", kv).with_data(&fp));
        Ok(out)
    }
}

// ───────────────────────────── checksec ─────────────────────────────

/// Exploit mitigations.
pub struct Checksec;

impl Analyzer for Checksec {
    fn name(&self) -> &'static str {
        "binary.checksec"
    }
    fn description(&self) -> &'static str {
        "Exploit mitigations: NX, PIE/ASLR, RELRO, canaries, FORTIFY, CFG, CET, signing"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a)
    }
    fn priority(&self) -> i32 {
        20
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let b = Binary::parse(a.data())?;
        let mut out = AnalyzerOutput::new();
        let rows = b
            .mitigations
            .iter()
            .map(|m| {
                vec![
                    m.name.to_string(),
                    m.status.label().to_string(),
                    m.detail.clone(),
                ]
            })
            .collect();
        out.section(
            Section::table(
                "binary.checksec",
                "Security mitigations",
                &["mitigation", "status", "detail"],
                rows,
                0,
            )
            .with_data(&b.mitigations),
        );
        let exec = !b.file_type.contains("library")
            && b.file_type != "DLL"
            && !b.file_type.contains("object");
        for m in &b.mitigations {
            let (sev, why) = match (m.name, m.status) {
                ("NX" | "DEP/NX" | "NX stack", MitigationStatus::Disabled) => (
                    Severity::High,
                    "Injected data on the stack/heap can be executed as code (classic shellcode).",
                ),
                ("PIE" | "ASLR", MitigationStatus::Disabled) if exec => (
                    Severity::Medium,
                    "Code is loaded at a fixed address, so ROP gadgets have predictable addresses.",
                ),
                ("ASLR", MitigationStatus::Partial) => (
                    Severity::Medium,
                    "ASLR requested but relocations are stripped, so the loader can't move the image.",
                ),
                ("RELRO", MitigationStatus::Disabled) => (
                    Severity::Medium,
                    "The GOT stays writable: a write primitive can redirect library calls.",
                ),
                ("RELRO", MitigationStatus::Partial) => {
                    (Severity::Low, "Lazy binding keeps .got.plt writable.")
                }
                ("Stack canary" | "GS cookie", MitigationStatus::Disabled) => (
                    Severity::Medium,
                    "Stack buffer overflows can overwrite return addresses undetected.",
                ),
                ("No RPATH", MitigationStatus::Disabled) => (
                    Severity::Medium,
                    "RPATH can enable library hijacking if the path is writable.",
                ),
                ("CFG", MitigationStatus::Disabled) => (
                    Severity::Low,
                    "Indirect calls are not validated against a set of valid targets.",
                ),
                ("SafeSEH", MitigationStatus::Disabled) => (
                    Severity::Medium,
                    "SEH overwrite exploits are possible on 32-bit Windows.",
                ),
                ("FORTIFY_SOURCE", MitigationStatus::Disabled) => (
                    Severity::Info,
                    "Compiled without -D_FORTIFY_SOURCE (or no fortifiable calls).",
                ),
                _ => continue,
            };
            out.finding(
                Finding::new(
                    format!(
                        "BIN-MITIGATION-{}",
                        m.name.to_ascii_uppercase().replace(['/', ' '], "-")
                    ),
                    sev,
                    "mitigation",
                    format!(
                        "{}: {}",
                        m.name,
                        m.status
                            .label()
                            .trim_start_matches(|c: char| !c.is_alphabetic())
                    ),
                )
                .describe(why)
                .evidence(m.detail.clone()),
            );
        }
        Ok(out)
    }
}

// ───────────────────────────── packer ─────────────────────────────

/// Packer heuristics.
pub struct Packer;

impl Analyzer for Packer {
    fn name(&self) -> &'static str {
        "binary.packer"
    }
    fn description(&self) -> &'static str {
        "Packer/protector signatures and entropy-based packing heuristics"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a)
    }
    fn priority(&self) -> i32 {
        25
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let b = Binary::parse(a.data())?;
        let v = packer::detect(&b, a.data());
        let mut out = AnalyzerOutput::new();
        let mut kv = vec![
            (
                "Verdict".to_string(),
                if v.is_packed() {
                    "likely packed".to_string()
                } else {
                    "not packed".to_string()
                },
            ),
            ("Score".to_string(), format!("{}/100", v.score)),
        ];
        if let Some(n) = &v.name {
            kv.push(("Packer".into(), n.clone()));
        }
        for (i, r) in v.reasons.iter().enumerate() {
            kv.push((format!("Reason {}", i + 1), r.clone()));
        }
        out.section(Section::kv("binary.packer", "Packing / obfuscation", kv).with_data(&v));
        if v.is_packed() {
            out.finding(
                Finding::new(
                    "BIN-PACKED",
                    Severity::Medium,
                    "packer",
                    match &v.name {
                        Some(n) => format!("Packed with {n}"),
                        None => "Likely packed or encrypted".into(),
                    },
                )
                .describe("Static analysis sees only the unpacking stub. Unpack first (e.g. `upx -d`) or analyse a memory dump.")
                .evidence_all(v.reasons.clone())
                .attack("T1027.002"),
            );
        }
        Ok(out)
    }
}

// ───────────────────────────── capabilities ─────────────────────────────

/// capa-style behaviour detection.
pub struct Capabilities;

impl Analyzer for Capabilities {
    fn name(&self) -> &'static str {
        "binary.capabilities"
    }
    fn description(&self) -> &'static str {
        "Behavioural capabilities from imports, strings and constants, mapped to MITRE ATT&CK"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a) || a.kind() == ArtifactKind::Blob
    }
    fn priority(&self) -> i32 {
        30
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let imports = if native(a) {
            Binary::parse(a.data())
                .map(|b| b.import_names())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let strs: Vec<String> = strings::extract(a.data(), opts.min_string_len.max(4))
            .into_iter()
            .map(|s| s.text)
            .collect();
        let caps = capabilities::detect(&capabilities::Evidence {
            imports: &imports,
            strings: &strs,
            data: a.data(),
        });
        let mut out = AnalyzerOutput::new();
        let rows = caps
            .iter()
            .map(|c| {
                vec![
                    c.severity.to_string(),
                    c.name.to_string(),
                    c.namespace.to_string(),
                    c.attack.join(", "),
                ]
            })
            .collect();
        out.section(
            Section::table(
                "binary.capabilities",
                "Capabilities (ATT&CK)",
                &["severity", "capability", "namespace", "ATT&CK"],
                rows,
                0,
            )
            .with_data(&caps),
        );
        for c in caps {
            let mut f =
                Finding::new(c.id, c.severity, "capability", c.name).evidence_all(c.evidence);
            for t in c.attack {
                f = f.attack(t);
            }
            f.description = format!("namespace: {}", c.namespace);
            out.finding(f);
        }
        Ok(out)
    }
}

// ───────────────────────────── strings ─────────────────────────────

/// Interesting strings.
pub struct Strings;

impl Analyzer for Strings {
    fn name(&self) -> &'static str {
        "binary.strings"
    }
    fn description(&self) -> &'static str {
        "ASCII/UTF-16 strings, classified (URLs, IPs, paths, registry, secrets, commands)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a)
            || matches!(
                a.kind(),
                ArtifactKind::Blob
                    | ArtifactKind::JavaClass
                    | ArtifactKind::Wasm
                    | ArtifactKind::Dex
            )
    }
    fn priority(&self) -> i32 {
        40
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let all = strings::extract(a.data(), opts.min_string_len);
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for s in &all {
            *counts.entry(s.category.as_str()).or_default() += 1;
        }
        let mut interesting: Vec<&strings::FoundString> = strings::interesting(&all).collect();
        interesting.sort_by_key(|s| (s.category, s.offset));
        interesting.dedup_by(|x, y| x.text == y.text);
        let rows = interesting
            .iter()
            .map(|s| {
                vec![
                    s.category.as_str().to_string(),
                    hex(s.offset),
                    s.text.clone(),
                ]
            })
            .collect();
        let mut out = AnalyzerOutput::new();
        out.section(Section::kv(
            "binary.strings.summary",
            "String statistics",
            std::iter::once(("total".to_string(), all.len().to_string()))
                .chain(counts.iter().map(|(k, v)| (k.to_string(), v.to_string()))),
        ));
        out.section(
            Section::table(
                "binary.strings",
                "Interesting strings",
                &["category", "offset", "string"],
                rows,
                opts.max_rows.max(100),
            )
            .with_data(&interesting),
        );
        let secrets: Vec<_> = interesting
            .iter()
            .filter(|s| s.category == strings::Category::Secret)
            .collect();
        if !secrets.is_empty() {
            out.finding(
                Finding::new("BIN-EMBEDDED-SECRET", Severity::High, "secret", "Embedded credential or private key")
                    .describe("Secrets compiled into binaries are recoverable by anyone with the file. Rotate them.")
                    .evidence_all(secrets.iter().map(|s| format!("{:#x}: {}", s.offset, redact(&s.text))))
                    .attack("T1552.001")
                    .at(Location { offset: Some(secrets[0].offset), ..Default::default() }),
            );
        }
        let net: Vec<_> = interesting
            .iter()
            .filter(|s| matches!(s.category, strings::Category::Url | strings::Category::Ip))
            .take(20)
            .collect();
        if !net.is_empty() {
            out.finding(
                Finding::new(
                    "BIN-NETWORK-IOC",
                    Severity::Info,
                    "ioc",
                    format!("{} network indicator(s) (URLs/IPs)", net.len()),
                )
                .evidence_all(net.iter().map(|s| s.text.clone())),
            );
        }
        Ok(out)
    }
}

/// Mask the middle of a secret so reports don't re-leak it.
pub fn redact(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= 10 {
        return "*".repeat(chars.len());
    }
    let head: String = chars[..6].iter().collect();
    let tail: String = chars[chars.len() - 4..].iter().collect();
    format!("{head}…{tail} ({} chars)", chars.len())
}

// ───────────────────────────── functions ─────────────────────────────

const UNSAFE_FUNCS: &[(&str, Severity)] = &[
    ("gets", Severity::High),
    ("strcpy", Severity::Low),
    ("strcat", Severity::Low),
    ("sprintf", Severity::Low),
    ("vsprintf", Severity::Low),
    ("lstrcpyA", Severity::Low),
    ("lstrcpyW", Severity::Low),
    ("lstrcatA", Severity::Low),
    ("lstrcatW", Severity::Low),
    ("wcscpy", Severity::Low),
    ("wcscat", Severity::Low),
    ("mktemp", Severity::Low),
    ("tmpnam", Severity::Low),
    ("system", Severity::Low),
    ("popen", Severity::Low),
];

/// Function recovery, call graph and disassembly of `main`.
pub struct Functions;

impl Analyzer for Functions {
    fn name(&self) -> &'static str {
        "binary.functions"
    }
    fn description(&self) -> &'static str {
        "Recursive-descent function discovery, CFGs, call graph, xrefs and unsafe-API usage (x86/x64)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        native(a)
    }
    fn priority(&self) -> i32 {
        50
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let b = Binary::parse(a.data())?;
        let prog = functions::analyze(&b, a.data(), opts);
        let mut out = AnalyzerOutput::new();
        if prog.unsupported_arch {
            out.section(Section::text(
                "binary.functions",
                "Functions",
                format!(
                    "Control-flow recovery is built in for x86/x64. {} code needs the `multiarch` feature for disassembly (`cargo install rex-cli --features multiarch`).",
                    b.arch.name()
                ),
            ));
            return Ok(out);
        }
        let callers = prog.callers();
        let mut funcs: Vec<&functions::Function> = prog.functions.values().collect();
        funcs.sort_by_key(|f| std::cmp::Reverse(f.size));
        let rows = funcs
            .iter()
            .map(|f| {
                vec![
                    hex(f.addr),
                    f.name.clone(),
                    f.size.to_string(),
                    f.blocks.len().to_string(),
                    f.cyclomatic().to_string(),
                    callers
                        .get(&f.addr)
                        .map(|c| c.len())
                        .unwrap_or(0)
                        .to_string(),
                    f.imports_called
                        .iter()
                        .take(4)
                        .cloned()
                        .collect::<Vec<_>>()
                        .join(", "),
                    f.strings
                        .iter()
                        .take(2)
                        .map(|s| format!("\"{}\"", s.chars().take(40).collect::<String>()))
                        .collect::<Vec<_>>()
                        .join(" "),
                ]
            })
            .collect();
        out.section(Section::kv(
            "binary.functions.summary",
            "Code recovery",
            [
                (
                    "Functions recovered".to_string(),
                    prog.functions.len().to_string(),
                ),
                (
                    "Basic blocks".to_string(),
                    prog.functions
                        .values()
                        .map(|f| f.blocks.len())
                        .sum::<usize>()
                        .to_string(),
                ),
                (
                    "Instructions".to_string(),
                    prog.functions
                        .values()
                        .map(|f| f.insn_count())
                        .sum::<usize>()
                        .to_string(),
                ),
                (
                    "Import stubs resolved".to_string(),
                    prog.stubs.len().to_string(),
                ),
                (
                    "main".to_string(),
                    prog.main
                        .map(hex)
                        .unwrap_or_else(|| "from symbols / n/a".into()),
                ),
            ],
        ));
        out.section(Section::table(
            "binary.functions",
            "Functions (largest first)",
            &[
                "address",
                "name",
                "size",
                "blocks",
                "cyclomatic",
                "callers",
                "imports called",
                "strings",
            ],
            rows,
            opts.max_rows,
        ));

        let root = prog
            .main
            .or_else(|| {
                prog.functions
                    .values()
                    .find(|f| f.name == "main" || f.name == "_main" || f.name == "WinMain")
                    .map(|f| f.addr)
            })
            .or_else(|| (b.entry != 0).then_some(b.entry))
            .filter(|r| prog.functions.contains_key(r));
        if let Some(r) = root {
            out.section(Section::diagram(
                "binary.callgraph",
                format!("Call graph from {}", prog.name_of(r)),
                "mermaid",
                functions::callgraph_mermaid(&prog, r, 25),
            ));
            let f = &prog.functions[&r];
            let listing = functions::function_listing(&prog, f);
            let lines: Vec<&str> = listing.lines().collect();
            let limit = if opts.deep { usize::MAX } else { 120 };
            let mut text = lines
                .iter()
                .take(limit)
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
            if lines.len() > limit {
                text.push_str(&format!(
                    "\n; … {} more lines (rex disasm --function {})",
                    lines.len() - limit,
                    f.name
                ));
            }
            out.section(Section::code(
                "binary.disasm.root",
                format!("Disassembly: {}", f.name),
                "asm",
                text,
            ));
            if f.blocks.len() <= 60 {
                out.section(Section::diagram(
                    "binary.cfg.root",
                    format!("Control-flow graph: {}", f.name),
                    "mermaid",
                    functions::cfg_mermaid(f, 6),
                ));
            }
        }

        // Unsafe API usage with call sites.
        let mut hits: Vec<(String, Severity, Vec<String>)> = Vec::new();
        for (name, sev) in UNSAFE_FUNCS {
            let sites: Vec<String> = prog
                .functions
                .values()
                .filter(|f| f.imports_called.iter().any(|i| i == name))
                .map(|f| f.name.clone())
                .collect();
            let imported = b.imports.iter().any(|i| i.name == *name);
            if !sites.is_empty() || (imported && *sev >= Severity::High) {
                hits.push((name.to_string(), *sev, sites));
            }
        }
        if !hits.is_empty() {
            let sev = hits.iter().map(|h| h.1).max().unwrap_or(Severity::Low);
            out.finding(
                Finding::new("BIN-UNSAFE-API", sev, "code-quality", "Calls memory-unsafe C library functions")
                    .describe("Unbounded copies / formatting (CWE-676, CWE-120). `gets` can never be used safely.")
                    .evidence_all(hits.iter().map(|(n, _, sites)| {
                        if sites.is_empty() {
                            format!("{n} (imported)")
                        } else {
                            format!("{n} ← {}", sites.iter().take(5).cloned().collect::<Vec<_>>().join(", "))
                        }
                    })),
            );
        }
        Ok(out)
    }
}

// ───────────────────────────── firmware ─────────────────────────────

/// Entropy profile for blobs and firmware.
pub struct Entropy;

impl Analyzer for Entropy {
    fn name(&self) -> &'static str {
        "firmware.entropy"
    }
    fn description(&self) -> &'static str {
        "Block entropy profile to locate compressed/encrypted regions"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Blob && a.size() >= 64
    }
    fn priority(&self) -> i32 {
        55
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let block = (a.data().len() / 256).clamp(256, 1 << 20);
        let profile = hash::entropy_profile(a.data(), block);
        let values: Vec<f64> = profile.iter().map(|p| p.1).collect();
        let mut text = format!("block size {block} bytes · 0 ▁ … █ 8 bits/byte\n");
        for chunk in values.chunks(64) {
            text.push_str(&hash::sparkline(chunk, 8.0));
            text.push('\n');
        }
        let regions = carve::entropy_regions(&profile, block);
        let mut out = AnalyzerOutput::new();
        out.section(
            Section::code("firmware.entropy", "Entropy profile", "text", text).with_data(&profile),
        );
        out.section(Section::table(
            "firmware.regions",
            "Entropy regions",
            &["start", "end", "class"],
            regions
                .iter()
                .map(|(s, e, c)| {
                    vec![
                        hex(*s as u64),
                        hex((*e).min(a.data().len()) as u64),
                        c.to_string(),
                    ]
                })
                .collect(),
            0,
        ));
        let enc: usize = regions
            .iter()
            .filter(|r| r.2 == "compressed/encrypted")
            .map(|r| r.1 - r.0)
            .sum();
        if enc * 10 > a.data().len() * 9 {
            out.finding(
                Finding::new("FW-ENCRYPTED", Severity::Medium, "firmware", "Image is almost entirely high-entropy")
                    .describe("Likely encrypted (not just compressed) firmware: look for a decryption routine in the bootloader or an older unencrypted version."),
            );
        }
        Ok(out)
    }
}

/// Embedded-file signatures.
pub struct Carve;

impl Analyzer for Carve {
    fn name(&self) -> &'static str {
        "firmware.carve"
    }
    fn description(&self) -> &'static str {
        "binwalk-style signature scan for embedded files and filesystems"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Blob
            || (native(a)
                && Binary::parse(a.data())
                    .ok()
                    .and_then(|b| b.overlay_offset)
                    .is_some())
    }
    fn priority(&self) -> i32 {
        60
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let (base, data) = if native(a) {
            let o = Binary::parse(a.data())?.overlay_offset.unwrap_or(0) as usize;
            (o as u64, &a.data()[o..])
        } else {
            (0, a.data())
        };
        let hits = carve::scan(data, false);
        let rows = hits
            .iter()
            .map(|h| {
                vec![
                    hex(base + h.offset),
                    h.kind.to_string(),
                    h.size.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                    h.description.clone(),
                ]
            })
            .collect();
        let mut out = AnalyzerOutput::new();
        out.section(
            Section::table(
                "firmware.carve",
                if base > 0 {
                    "Embedded files (overlay)"
                } else {
                    "Embedded files"
                },
                &["offset", "type", "size", "description"],
                rows,
                opts.max_rows,
            )
            .with_data(&hits),
        );
        let fs: Vec<_> = hits
            .iter()
            .filter(|h| matches!(h.kind, "squashfs" | "cpio" | "jffs2" | "ubi" | "uimage"))
            .collect();
        if !fs.is_empty() {
            out.finding(
                Finding::new("FW-FILESYSTEM", Severity::Info, "firmware", "Embedded kernel / filesystem found")
                    .describe("Extract with `rex carve <file> -o out/`, then unpack the filesystem (unsquashfs, cpio -idv).")
                    .evidence_all(fs.iter().map(|h| format!("{:#x}: {}", base + h.offset, h.description))),
            );
        }
        let keys: Vec<_> = hits
            .iter()
            .filter(|h| h.kind == "pem" && h.description.contains("PRIVATE"))
            .collect();
        if !keys.is_empty() {
            out.finding(
                Finding::new(
                    "FW-PRIVATE-KEY",
                    Severity::High,
                    "secret",
                    "Private key embedded in image",
                )
                .evidence_all(
                    keys.iter()
                        .map(|h| format!("{:#x}: {}", base + h.offset, h.description)),
                )
                .attack("T1552.004"),
            );
        }
        Ok(out)
    }
}

// ───────────────────────────── yara ─────────────────────────────

/// YARA-X scanning with bundled starter rules (and `REX_YARA_RULES`).
#[cfg(feature = "yara")]
pub struct Yara;

#[cfg(feature = "yara")]
impl Analyzer for Yara {
    fn name(&self) -> &'static str {
        "scan.yara"
    }
    fn description(&self) -> &'static str {
        "YARA rules (bundled starter set plus $REX_YARA_RULES)"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() != ArtifactKind::Directory
    }
    fn priority(&self) -> i32 {
        35
    }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let extra = std::env::var_os("REX_YARA_RULES").map(std::path::PathBuf::from);
        let rules = crate::yara::compile(extra.as_deref())?;
        let matches = crate::yara::scan(&rules, a.data())?;
        let mut out = AnalyzerOutput::new();
        out.section(
            Section::table(
                "scan.yara",
                "YARA matches",
                &["namespace", "rule", "patterns"],
                matches
                    .iter()
                    .map(|m| {
                        vec![
                            m.namespace.clone(),
                            m.rule.clone(),
                            m.patterns
                                .iter()
                                .map(|(p, o)| format!("{p}@{o:#x}"))
                                .collect::<Vec<_>>()
                                .join(" "),
                        ]
                    })
                    .collect(),
                0,
            )
            .with_data(&matches),
        );
        for m in matches {
            out.finding(
                Finding::new(
                    format!("YARA-{}", m.rule),
                    Severity::Medium,
                    "yara",
                    format!("YARA rule matched: {}", m.rule),
                )
                .evidence_all(m.patterns.iter().map(|(p, o)| format!("{p} at {o:#x}"))),
            );
        }
        Ok(out)
    }
}
