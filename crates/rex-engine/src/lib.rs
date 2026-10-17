//! # rex-engine
//!
//! The high-level verbs of rex (*analyze*, *disassemble*, *diff*, *carve*,
//! *har-to-openapi*, …) as plain functions returning [`Report`]s or text.
//! The CLI and the MCP server are thin shells over this crate, so both
//! interfaces always behave identically.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rex_binary::functions::{self, Program};
use rex_binary::{Binary, carve, diff, strings};
use rex_core::{
    AnalysisOptions, Artifact, ArtifactKind, ArtifactSummary, Error, Finding, Registry, Report,
    Result, Section, SectionBody, Severity,
};
use std::path::Path;
use std::time::Instant;

pub use rex_core;
pub use rex_report;

/// Every analyzer rex ships.
pub fn registry() -> Registry {
    let mut r = Registry::new();
    rex_binary::register(&mut r);
    rex_web::register(&mut r);
    rex_code::register(&mut r);
    r
}

/// Load a path, optionally forcing its kind.
pub fn load(path: &Path, max_size: u64, kind: Option<ArtifactKind>) -> Result<Artifact> {
    let a = Artifact::from_path(path, max_size)?;
    Ok(match kind {
        Some(k) => a.with_kind(k),
        None => a,
    })
}

/// Run every applicable analyzer.
pub fn analyze(a: &Artifact, opts: &AnalysisOptions, only: &[String]) -> Report {
    registry().run(a, opts, only)
}

fn native(a: &Artifact) -> Result<Binary> {
    if !a.kind().is_native_binary() {
        return Err(Error::Unsupported(format!(
            "{} is a {}, not an ELF/PE/Mach-O executable",
            a.name(),
            a.kind()
        )));
    }
    Ok(Binary::of(a)?.as_ref().clone())
}

/// A native binary with code to analyse: cores hold a crashed process's memory, not a program.
fn native_code(a: &Artifact) -> Result<Binary> {
    let b = native(a)?;
    if b.core.is_some() {
        return Err(Error::Unsupported(
            "core dump: use `rex core` or `rex analyze`".into(),
        ));
    }
    Ok(b)
}

fn new_report(title: String, a: &Artifact) -> Report {
    Report::new(title, ArtifactSummary::of(a))
}

fn hex(v: u64) -> String {
    format!("{v:#x}")
}

/// Parse a hex (`0x…`) or decimal address.
pub fn parse_addr(s: &str) -> Option<u64> {
    let s = s.trim();
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .map(|h| u64::from_str_radix(h, 16).ok())
        .unwrap_or_else(|| s.parse().ok())
}

/// Annotated listing of one recovered function.
pub fn function_listing(p: &Program, f: &functions::Function) -> String {
    functions::function_listing(p, f)
}

/// Recover the program (functions, CFGs) for a native binary.
pub fn program(a: &Artifact, opts: &AnalysisOptions) -> Result<(Binary, Program)> {
    let b = native_code(a)?;
    let p = functions::analyze(&b, a.data(), opts);
    Ok((b, p))
}

/// Compact checksec tables across many files (one table per executable format).
pub fn checksec_many(arts: &[Artifact]) -> Report {
    let start = Instant::now();
    // format → (column order, rows of (file, cells))
    type Rows = Vec<(String, Vec<(&'static str, String)>)>;
    let mut groups: Vec<(String, Vec<&'static str>, Rows)> = Vec::new();
    let mut errors = Vec::new();
    let mut findings = Vec::new();
    for a in arts {
        match native_code(a) {
            Ok(b) => {
                let fmt = b.format.as_str().to_string();
                let idx = match groups.iter().position(|g| g.0 == fmt) {
                    Some(i) => i,
                    None => {
                        groups.push((fmt.clone(), vec!["arch"], Vec::new()));
                        groups.len() - 1
                    }
                };
                let g = &mut groups[idx];
                let mut cells = vec![("arch", format!("{} {}", b.arch.name(), b.file_type))];
                for m in &b.mitigations {
                    if !g.1.contains(&m.name) {
                        g.1.push(m.name);
                    }
                    cells.push((m.name, m.status.label().to_string()));
                }
                if b.mitigations.iter().any(|m| {
                    matches!(m.name, "NX" | "DEP/NX" | "NX stack")
                        && m.status == rex_binary::model::MitigationStatus::Disabled
                }) {
                    findings.push(Finding::new(
                        "BIN-MITIGATION-NX",
                        Severity::High,
                        "mitigation",
                        format!("{}: NX disabled", a.name()),
                    ));
                }
                g.2.push((a.name().to_string(), cells));
            }
            Err(e) => errors.push(format!("{}: {e}", a.name())),
        }
    }
    let summary = ArtifactSummary {
        name: format!("{} file(s)", arts.len()),
        size: arts.iter().map(|a| a.size()).sum(),
        ..Default::default()
    };
    let mut rep = Report::new(format!("rex checksec: {} file(s)", arts.len()), summary);
    for (fmt, cols, rows) in groups {
        let mut header = vec!["file"];
        header.extend(cols.iter().copied());
        let table: Vec<Vec<String>> = rows
            .into_iter()
            .map(|(n, cells)| {
                let mut r = vec![n];
                for c in &cols {
                    r.push(
                        cells
                            .iter()
                            .find(|(k, _)| k == c)
                            .map(|(_, v)| v.clone())
                            .unwrap_or_else(|| "-".into()),
                    );
                }
                r
            })
            .collect();
        rep.push(Section::table(
            format!("checksec.{}", fmt.to_ascii_lowercase()),
            format!("{fmt} mitigations"),
            &header,
            table,
            0,
        ));
    }
    rep.errors = errors;
    rep.findings = findings;
    rep.sort_findings();
    rep.duration_ms = start.elapsed().as_millis() as u64;
    rep
}

/// Crash triage of an ELF core dump (the `binary.core` analyzer on its own).
pub fn core_report(a: &Artifact, opts: &AnalysisOptions) -> Result<Report> {
    if native(a)?.core.is_none() {
        return Err(Error::Unsupported(format!(
            "{} is not a core dump (ELF ET_CORE)",
            a.name()
        )));
    }
    let mut rep = analyze(a, opts, &["binary.core".into()]);
    rep.title = format!("rex core: {}", a.name());
    Ok(rep)
}

/// Strings with optional category filter.
pub fn strings_report(a: &Artifact, min_len: usize, all: bool, categories: &[String]) -> Report {
    let start = Instant::now();
    let found = strings::extract(a.data(), min_len);
    let rows: Vec<Vec<String>> = found
        .iter()
        .filter(|s| all || s.category != strings::Category::Other || !categories.is_empty())
        .filter(|s| {
            categories.is_empty()
                || categories
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(s.category.as_str()))
        })
        .filter(|s| all || !categories.is_empty() || s.category != strings::Category::Format)
        .map(|s| {
            vec![
                hex(s.offset),
                format!("{:?}", s.encoding).to_lowercase(),
                s.category.as_str().into(),
                s.text.clone(),
            ]
        })
        .collect();
    let mut rep = new_report(format!("rex strings: {}", a.name()), a);
    let n = rows.len();
    rep.push(Section::table(
        "strings",
        format!("Strings ({n} of {} shown)", found.len()),
        &["offset", "encoding", "category", "string"],
        rows,
        0,
    ));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    rep
}

/// Function list.
pub fn functions_report(a: &Artifact, opts: &AnalysisOptions) -> Result<Report> {
    let start = Instant::now();
    let (_, p) = program(a, opts)?;
    let callers = p.callers();
    let rows = p
        .functions
        .values()
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
                f.calls.len().to_string(),
                f.imports_called.join(", "),
            ]
        })
        .collect();
    let mut rep = new_report(format!("rex functions: {}", a.name()), a);
    rep.push(
        Section::table(
            "functions",
            format!("Functions ({})", p.functions.len()),
            &[
                "address",
                "name",
                "size",
                "blocks",
                "cyclomatic",
                "callers",
                "callees",
                "imports",
            ],
            rows,
            0,
        )
        .with_data(program_summary(&p)),
    );
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Machine-readable shape of a recovered program without the instruction listings. Serializing
/// every instruction of every block made `rex functions` spend most of its time in serde on large
/// binaries (a Go hello world has ~2M instructions); `rex disasm` is the way to get listings.
fn program_summary(p: &Program) -> serde_json::Value {
    let funcs: Vec<serde_json::Value> = p
        .functions
        .values()
        .map(|f| {
            serde_json::json!({
                "addr": f.addr,
                "name": f.name,
                "size": f.size,
                "insns": f.insn_count(),
                "cyclomatic": f.cyclomatic(),
                "blocks": f.blocks.iter().map(|b| serde_json::json!({
                    "start": b.start,
                    "end": b.end,
                    "succs": b.succs,
                })).collect::<Vec<_>>(),
                "calls": f.calls,
                "imports_called": f.imports_called,
                "strings": f.strings,
                "thunk_to": f.thunk_to,
            })
        })
        .collect();
    serde_json::json!({
        "functions": funcs,
        "stubs": p.stubs,
        "main": p.main,
        "unsupported_arch": p.unsupported_arch,
    })
}

/// Disassemble a function (by name/address) or a raw range.
pub fn disasm(
    a: &Artifact,
    opts: &AnalysisOptions,
    function: Option<&str>,
    addr: Option<u64>,
    count: usize,
) -> Result<String> {
    if a.kind() == ArtifactKind::Wasm {
        return wasm_disasm(a, function);
    }
    let (b, p) = program(a, opts)?;
    if p.unsupported_arch {
        #[cfg(feature = "multiarch")]
        {
            let start = addr
                .or_else(|| function.and_then(|f| b.find_symbol(f).map(|s| s.addr)))
                .unwrap_or(b.entry);
            let bytes = b
                .bytes_at(a.data(), start)
                .ok_or_else(|| Error::Other(format!("{start:#x} is not mapped")))?;
            let insns =
                rex_binary::disasm::linear_capstone(&b.arch, b.little_endian, bytes, start, count)
                    .map_err(Error::Other)?;
            return Ok(rex_binary::disasm::listing(&insns, &Default::default()));
        }
        #[cfg(not(feature = "multiarch"))]
        return Err(Error::Unsupported(format!(
            "{} disassembly needs the `multiarch` feature",
            b.arch.name()
        )));
    }
    if let Some(f) = function {
        let func = p
            .find(f)
            .ok_or_else(|| Error::Other(format!("no function '{f}' (try `rex functions`)")))?;
        return Ok(functions::function_listing(&p, func));
    }
    let start = addr.unwrap_or(b.entry);
    let bytes = b
        .bytes_at(a.data(), start)
        .ok_or_else(|| Error::Other(format!("{start:#x} is not in a mapped section")))?;
    let names = rex_binary::disasm::Names(std::sync::Arc::new(p.names.clone()));
    let mut x = rex_binary::disasm::decoder_for(&b, &names)
        .ok_or_else(|| Error::Unsupported(format!("{} control-flow analysis", b.arch.name())))?;
    let insns = x.linear(bytes, start, count);
    let comments = insns
        .iter()
        .filter_map(|i| {
            i.data_ref.and_then(|r| p.strings_at.get(&r)).map(|s| {
                (
                    i.addr,
                    format!(
                        "\"{}\"",
                        s.chars().take(60).collect::<String>().escape_debug()
                    ),
                )
            })
        })
        .collect();
    Ok(rex_binary::disasm::listing(&insns, &comments))
}

/// Resolve a WebAssembly function by index (`4`, `func_4`), `module.name` (imports) or name.
fn wasm_resolve(m: &rex_binary::wasm::Module, q: &str) -> Option<u32> {
    let total = (m.imported_functions + m.defined_functions) as u32;
    let q = q.trim_start_matches('$');
    if let Some(n) = q
        .strip_prefix("func_")
        .unwrap_or(q)
        .parse::<u32>()
        .ok()
        .filter(|n| *n < total)
    {
        return Some(n);
    }
    if let Some(n) = m
        .imports
        .iter()
        .filter(|i| i.kind == rex_binary::wasm::ExternKind::Func)
        .position(|i| i.name == q)
    {
        return Some(n as u32);
    }
    (0..total).find(|&i| m.label(i) == q || m.func_name(i) == q)
}

fn wasm_disasm(a: &Artifact, function: Option<&str>) -> Result<String> {
    let m = rex_binary::wasm::parse(a.data())?;
    let idx = match function {
        Some(f) => wasm_resolve(&m, f)
            .ok_or_else(|| Error::Other(format!("no function '{f}' (try `rex analyze`)")))?,
        None => m
            .start
            .or_else(|| {
                m.exports
                    .iter()
                    .find(|e| e.kind == rex_binary::wasm::ExternKind::Func)
                    .map(|e| e.index)
            })
            .ok_or_else(|| {
                Error::Other("module has no start or exported function; pass -F".into())
            })?,
    };
    Ok(rex_binary::wasm_ops::disassemble(&m, a.data(), idx)?.render())
}

fn wasm_xrefs(a: &Artifact, target: &str) -> Result<Report> {
    let start = Instant::now();
    let m = rex_binary::wasm::parse(a.data())?;
    let idx = wasm_resolve(&m, target)
        .ok_or_else(|| Error::Other(format!("no function or import '{target}'")))?;
    let edges = rex_binary::wasm_ops::call_edges(&m, a.data());
    let mut rep = new_report(format!("rex xrefs: {target} in {}", a.name()), a);
    let kind = if (idx as usize) < m.imported_functions {
        "import"
    } else {
        "defined"
    };
    rep.push(Section::kv(
        "xrefs.target",
        "Function",
        [
            ("Name".to_string(), m.label(idx)),
            ("Index".to_string(), idx.to_string()),
            ("Kind".to_string(), kind.to_string()),
        ],
    ));
    let mut callers: Vec<u32> = edges
        .iter()
        .filter(|(_, c)| *c == idx)
        .map(|(f, _)| *f)
        .collect();
    callers.dedup();
    rep.push(Section::table(
        "xrefs.callers",
        "Called by",
        &["index", "function"],
        callers
            .iter()
            .map(|c| vec![c.to_string(), m.label(*c)])
            .collect(),
        0,
    ));
    let mut callees: Vec<u32> = edges
        .iter()
        .filter(|(f, _)| *f == idx)
        .map(|(_, c)| *c)
        .collect();
    callees.dedup();
    rep.push(Section::table(
        "xrefs.callees",
        "Calls",
        &["index", "function"],
        callees
            .iter()
            .map(|c| vec![c.to_string(), m.label(*c)])
            .collect(),
        0,
    ));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// CFG of a function in `dot` or `mermaid`.
pub fn cfg(a: &Artifact, opts: &AnalysisOptions, function: &str, format: &str) -> Result<String> {
    let (_, p) = program(a, opts)?;
    let f = p
        .find(function)
        .ok_or_else(|| Error::Other(format!("no function '{function}'")))?;
    Ok(match format {
        "dot" => functions::cfg_dot(f),
        _ => functions::cfg_mermaid(f, 8),
    })
}

/// Call graph from a function (or entry) as Mermaid.
pub fn callgraph(
    a: &Artifact,
    opts: &AnalysisOptions,
    root: Option<&str>,
    max_nodes: usize,
) -> Result<String> {
    let (b, p) = program(a, opts)?;
    let r = match root {
        Some(n) => p
            .find(n)
            .map(|f| f.addr)
            .ok_or_else(|| Error::Other(format!("no function '{n}'")))?,
        None => p
            .main
            .or_else(|| p.find("main").map(|f| f.addr))
            .unwrap_or(b.entry),
    };
    Ok(functions::callgraph_mermaid(&p, r, max_nodes))
}

/// Cross-references: callers/callees of a function, or functions referencing a string.
pub fn xrefs(a: &Artifact, opts: &AnalysisOptions, target: &str) -> Result<Report> {
    let start = Instant::now();
    if a.kind() == ArtifactKind::Wasm {
        return wasm_xrefs(a, target);
    }
    let (_, p) = program(a, opts)?;
    let mut rep = new_report(format!("rex xrefs: {target} in {}", a.name()), a);
    if let Some(f) = p.find(target) {
        let callers = p.callers();
        let rows: Vec<Vec<String>> = callers
            .get(&f.addr)
            .map(|v| v.iter().map(|c| vec![hex(*c), p.name_of(*c)]).collect())
            .unwrap_or_default();
        rep.push(Section::kv(
            "xrefs.target",
            "Function",
            [
                ("Name", f.name.clone()),
                ("Address", hex(f.addr)),
                ("Size", f.size.to_string()),
                ("Cyclomatic", f.cyclomatic().to_string()),
            ],
        ));
        rep.push(Section::table(
            "xrefs.callers",
            "Called by",
            &["address", "function"],
            rows,
            0,
        ));
        let mut callees: Vec<Vec<String>> = f
            .calls
            .iter()
            .map(|c| vec![hex(*c), p.name_of(*c)])
            .collect();
        callees.extend(
            f.imports_called
                .iter()
                .map(|i| vec!["import".into(), i.clone()]),
        );
        rep.push(Section::table(
            "xrefs.callees",
            "Calls",
            &["address", "function"],
            callees,
            0,
        ));
        rep.push(Section::table(
            "xrefs.strings",
            "Strings referenced",
            &["string"],
            f.strings.iter().map(|s| vec![s.clone()]).collect(),
            0,
        ));
    } else {
        let needle = target.to_ascii_lowercase();
        let rows: Vec<Vec<String>> = p
            .functions
            .values()
            .flat_map(|f| {
                f.strings
                    .iter()
                    .filter(|s| s.to_ascii_lowercase().contains(&needle))
                    .map(move |s| vec![hex(f.addr), f.name.clone(), s.clone()])
            })
            .collect();
        let imp_rows: Vec<Vec<String>> = p
            .functions
            .values()
            .filter(|f| {
                f.imports_called
                    .iter()
                    .any(|i| i.eq_ignore_ascii_case(target))
            })
            .map(|f| vec![hex(f.addr), f.name.clone(), format!("calls {target}")])
            .collect();
        if rows.is_empty() && imp_rows.is_empty() {
            return Err(Error::Other(format!(
                "'{target}' is not a function, import or referenced string"
            )));
        }
        rep.push(Section::table(
            "xrefs.uses",
            format!("Code referencing \"{target}\""),
            &["address", "function", "reference"],
            rows.into_iter().chain(imp_rows).collect(),
            0,
        ));
    }
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Signature scan; optionally extract into `out`.
pub fn carve_report(a: &Artifact, out: Option<&Path>) -> Result<Report> {
    let start = Instant::now();
    let hits = carve::scan(a.data(), false);
    let mut rep = new_report(format!("rex carve: {}", a.name()), a);
    rep.push(
        Section::table(
            "carve",
            format!("Embedded objects ({})", hits.len()),
            &["offset", "type", "size", "description"],
            hits.iter()
                .map(|h| {
                    vec![
                        hex(h.offset),
                        h.kind.into(),
                        h.size.map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                        h.description.clone(),
                    ]
                })
                .collect(),
            0,
        )
        .with_data(&hits),
    );
    if let Some(dir) = out {
        let written = carve::extract(a.data(), &hits, dir).map_err(|e| Error::Io {
            path: dir.into(),
            source: e,
        })?;
        rep.push(Section::table(
            "carve.extracted",
            format!("Extracted to {}", dir.display()),
            &["file", "bytes"],
            written
                .iter()
                .map(|p| {
                    vec![
                        p.display().to_string(),
                        std::fs::metadata(p)
                            .map(|m| m.len())
                            .unwrap_or(0)
                            .to_string(),
                    ]
                })
                .collect(),
            0,
        ));
    }
    let block = (a.data().len() / 128).clamp(256, 1 << 20);
    let prof = rex_core::hash::entropy_profile(a.data(), block);
    let vals: Vec<f64> = prof.iter().map(|p| p.1).collect();
    rep.push(Section::code(
        "carve.entropy",
        "Entropy profile",
        "text",
        format!(
            "{}\nblock {block} B · ▁=0 … █=8 bits/byte",
            rex_core::hash::sparkline(&vals, 8.0)
        ),
    ));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Diff two native binaries.
pub fn diff_report(old: &Artifact, new: &Artifact, opts: &AnalysisOptions) -> Result<Report> {
    let start = Instant::now();
    let (ba, pa) = program(old, opts)?;
    let (bb, pb) = program(new, opts)?;
    let interesting = |a: &Artifact| -> Vec<String> {
        strings::interesting(&strings::extract(a.data(), 5))
            .map(|s| s.text.clone())
            .collect()
    };
    let (sa, sb) = (interesting(old), interesting(new));
    let d = diff::diff((&ba, &pa, &sa), (&bb, &pb, &sb));
    let mut rep = new_report(format!("rex diff: {} → {}", old.name(), new.name()), new);
    rep.push(Section::kv(
        "diff.summary",
        "Summary",
        [
            (
                "Functions (old → new)".to_string(),
                format!("{} → {}", pa.functions.len(), pb.functions.len()),
            ),
            (
                "Identical".to_string(),
                d.count(diff::Change::Identical).to_string(),
            ),
            (
                "Changed".to_string(),
                d.count(diff::Change::Changed).to_string(),
            ),
            (
                "Added".to_string(),
                d.count(diff::Change::Added).to_string(),
            ),
            (
                "Removed".to_string(),
                d.count(diff::Change::Removed).to_string(),
            ),
            (
                "Imports added / removed".to_string(),
                format!("{} / {}", d.imports_added.len(), d.imports_removed.len()),
            ),
            (
                "TLSH distance".to_string(),
                rex_binary::fingerprint::tlsh_distance(old.data(), new.data())
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "n/a".into()),
            ),
        ],
    ));
    let rows = d
        .functions
        .iter()
        .filter(|r| r.change != diff::Change::Identical)
        .map(|r| {
            vec![
                format!("{:?}", r.change).to_lowercase(),
                r.name.clone(),
                r.old_addr.map(hex).unwrap_or_default(),
                r.new_addr.map(hex).unwrap_or_default(),
                format!("{:.2}", r.similarity),
                format!("{:+}", r.insn_delta),
                format!("{:+}", r.block_delta),
                r.matched_by.to_string(),
            ]
        })
        .collect();
    rep.push(
        Section::table(
            "diff.functions",
            "Changed functions (least similar first)",
            &[
                "change",
                "function",
                "old",
                "new",
                "similarity",
                "Δinsns",
                "Δblocks",
                "matched by",
            ],
            rows,
            0,
        )
        .with_data(&d),
    );
    if !d.imports_added.is_empty() || !d.imports_removed.is_empty() {
        let mut rows: Vec<Vec<String>> = d
            .imports_added
            .iter()
            .map(|i| vec!["+".into(), i.clone()])
            .collect();
        rows.extend(
            d.imports_removed
                .iter()
                .map(|i| vec!["-".into(), i.clone()]),
        );
        rep.push(Section::table(
            "diff.imports",
            "Import changes",
            &["", "import"],
            rows,
            0,
        ));
    }
    if !d.strings_added.is_empty() || !d.strings_removed.is_empty() {
        let mut rows: Vec<Vec<String>> = d
            .strings_added
            .iter()
            .map(|i| vec!["+".into(), i.clone()])
            .collect();
        rows.extend(
            d.strings_removed
                .iter()
                .map(|i| vec!["-".into(), i.clone()]),
        );
        rep.push(Section::table(
            "diff.strings",
            "Interesting string changes",
            &["", "string"],
            rows,
            100,
        ));
    }
    if !d.sections.is_empty() {
        rep.push(Section::table(
            "diff.sections",
            "Section size changes",
            &["section", "old", "new"],
            d.sections
                .iter()
                .map(|(n, a, b)| vec![n.clone(), a.to_string(), b.to_string()])
                .collect(),
            0,
        ));
    }
    // Small, surgical changes in otherwise similar functions are what patch analysis looks for.
    let surgical: Vec<String> = d
        .functions
        .iter()
        .filter(|r| {
            r.change == diff::Change::Changed && r.similarity >= 0.7 && r.insn_delta.abs() <= 20
        })
        .take(10)
        .map(|r| {
            format!(
                "{} (similarity {:.2}, Δ{} insns)",
                r.name, r.similarity, r.insn_delta
            )
        })
        .collect();
    if !surgical.is_empty() {
        rep.findings.push(
            Finding::new("DIFF-SURGICAL-CHANGE", Severity::Info, "patch-analysis", "Small changes in otherwise similar functions")
                .describe("In security patches these are often the fix (an added bounds check). Start reviewing here.")
                .evidence_all(surgical),
        );
    }
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// HAR → (OpenAPI document, report).
pub fn har_to_openapi(
    a: &Artifact,
    include_static: bool,
    hosts: &[String],
    title: Option<&str>,
) -> Result<(serde_json::Value, Report)> {
    let start = Instant::now();
    let h = rex_web::har::parse(a.data())?;
    let eps = rex_web::har::extract(
        &h,
        &rex_web::har::ExtractOptions {
            include_static,
            hosts: hosts.to_vec(),
            min_distinct: 3,
        },
    );
    let spec = rex_web::openapi::build(&h, &eps, title);
    let mut rep = new_report(format!("rex har2openapi: {}", a.name()), a);
    rep.push(Section::table(
        "endpoints",
        format!(
            "{} endpoints from {} requests",
            eps.len(),
            h.log.entries.len()
        ),
        &["method", "path", "calls", "status"],
        eps.iter()
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
                ]
            })
            .collect(),
        0,
    ));
    rep.findings = rex_web::audit::audit(&h);
    rep.sort_findings();
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok((spec, rep))
}

/// Unpack a source map (file or inline map in a bundle) into `out`.
pub fn sourcemap_unpack(a: &Artifact, out: &Path) -> Result<Report> {
    let start = Instant::now();
    let data: Vec<u8> = if a.kind() == ArtifactKind::JavaScript {
        let src = String::from_utf8_lossy(a.data());
        let r = rex_web::js::analyze(&src);
        let url = r
            .source_map_url
            .ok_or_else(|| Error::Other("bundle has no sourceMappingURL".into()))?;
        match rex_web::js::inline_source_map(&url) {
            Some(d) => d,
            None => {
                let p = a
                    .path()
                    .and_then(|p| p.parent())
                    .map(|d| d.join(&url))
                    .ok_or_else(|| {
                        Error::Other(format!(
                            "external map '{url}': download it and pass the .map file"
                        ))
                    })?;
                std::fs::read(&p).map_err(|e| Error::Io { path: p, source: e })?
            }
        }
    } else {
        a.data().to_vec()
    };
    let map = rex_web::js::parse_source_map(&data)?;
    let (written, missing) = rex_web::js::unpack(&map, out).map_err(|e| Error::Io {
        path: out.into(),
        source: e,
    })?;
    let mut rep = new_report(format!("rex sourcemap: {}", a.name()), a);
    rep.push(Section::kv(
        "sourcemap",
        "Recovered sources",
        [
            ("Written".to_string(), written.len().to_string()),
            ("Without content".to_string(), missing.to_string()),
            ("Output".to_string(), out.display().to_string()),
        ],
    ));
    rep.push(Section::table(
        "sourcemap.files",
        "Files",
        &["path"],
        written
            .iter()
            .map(|p| vec![p.display().to_string()])
            .collect(),
        0,
    ));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Extract an Electron `app.asar` into `out` (paths that would escape `out` are skipped).
pub fn asar_unpack(a: &Artifact, out: &Path) -> Result<Report> {
    let start = Instant::now();
    let ar = rex_web::asar::parse(a.data())?;
    std::fs::create_dir_all(out).map_err(|e| Error::Io {
        path: out.into(),
        source: e,
    })?;
    let (written, skipped) = ar.extract(out).map_err(|e| Error::Io {
        path: out.into(),
        source: e,
    })?;
    let mut rep = new_report(format!("rex asar: {}", a.name()), a);
    rep.push(Section::kv(
        "asar",
        "Extracted Electron archive",
        [
            ("Written".to_string(), written.to_string()),
            (
                "Skipped (links, unpacked or unsafe paths)".to_string(),
                skipped.to_string(),
            ),
            ("Output".to_string(), out.display().to_string()),
        ],
    ));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

/// Serialise an OpenAPI (or any JSON) document as YAML.
pub fn openapi_yaml(spec: &serde_json::Value) -> String {
    rex_web::yaml::to_yaml(spec)
}

/// Readiness report: compiled-in features, AI credentials and companion tools.
///
/// Presence is checked by looking on `PATH`; nothing is executed. rex does not call the
/// companion tools itself. They are what to open *next* once rex has told you where to look.
pub fn doctor_report(find: &dyn Fn(&str) -> Option<std::path::PathBuf>) -> Report {
    let mut rep = Report::new("rex doctor", ArtifactSummary::default());
    let yes = |b: bool| if b { "✔ yes" } else { "✘ no" }.to_string();
    rep.push(Section::kv(
        "doctor.build",
        "This build",
        [
            ("rex version".to_string(), rex_core::VERSION.to_string()),
            (
                "multiarch (ARM/MIPS/... disassembly)".to_string(),
                yes(cfg!(feature = "multiarch")),
            ),
            (
                "yara (YARA-X rules)".to_string(),
                yes(cfg!(feature = "yara")),
            ),
        ],
    ));
    let key = std::env::var_os("ANTHROPIC_API_KEY").is_some_and(|v| !v.is_empty())
        || std::env::var_os("ANTHROPIC_AUTH_TOKEN").is_some_and(|v| !v.is_empty());
    rep.push(Section::kv(
        "doctor.ai",
        "AI assistance (optional, opt-in)",
        [
            ("Claude credentials in environment".to_string(), yes(key)),
            (
                "Ollama (local) binary on PATH".to_string(),
                yes(find("ollama").is_some()),
            ),
        ],
    ));
    // (tool, executables to look for, what to use it for after rex)
    const TOOLS: &[(&str, &[&str], &str)] = &[
        (
            "Ghidra",
            &["ghidraRun", "analyzeHeadless"],
            "decompiler: open the addresses from `rex functions`",
        ),
        (
            "radare2 / rizin",
            &["r2", "rizin"],
            "interactive analysis: `r2 -A`, then `s <addr>; pdf`",
        ),
        (
            "objdump",
            &["objdump", "llvm-objdump"],
            "cross-check disassembly: `objdump -d -M intel`",
        ),
        (
            "gdb / lldb",
            &["gdb", "lldb"],
            "dynamic analysis once triage says what to break on",
        ),
        (
            "binwalk / unblob",
            &["binwalk", "unblob"],
            "deeper firmware extraction after `rex carve`",
        ),
        (
            "UPX",
            &["upx"],
            "`upx -d` when rex reports a UPX-packed binary",
        ),
        (
            "jadx",
            &["jadx", "jadx-gui"],
            "decompile APK classes after `rex apk`",
        ),
        ("apktool", &["apktool"], "decode APK resources"),
        ("YARA", &["yara"], "run community rule sets against samples"),
        (
            "mitmproxy",
            &["mitmproxy", "mitmdump"],
            "capture traffic, export HAR for `rex web har2openapi`",
        ),
        (
            "git",
            &["git"],
            "needed for `rex code map` history, hotspots and bus factor",
        ),
    ];
    let rows = TOOLS
        .iter()
        .map(|(name, exes, why)| {
            let found = exes.iter().find_map(|e| find(e));
            vec![
                name.to_string(),
                found
                    .map(|p| format!("✔ {}", p.display()))
                    .unwrap_or_else(|| "✘ not found".into()),
                why.to_string(),
            ]
        })
        .collect();
    rep.push(Section::table(
        "doctor.tools",
        "Companion tools (optional)",
        &["tool", "status", "use it for"],
        rows,
        0,
    ));
    rep
}

/// List analyzers.
pub fn analyzers_report() -> Report {
    let r = registry();
    let mut rep = Report::new("rex analyzers", ArtifactSummary::default());
    rep.push(Section::table(
        "analyzers",
        "Available analyzers",
        &["name", "description"],
        r.analyzers()
            .map(|a| vec![a.name().to_string(), a.description().to_string()])
            .collect(),
        0,
    ));
    rep
}

/// Compare two saved `rex analyze -f json` reports: findings that appeared, disappeared or
/// changed severity, and rows added to or removed from every table (imports, capabilities,
/// endpoints, dependencies, …). Addresses are ignored when matching rows, so a rebuild that only
/// moved code does not show up as a change. New and escalated findings are repeated as findings
/// of this report, so `rex compare old.json new.json --fail-on high` gates CI on regressions.
pub fn compare_reports(old_json: &str, new_json: &str) -> Result<Report> {
    use std::collections::{BTreeMap, BTreeSet};
    let start = Instant::now();
    let load = |s: &str, which: &str| -> Result<Report> {
        let v: serde_json::Value =
            serde_json::from_str(s).map_err(|e| Error::parse("report", format!("{which}: {e}")))?;
        // `rex analyze -f json` writes a list (one report per input); take the first.
        let first = match v {
            serde_json::Value::Array(mut a) if !a.is_empty() => a.swap_remove(0),
            o @ serde_json::Value::Object(_) => o,
            _ => {
                return Err(Error::parse(
                    "report",
                    format!("{which}: not a rex JSON report"),
                ));
            }
        };
        serde_json::from_value(first).map_err(|e| Error::parse("report", format!("{which}: {e}")))
    };
    let (old, new) = (load(old_json, "old")?, load(new_json, "new")?);

    let mut rep = Report::new(
        format!("rex compare: {} → {}", old.artifact.name, new.artifact.name),
        new.artifact.clone(),
    );
    let sev = |r: &Report| -> BTreeMap<String, (Severity, String)> {
        r.findings
            .iter()
            .map(|f| {
                (
                    format!("{}\u{1}{}", f.id, f.title),
                    (f.severity, f.title.clone()),
                )
            })
            .collect()
    };
    let (fo, fnw) = (sev(&old), sev(&new));
    let mut rows = Vec::new();
    for (k, (s, title)) in &fnw {
        let id = k.split('\u{1}').next().unwrap_or_default().to_string();
        match fo.get(k) {
            None => {
                rows.push(vec![
                    "added".into(),
                    s.as_str().into(),
                    id.clone(),
                    title.clone(),
                ]);
                rep.findings.push(Finding::new(
                    format!("COMPARE-NEW-{id}"),
                    *s,
                    "regression",
                    format!("New: {title}"),
                ));
            }
            Some((os, _)) if os != s => {
                rows.push(vec![
                    format!("{} → {}", os.as_str(), s.as_str()),
                    s.as_str().into(),
                    id.clone(),
                    title.clone(),
                ]);
                if s > os {
                    rep.findings.push(Finding::new(
                        format!("COMPARE-ESCALATED-{id}"),
                        *s,
                        "regression",
                        format!("Now {}: {title}", s.as_str()),
                    ));
                }
            }
            _ => {}
        }
    }
    for (k, (s, title)) in &fo {
        if !fnw.contains_key(k) {
            let id = k.split('\u{1}').next().unwrap_or_default().to_string();
            rows.push(vec!["removed".into(), s.as_str().into(), id, title.clone()]);
        }
    }
    let same_input = old.artifact.sha256.is_some() && old.artifact.sha256 == new.artifact.sha256;
    rep.push(Section::kv(
        "compare.summary",
        "Summary",
        [
            (
                "Old".to_string(),
                format!("{} ({})", old.artifact.name, crate::short_hash(&old)),
            ),
            (
                "New".to_string(),
                format!("{} ({})", new.artifact.name, crate::short_hash(&new)),
            ),
            ("Identical input".to_string(), same_input.to_string()),
            (
                "Findings".to_string(),
                format!("{} → {}", old.findings.len(), new.findings.len()),
            ),
            ("Finding changes".to_string(), rows.len().to_string()),
        ],
    ));
    rep.push(Section::table(
        "compare.findings",
        "Findings that changed",
        &["change", "severity", "id", "title"],
        rows,
        0,
    ));

    // Tables: set difference of rows, keyed on their non-address cells.
    let is_addr = |c: &str| c.starts_with("0x") && c[2..].chars().all(|d| d.is_ascii_hexdigit());
    let key = |row: &[String]| -> String {
        row.iter()
            .filter(|c| !is_addr(c))
            .cloned()
            .collect::<Vec<_>>()
            .join(" | ")
    };
    let tables = |r: &Report| -> BTreeMap<String, (String, BTreeSet<String>)> {
        r.sections
            .iter()
            .filter_map(|s| match &s.body {
                SectionBody::Table { rows, .. } => Some((
                    s.id.clone(),
                    (s.title.clone(), rows.iter().map(|r| key(r)).collect()),
                )),
                _ => None,
            })
            .collect()
    };
    let (to, tn) = (tables(&old), tables(&new));
    let ids: BTreeSet<&String> = to.keys().chain(tn.keys()).collect();
    let empty = BTreeSet::new();
    for id in ids {
        let o = to.get(id).map(|t| &t.1).unwrap_or(&empty);
        let n = tn.get(id).map(|t| &t.1).unwrap_or(&empty);
        let title = tn
            .get(id)
            .or_else(|| to.get(id))
            .map(|t| t.0.clone())
            .unwrap_or_default();
        let mut rows: Vec<Vec<String>> = n
            .difference(o)
            .map(|r| vec!["+".into(), r.clone()])
            .collect();
        rows.extend(o.difference(n).map(|r| vec!["-".into(), r.clone()]));
        if !rows.is_empty() {
            rep.push(Section::table(
                format!("compare.{id}"),
                format!(
                    "{title}: {} added, {} removed",
                    n.difference(o).count(),
                    o.difference(n).count()
                ),
                &["", "row"],
                rows,
                200,
            ));
        }
    }
    rep.findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    rep.duration_ms = start.elapsed().as_millis() as u64;
    Ok(rep)
}

fn short_hash(r: &Report) -> String {
    r.artifact
        .sha256
        .as_deref()
        .map(|h| h.chars().take(12).collect())
        .unwrap_or_else(|| "no hash".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture(name: &str) -> Artifact {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../rex-binary/tests/fixtures")
            .join(name);
        Artifact::from_path(p, rex_core::DEFAULT_MAX_SIZE).unwrap()
    }

    #[test]
    fn verbs_work_on_fixtures() {
        let o = AnalysisOptions::default();
        let a = fixture("crackme.elf");
        assert!(
            disasm(&a, &o, Some("check_password"), None, 50)
                .unwrap()
                .contains("strlen@plt")
        );
        assert!(
            disasm(&a, &o, None, Some(a_entry(&a)), 5)
                .unwrap()
                .lines()
                .count()
                == 5
        );
        assert!(
            cfg(&a, &o, "check_password", "dot")
                .unwrap()
                .starts_with("digraph")
        );
        assert!(
            callgraph(&a, &o, None, 10)
                .unwrap()
                .contains("check_password")
        );
        let x = xrefs(&a, &o, "check_password").unwrap();
        assert!(
            serde_json::to_string(&x.section("xrefs.callers").unwrap().body)
                .unwrap()
                .contains("main")
        );
        let s = xrefs(&a, &o, "Access granted").unwrap();
        assert!(s.section("xrefs.uses").is_some());
        assert!(xrefs(&a, &o, "no-such-thing-xyz").is_err());
        let d = diff_report(&a, &fixture("crackme.stripped.elf"), &o).unwrap();
        assert!(d.section("diff.summary").is_some());
        let c = checksec_many(&[
            a,
            fixture("vuln.elf"),
            fixture("sample.exe"),
            fixture("hello.macho"),
        ]);
        assert!(c.findings.iter().any(|f| f.title.contains("vuln.elf")));
        assert!(
            functions_report(&fixture("sample.exe"), &o)
                .unwrap()
                .section("functions")
                .is_some()
        );
        assert!(analyzers_report().section("analyzers").is_some());
        assert!(parse_addr("0x10") == Some(16) && parse_addr("16") == Some(16));
    }

    fn a_entry(a: &Artifact) -> u64 {
        Binary::parse(a.data()).unwrap().entry
    }

    #[test]
    fn web_verbs() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../labs/web");
        let har = Artifact::from_path(root.join("sample.har"), rex_core::DEFAULT_MAX_SIZE).unwrap();
        let (spec, rep) = har_to_openapi(&har, false, &[], Some("Shop")).unwrap();
        assert_eq!(spec["info"]["title"], "Shop");
        assert!(!rep.findings.is_empty());
        let js = Artifact::from_path(root.join("bundle/app.min.js"), rex_core::DEFAULT_MAX_SIZE)
            .unwrap();
        let out = tempfile::tempdir().unwrap();
        let r = sourcemap_unpack(&js, out.path()).unwrap();
        assert!(r.section("sourcemap").is_some());
        assert!(out.path().join("src/config.ts").exists());
    }

    #[cfg(feature = "multiarch")]
    #[test]
    fn arm_listing_cfg_and_address_mode_use_the_arm_decoder() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../rex-binary/tests/fixtures/sample_a64.elf");
        let a = Artifact::from_bytes("sample_a64.elf", std::fs::read(path).unwrap());
        let o = AnalysisOptions::default();
        let text = disasm(&a, &o, Some("check"), None, 0).unwrap();
        assert!(
            text.contains("cbz") && text.contains("open-sesame"),
            "{text}"
        );
        let mm = cfg(&a, &o, "check", "mermaid").unwrap();
        assert!(mm.contains("-- T -->") && mm.contains("-- F -->"), "{mm}");
        let b = rex_binary::Binary::parse(a.data()).unwrap();
        let main = b.find_symbol("main").unwrap().addr;
        let at = disasm(&a, &o, None, Some(main), 4).unwrap();
        assert!(
            at.contains("stp"),
            "address mode must decode AArch64, not x86: {at}"
        );
    }

    #[test]
    fn wasm_disasm_and_xrefs_resolve_names_indices_and_imports() {
        let data = std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../labs/wasm/sample.wasm"),
        )
        .unwrap();
        let a = Artifact::from_bytes("sample.wasm", data);
        let o = AnalysisOptions::default();
        let text = disasm(&a, &o, Some("decrypt_config"), None, 0).unwrap();
        assert!(text.contains("br_if 0  ;; -> loop"), "{text}");
        assert_eq!(
            disasm(&a, &o, Some("4"), None, 0).unwrap(),
            text,
            "index works too"
        );
        assert!(
            disasm(&a, &o, None, None, 0).unwrap().contains("$run"),
            "defaults to start"
        );
        assert!(disasm(&a, &o, Some("nope"), None, 0).is_err());

        for q in ["path_open", "wasi_snapshot_preview1.path_open", "0"] {
            let r = xrefs(&a, &o, q).unwrap();
            let callers = serde_json::to_string(r.section("xrefs.callers").unwrap()).unwrap();
            assert!(callers.contains("run"), "{q}: {callers}");
        }
        let r = xrefs(&a, &o, "run").unwrap();
        let callees = serde_json::to_string(r.section("xrefs.callees").unwrap()).unwrap();
        assert!(callees.contains("decrypt_config") && callees.contains("sock_connect"));
    }
}
