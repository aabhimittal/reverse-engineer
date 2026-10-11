//! The `code.map` analyzer: a "codebase atlas" for an unfamiliar repository.

use crate::project::{self, Project};
use crate::{git, patterns};
use rex_core::{
    AnalysisOptions, Analyzer, AnalyzerOutput, Artifact, ArtifactKind, Finding, Location, Registry,
    Result, Section, Severity,
};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

/// Register code analyzers.
pub fn register(r: &mut Registry) {
    r.register(CodeMap);
}

/// Build the atlas for a directory.
pub struct CodeMap;

fn pct(a: usize, b: usize) -> String {
    if b == 0 {
        "0%".into()
    } else {
        format!("{:.0}%", a as f64 * 100.0 / b as f64)
    }
}

fn mermaid_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Collapse file paths to directories at `depth` (for graphs of large repos).
fn bucket(path: &str, depth: usize) -> String {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() <= depth {
        path.to_string()
    } else {
        parts[..depth].join("/") + "/"
    }
}

/// Module graph as Mermaid; aggregates to directories when there are too many files.
pub fn module_graph_mermaid(p: &Project, max_nodes: usize) -> (String, usize) {
    let involved: std::collections::BTreeSet<usize> =
        p.edges.iter().flat_map(|&(a, b)| [a, b]).collect();
    let mut depth = 8;
    let mut nodes: std::collections::BTreeSet<String>;
    loop {
        nodes = involved
            .iter()
            .map(|&i| bucket(&p.files[i].path, depth))
            .collect();
        if nodes.len() <= max_nodes || depth == 1 {
            break;
        }
        depth -= 1;
    }
    let mut edges: BTreeMap<(String, String), usize> = BTreeMap::new();
    for &(a, b) in &p.edges {
        let (x, y) = (
            bucket(&p.files[a].path, depth),
            bucket(&p.files[b].path, depth),
        );
        if x != y {
            *edges.entry((x, y)).or_default() += 1;
        }
    }
    // Keep the most connected nodes.
    let mut degree: HashMap<&String, usize> = HashMap::new();
    for ((x, y), n) in &edges {
        *degree.entry(x).or_default() += n;
        *degree.entry(y).or_default() += n;
    }
    let mut ranked: Vec<(&String, usize)> = degree.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let keep: std::collections::BTreeSet<String> = ranked
        .iter()
        .take(max_nodes)
        .map(|(n, _)| (*n).clone())
        .collect();
    let mut o = String::from("flowchart LR\n");
    for n in &keep {
        let _ = writeln!(o, "  {}[\"{}\"]", mermaid_id(n), n.replace('"', "'"));
    }
    for ((x, y), n) in &edges {
        if keep.contains(x) && keep.contains(y) {
            let label = if *n > 1 {
                format!("|{n}|")
            } else {
                String::new()
            };
            let _ = writeln!(o, "  {} -->{label} {}", mermaid_id(x), mermaid_id(y));
        }
    }
    (o, depth)
}

impl Analyzer for CodeMap {
    fn name(&self) -> &'static str {
        "code.map"
    }
    fn description(&self) -> &'static str {
        "Source tree → languages, stack, entry points, routes, module/call graphs, hotspots, ownership, security smells"
    }
    fn supports(&self, a: &Artifact) -> bool {
        a.kind() == ArtifactKind::Directory
    }
    fn priority(&self) -> i32 {
        10
    }
    fn analyze(&self, a: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let root = a
            .path()
            .ok_or_else(|| rex_core::Error::Unsupported("directory without a path".into()))?;
        let p = project::scan(root, 200_000);
        Ok(atlas(&p, opts))
    }
}

/// Compute all sections and findings for a scanned project.
pub fn atlas(p: &Project, opts: &AnalysisOptions) -> AnalyzerOutput {
    let mut out = AnalyzerOutput::new();
    let hist = git::history(&p.root, "24.months");
    let routes = patterns::routes(p);
    let entries = patterns::entry_points(p);
    let stack = patterns::stack(p);
    let (smells, secrets) = patterns::smells(p);
    let pr = p.pagerank(30);
    let indeg = p.in_degree();
    let fan = p.call_fan_in();
    let cycles = p.cycles();

    // ── Overview
    let code_files: Vec<_> = p.files.iter().filter(|f| f.lang.is_code()).collect();
    let total_code: usize = code_files.iter().map(|f| f.loc.code).sum();
    let test_code: usize = code_files
        .iter()
        .map(|f| {
            f.test_loc(|from| {
                std::fs::read_to_string(p.root.join(&f.path))
                    .map(|s| {
                        crate::lang::count(
                            f.lang,
                            &s.lines()
                                .skip(from as usize - 1)
                                .collect::<Vec<_>>()
                                .join("\n"),
                        )
                        .code
                    })
                    .unwrap_or(0)
            })
        })
        .sum();
    let defs: usize = p
        .files
        .iter()
        .filter_map(|f| f.syntax.as_ref())
        .map(|s| s.defs.len())
        .sum();
    let mut kv: Vec<(String, String)> = vec![
        (
            "Files".into(),
            format!("{} ({} source)", p.files.len(), code_files.len()),
        ),
        ("Lines of code".into(), total_code.to_string()),
        (
            "Test code".into(),
            format!("{test_code} lines ({})", pct(test_code, total_code)),
        ),
        ("Definitions parsed".into(), defs.to_string()),
        ("Internal import edges".into(), p.edges.len().to_string()),
        ("External dependencies".into(), p.external.len().to_string()),
        ("HTTP routes".into(), routes.len().to_string()),
        ("Entry points".into(), entries.len().to_string()),
    ];
    if let Some(h) = &hist {
        kv.push((
            "Git history".into(),
            format!(
                "{} commits total · first {} · last {}",
                h.total_commits
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "?".into()),
                h.first_commit.clone().unwrap_or_default(),
                h.last_commit.clone().unwrap_or_default()
            ),
        ));
        kv.push((
            "Active authors (24 mo)".into(),
            format!("{} · bus factor {}", h.authors.len(), h.bus_factor()),
        ));
    }
    if p.skipped > 0 {
        kv.push(("Skipped (limit)".into(), p.skipped.to_string()));
    }
    out.section(Section::kv("code.overview", "Codebase overview", kv));

    // ── Where to start reading
    let mut start = String::new();
    let _ = writeln!(
        start,
        "A suggested reading order, built from entry points, the module graph and change history:\n"
    );
    let mut n = 1;
    for e in entries
        .iter()
        .filter(|e| e.kind == "main" || e.kind == "cli")
        .take(3)
    {
        let _ = writeln!(start, "{n}. **Entry point**: `{}` ({})", e.at, e.what);
        n += 1;
    }
    let mut central: Vec<(usize, f64)> = pr
        .iter()
        .copied()
        .enumerate()
        .filter(|(i, _)| indeg[*i] > 0 && !p.files[*i].test)
        .collect();
    central.sort_by(|a, b| b.1.total_cmp(&a.1));
    for (i, _) in central.iter().take(5) {
        let _ = writeln!(
            start,
            "{n}. **Core module**: `{}` (imported by {} modules)",
            p.files[*i].path, indeg[*i]
        );
        n += 1;
    }
    if !routes.is_empty() {
        let _ = writeln!(
            start,
            "{n}. **API surface**: {} routes (see *HTTP routes*); start from `{}`",
            routes.len(),
            routes[0].at
        );
        n += 1;
    }
    let mut hotspots: Vec<(String, usize, u32, usize, f64)> = Vec::new();
    if let Some(h) = &hist {
        let max_c = p
            .files
            .iter()
            .map(|f| f.complexity())
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        let max_ch = h
            .files
            .values()
            .map(|f| f.commits)
            .max()
            .unwrap_or(1)
            .max(1) as f64;
        for f in p.files.iter().filter(|f| f.lang.is_code() && !f.generated) {
            if let Some(fh) = h.files.get(&f.path) {
                let cx = f.complexity().max(f.loc.code as u32 / 10);
                let score = (fh.commits as f64 / max_ch) * (cx as f64 / max_c);
                if score > 0.0 {
                    hotspots.push((f.path.clone(), fh.commits, cx, fh.authors.len(), score));
                }
            }
        }
        hotspots.sort_by(|a, b| b.4.total_cmp(&a.4));
        if let Some(top) = hotspots.first() {
            let _ = writeln!(
                start,
                "{n}. **Hotspot**: `{}` changes often *and* is complex: expect bugs here",
                top.0
            );
        }
    }
    out.section(Section::text("code.start", "Where to start reading", start));

    // ── Languages
    let mut langs: BTreeMap<&str, (usize, usize, usize)> = BTreeMap::new();
    for f in &p.files {
        let e = langs.entry(f.lang.name()).or_default();
        e.0 += 1;
        e.1 += f.loc.code;
        e.2 += f.loc.comment;
    }
    let mut lrows: Vec<(usize, Vec<String>)> = langs
        .iter()
        .map(|(l, (files, code, comment))| {
            (
                *code,
                vec![
                    l.to_string(),
                    files.to_string(),
                    code.to_string(),
                    comment.to_string(),
                    pct(*code, total_code.max(1)),
                ],
            )
        })
        .collect();
    lrows.sort_by_key(|r| std::cmp::Reverse(r.0));
    out.section(Section::table(
        "code.languages",
        "Languages",
        &["language", "files", "code", "comments", "share"],
        lrows.into_iter().map(|r| r.1).collect(),
        0,
    ));

    // ── Stack
    if !stack.is_empty() {
        out.section(Section::table(
            "code.stack",
            "Technology stack",
            &["kind", "name"],
            stack
                .iter()
                .map(|(k, v)| vec![k.clone(), v.clone()])
                .collect(),
            0,
        ));
    }
    // ── Entry points & routes
    if !entries.is_empty() {
        out.section(Section::table(
            "code.entrypoints",
            "Entry points",
            &["kind", "what", "location"],
            entries
                .iter()
                .map(|e| vec![e.kind.into(), e.what.clone(), e.at.clone()])
                .collect(),
            opts.max_rows,
        ));
    }
    if !routes.is_empty() {
        out.section(
            Section::table(
                "code.routes",
                "HTTP routes",
                &["method", "path", "framework", "location"],
                routes
                    .iter()
                    .map(|r| {
                        vec![
                            r.method.clone(),
                            r.path.clone(),
                            r.framework.into(),
                            r.at.clone(),
                        ]
                    })
                    .collect(),
                opts.max_rows.max(200),
            )
            .with_data(&routes),
        );
    }
    // ── Module graph
    if !p.edges.is_empty() {
        let (g, depth) = module_graph_mermaid(p, 30);
        out.section(Section::diagram(
            "code.modules",
            if depth < 8 {
                format!("Module graph (directories, depth {depth})")
            } else {
                "Module graph".into()
            },
            "mermaid",
            g,
        ));
        let mut core: Vec<(usize, f64)> = pr.iter().copied().enumerate().collect();
        core.sort_by(|a, b| b.1.total_cmp(&a.1));
        out.section(Section::table(
            "code.core",
            "Most depended-upon modules",
            &["module", "imported by", "imports", "loc", "rank"],
            core.iter()
                .filter(|(i, _)| indeg[*i] > 0)
                .take(15)
                .map(|(i, r)| {
                    let outd = p.edges.iter().filter(|(a, _)| a == i).count();
                    vec![
                        p.files[*i].path.clone(),
                        indeg[*i].to_string(),
                        outd.to_string(),
                        p.files[*i].loc.code.to_string(),
                        format!("{:.3}", r * p.files.len() as f64),
                    ]
                })
                .collect(),
            0,
        ));
    }
    if !p.external.is_empty() {
        let mut ext: Vec<(&String, &usize)> = p.external.iter().collect();
        ext.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        out.section(Section::table(
            "code.dependencies",
            "External dependencies (by importing files)",
            &["package", "files"],
            ext.iter()
                .map(|(k, v)| vec![(*k).clone(), v.to_string()])
                .collect(),
            opts.max_rows,
        ));
    }
    // ── Functions
    let mut funcs: Vec<(u32, String, String, u32)> = Vec::new();
    for f in &p.files {
        if let Some(sx) = &f.syntax {
            for d in sx.defs.iter().filter(|d| d.kind.callable()) {
                let name = match &d.container {
                    Some(c) => format!("{c}::{}", d.name),
                    None => d.name.clone(),
                };
                funcs.push((
                    d.complexity,
                    name,
                    format!("{}:{}", f.path, d.line),
                    d.end_line - d.line + 1,
                ));
            }
        }
    }
    funcs.sort_by_key(|f| std::cmp::Reverse(f.0));
    if !funcs.is_empty() {
        out.section(Section::table(
            "code.complex",
            "Most complex functions",
            &["function", "complexity", "lines", "location"],
            funcs
                .iter()
                .take(20)
                .map(|(c, n, at, l)| vec![n.clone(), c.to_string(), l.to_string(), at.clone()])
                .collect(),
            0,
        ));
    }
    if !fan.is_empty() {
        out.section(Section::table(
            "code.called",
            "Most called functions (fan-in)",
            &["function", "callers", "complexity", "location"],
            fan.iter()
                .take(20)
                .map(|(n, at, c, k)| vec![n.clone(), k.to_string(), c.to_string(), at.clone()])
                .collect(),
            0,
        ));
    }
    // ── History
    if let Some(h) = &hist {
        if !hotspots.is_empty() {
            out.section(Section::table(
                "code.hotspots",
                "Hotspots (churn × complexity, last 24 months)",
                &["file", "commits", "complexity", "authors", "score"],
                hotspots
                    .iter()
                    .take(15)
                    .map(|(f, c, x, a, s)| {
                        vec![
                            f.clone(),
                            c.to_string(),
                            x.to_string(),
                            a.to_string(),
                            format!("{s:.2}"),
                        ]
                    })
                    .collect(),
                0,
            ));
        }
        let mut authors: Vec<(&String, &usize)> = h.authors.iter().collect();
        authors.sort_by(|a, b| b.1.cmp(a.1));
        out.section(Section::table(
            "code.authors",
            "Contributors (last 24 months)",
            &["author", "commits", "share"],
            authors
                .iter()
                .take(15)
                .map(|(a, n)| vec![(*a).clone(), n.to_string(), pct(**n, h.commits)])
                .collect(),
            0,
        ));
        let silos: Vec<String> = hotspots
            .iter()
            .take(30)
            .filter(|(f, c, ..)| *c >= 5 && h.files.get(f).is_some_and(|fh| fh.authors.len() == 1))
            .map(|(f, c, ..)| format!("{f} ({c} commits, single author)"))
            .collect();
        if !silos.is_empty() {
            out.finding(
                Finding::new("CODE-KNOWLEDGE-SILO", Severity::Info, "maintainability", "Busy files owned by a single author")
                    .describe("Knowledge concentrated in one person is a bus-factor risk; pair or document these.")
                    .evidence_all(silos),
            );
        }
    }
    // ── Findings
    if !cycles.is_empty() {
        out.finding(
            Finding::new(
                "CODE-IMPORT-CYCLE",
                Severity::Low,
                "architecture",
                format!("{} import cycle(s)", cycles.len()),
            )
            .describe(
                "Cyclic dependencies make modules impossible to understand or test in isolation.",
            )
            .evidence_all(cycles.iter().take(10).map(|c| {
                c.iter()
                    .map(|&i| p.files[i].path.as_str())
                    .collect::<Vec<_>>()
                    .join(" ↔ ")
            })),
        );
    }
    let mut by_rule: BTreeMap<&str, Vec<&patterns::Smell>> = BTreeMap::new();
    for s in &smells {
        by_rule.entry(s.id).or_default().push(s);
    }
    for (id, v) in by_rule {
        let s0 = v[0];
        out.finding(
            Finding::new(
                id,
                s0.severity,
                "code-smell",
                format!("{} ({}×)", s0.title, v.len()),
            )
            .evidence_all(
                v.iter()
                    .take(15)
                    .map(|s| format!("{}:{}: {}", s.file, s.line, s.snippet)),
            )
            .at(Location {
                file: Some(s0.file.clone()),
                line: Some(s0.line),
                ..Default::default()
            }),
        );
    }
    let hi: Vec<_> = secrets.iter().filter(|(_, h)| h.high).collect();
    if !hi.is_empty() {
        out.finding(
            Finding::new("CODE-HARDCODED-SECRET", Severity::High, "secret", format!("{} hard-coded secret(s) in source", hi.len()))
                .describe("Move to a secret manager / environment and rotate: git history keeps the old value forever.")
                .evidence_all(hi.iter().take(15).map(|(f, h)| format!("{f}:{}: {}: {}", h.line, h.kind, rex_core::secrets::mask(&h.value))))
                .attack("T1552.001")
                .at(Location { file: Some(hi[0].0.clone()), line: Some(hi[0].1.line), ..Default::default() }),
        );
    }
    if total_code > 2000 && test_code * 20 < total_code {
        out.finding(Finding::new(
            "CODE-LOW-TEST-RATIO",
            Severity::Info,
            "quality",
            format!(
                "Test code is only {} of the codebase",
                pct(test_code, total_code)
            ),
        ));
    }
    if let Some(top) = funcs.first().filter(|f| f.0 >= 25) {
        out.finding(
            Finding::new(
                "CODE-COMPLEX-FUNCTION",
                Severity::Info,
                "quality",
                format!("Very complex function: {} (cyclomatic {})", top.1, top.0),
            )
            .evidence_all(
                funcs
                    .iter()
                    .take_while(|f| f.0 >= 25)
                    .take(10)
                    .map(|(c, n, at, _)| format!("{n} ({c}) at {at}")),
            ),
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atlas_on_tiny_repo() {
        let d = tempfile::tempdir().unwrap();
        for (p, c) in [
            (
                "app/main.py",
                "from app import db\nimport flask\n\n@app.route('/x')\ndef main():\n    db.q()\n\nif __name__ == '__main__':\n    main()\n",
            ),
            (
                "app/db.py",
                "def q():\n    cur.execute(f\"SELECT * FROM t WHERE id={id}\")\n",
            ),
            ("app/__init__.py", ""),
        ] {
            let path = d.path().join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, c).unwrap();
        }
        let a = Artifact::from_path(d.path(), rex_core::DEFAULT_MAX_SIZE).unwrap();
        let mut r = Registry::new();
        register(&mut r);
        let rep = r.run(&a, &AnalysisOptions::default(), &[]);
        assert!(rep.errors.is_empty(), "{:?}", rep.errors);
        for id in [
            "code.overview",
            "code.start",
            "code.languages",
            "code.routes",
            "code.modules",
            "code.entrypoints",
        ] {
            assert!(rep.section(id).is_some(), "missing {id}");
        }
        assert!(rep.findings.iter().any(|f| f.id == "CODE-SQL-CONCAT"));
        let md = rex_report::render(&rep, rex_report::Format::Markdown, Default::default());
        assert!(md.contains("```mermaid"));
    }
}
