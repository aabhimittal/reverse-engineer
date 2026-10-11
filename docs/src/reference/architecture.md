# Architecture and writing analyzers

```text
input ──► Artifact ──► detect kind ──► Analyzer registry (parallel, panic-isolated)
                                         │
                                         ▼
                              Sections + Findings ──► Report ──► text | json | md | sarif | html
```

| Crate | Role |
|---|---|
| `rex-core` | `Artifact`, kind detection, `Analyzer` trait and `Registry`, `Finding`, `Report`, shared secret detection |
| `rex-report` | Renderers (terminal, JSON, Markdown, SARIF 2.1.0, self-contained HTML) |
| `rex-binary` | ELF/PE/Mach-O model, checksec, strings, capabilities, packer heuristics, disassembly, CFGs, carving, diffing |
| `rex-web` | HAR to OpenAPI, traffic audit, JS bundles, source maps, APK / DEX / AXML |
| `rex-code` | tree-sitter symbols, import graphs, routes, hotspots, atlas |
| `rex-engine` | High-level verbs shared by the CLI and MCP |
| `rex-cli` / `rex-mcp` / `rex-ai` | The `rex` binary, MCP server, optional LLM assistance |

## Design rules

1. **Never execute the input.** All analysis is static.
2. **Hostile input is the norm.** Parsers return errors instead of panicking; the registry also
   catches panics per analyzer; size and iteration limits bound work.
3. **Analyzers describe, renderers decide.** Analyzers return `Section` primitives
   (key/value, table, text, code, diagram) so every domain looks consistent in every format.
4. **Findings carry stable ids** (`BIN-MITIGATION-NX`) usable as SARIF rule ids and CI gates.

## Writing an analyzer

```rust
use rex_core::*;

pub struct HelloAnalyzer;

impl Analyzer for HelloAnalyzer {
    fn name(&self) -> &'static str { "demo.hello" }
    fn description(&self) -> &'static str { "Reports the file size" }
    fn supports(&self, a: &Artifact) -> bool { a.kind() == ArtifactKind::Blob }
    fn analyze(&self, a: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
        let mut out = AnalyzerOutput::new();
        out.section(Section::kv("demo.size", "Size", [("bytes", a.size().to_string())]));
        if a.size() == 0 {
            out.finding(Finding::new("DEMO-EMPTY", Severity::Low, "demo", "File is empty"));
        }
        Ok(out)
    }
}

let mut registry = Registry::new();
registry.register(HelloAnalyzer);
let report = registry.run(&artifact, &AnalysisOptions::default(), &[]);
```

Add tests next to it, run `cargo test`, and open a pull request. See `CONTRIBUTING.md`.
