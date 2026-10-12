//! `rex`: one command to reverse engineer binaries, firmware, Android apps, web APIs and codebases.

use anyhow::{Context, Result, bail};
use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use rex_engine::rex_core::{AnalysisOptions, Artifact, ArtifactKind, Report, Severity};
use rex_engine::rex_report::{self, Format, RenderOptions};
mod setup;

use std::io::IsTerminal;
use std::path::{Path, PathBuf};

const ABOUT: &str = "rex: reverse engineer anything.\n\n\
Static analysis for ELF/PE/Mach-O binaries, firmware images, Android apps, HTTP traffic (HAR), \
JavaScript bundles and source trees. Inputs are never executed.";

const EXAMPLES: &str = "\x1b[1mExamples:\x1b[0m
  rex analyze ./suspicious.exe                  Auto-detect and analyse anything
  rex analyze ./app.apk -f html -o report.html  Shareable single-file HTML report
  rex analyze . -f sarif -o rex.sarif           Code scanning for a repo (GitHub SARIF)
  rex disasm ./a.out --function main            Annotated disassembly of a function
  rex xrefs ./a.out \"password\"                  Which functions use a string?
  rex diff v1.bin v2.bin                        What changed between two builds?
  rex carve firmware.bin --extract out/         Pull filesystems out of a firmware image
  rex web har2openapi traffic.har -o api.yaml   Undocumented API → OpenAPI 3.1
  rex code map ~/src/project -o ATLAS.md        Map an unfamiliar codebase
  rex analyze ./malware.bin --ai                Add an LLM briefing (needs ANTHROPIC_API_KEY)
  rex mcp                                       Serve rex as tools to AI agents (MCP)";

#[derive(Parser)]
#[command(name = "rex", version, about = ABOUT, after_help = EXAMPLES, propagate_version = true)]
struct Cli {
    #[command(flatten)]
    global: Global,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Global {
    /// Output format (default: text, or inferred from --output extension).
    #[arg(short, long, global = true, value_enum)]
    format: Option<OutFormat>,
    /// Write output to a file instead of stdout.
    #[arg(short, long, global = true, value_name = "FILE")]
    output: Option<PathBuf>,
    /// Colourise terminal output.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
    /// Maximum rows per table (0 = unlimited).
    #[arg(long, global = true, default_value_t = 50)]
    max_rows: usize,
    /// Stop function discovery after this many functions (large binaries are reported as partial).
    #[arg(long, global = true, default_value_t = 5000)]
    max_functions: usize,
    /// Refuse inputs larger than this many MiB.
    #[arg(long, global = true, default_value_t = 1024)]
    max_size: u64,
    /// Exit with status 3 if any finding is at or above this severity (CI gating).
    #[arg(long, global = true, value_name = "SEVERITY")]
    fail_on: Option<Severity>,
    /// Override input type detection.
    #[arg(long = "as", global = true, value_enum, value_name = "KIND")]
    as_kind: Option<KindArg>,
    /// Verbose logging (-v, -vv).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Clone, Copy, ValueEnum)]
enum OutFormat {
    Text,
    Json,
    Md,
    Sarif,
    Html,
}

impl From<OutFormat> for Format {
    fn from(f: OutFormat) -> Self {
        match f {
            OutFormat::Text => Format::Text,
            OutFormat::Json => Format::Json,
            OutFormat::Md => Format::Markdown,
            OutFormat::Sarif => Format::Sarif,
            OutFormat::Html => Format::Html,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ColorChoice {
    Auto,
    Always,
    Never,
}

#[derive(Clone, Copy, ValueEnum)]
enum KindArg {
    Elf,
    Pe,
    Macho,
    Apk,
    Dex,
    Axml,
    Har,
    Js,
    Sourcemap,
    Wasm,
    Asar,
    Blob,
}

impl From<KindArg> for ArtifactKind {
    fn from(k: KindArg) -> Self {
        match k {
            KindArg::Elf => ArtifactKind::Elf,
            KindArg::Pe => ArtifactKind::Pe,
            KindArg::Macho => ArtifactKind::MachO,
            KindArg::Apk => ArtifactKind::Apk,
            KindArg::Dex => ArtifactKind::Dex,
            KindArg::Axml => ArtifactKind::AndroidBinaryXml,
            KindArg::Har => ArtifactKind::Har,
            KindArg::Js => ArtifactKind::JavaScript,
            KindArg::Sourcemap => ArtifactKind::SourceMap,
            KindArg::Wasm => ArtifactKind::Wasm,
            KindArg::Asar => ArtifactKind::Asar,
            KindArg::Blob => ArtifactKind::Blob,
        }
    }
}

#[derive(Args, Clone, Default)]
struct AiArgs {
    /// Add an LLM-written briefing to the report (sends a redacted report to the provider).
    #[arg(long)]
    ai: bool,
    /// AI provider: anthropic (default) or ollama (local).
    #[arg(long, value_name = "PROVIDER")]
    ai_provider: Option<String>,
    /// Model override (default: claude-opus-5-5 / llama3.1).
    #[arg(long, value_name = "MODEL")]
    ai_model: Option<String>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Auto-detect and analyse files or directories (binaries, firmware, APK, HAR, JS, source trees).
    #[command(visible_alias = "a")]
    Analyze {
        /// Inputs.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Only run analyzers whose name starts with one of these (comma-separated), e.g. binary.checksec,binary.strings
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// Enable expensive passes (full listings).
        #[arg(long)]
        deep: bool,
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Headers, sections, imports and exports of a binary.
    Info { path: PathBuf },
    /// Exploit-mitigation table for one or more binaries.
    Checksec {
        #[arg(required = true)]
        paths: Vec<PathBuf>,
    },
    /// Extract and classify strings.
    Strings {
        path: PathBuf,
        /// Minimum length.
        #[arg(short = 'n', long, default_value_t = 5)]
        min_len: usize,
        /// Show every string, not just classified ones.
        #[arg(long)]
        all: bool,
        /// Only these categories (url, ip, email, domain, registry, path, command, wallet, secret, base64, format, user-agent).
        #[arg(short, long, value_delimiter = ',')]
        category: Vec<String>,
    },
    /// List recovered functions.
    Functions { path: PathBuf },
    /// Disassemble a function or address range.
    Disasm {
        path: PathBuf,
        /// Function name or address.
        #[arg(short = 'F', long)]
        function: Option<String>,
        /// Start address (hex).
        #[arg(short, long)]
        addr: Option<String>,
        /// Instructions to decode (address mode).
        #[arg(short = 'n', long, default_value_t = 64)]
        count: usize,
    },
    /// Control-flow graph of a function (Mermaid, or Graphviz with --dot).
    Cfg {
        path: PathBuf,
        function: String,
        #[arg(long)]
        dot: bool,
    },
    /// Call graph (Mermaid) from main/entry or a given function.
    Callgraph {
        path: PathBuf,
        #[arg(long)]
        root: Option<String>,
        #[arg(long, default_value_t = 40)]
        max_nodes: usize,
    },
    /// Cross-references for a function, import or string.
    Xrefs { path: PathBuf, target: String },
    /// Find (and optionally extract) embedded files and filesystems.
    Carve {
        path: PathBuf,
        /// Extract into this directory.
        #[arg(short = 'x', long, value_name = "DIR")]
        extract: Option<PathBuf>,
    },
    /// Function-level diff of two binaries (patch analysis).
    Diff { old: PathBuf, new: PathBuf },
    /// Compare two saved `rex analyze -f json` reports (what changed between builds or runs).
    /// With --fail-on, new or escalated findings fail the run.
    Compare { old: PathBuf, new: PathBuf },
    /// Web & API reverse engineering.
    #[command(subcommand)]
    Web(WebCmd),
    /// Analyse an Android APK (shortcut for `analyze`).
    Apk { path: PathBuf },
    /// Codebase archaeology.
    #[command(subcommand)]
    Code(CodeCmd),
    /// LLM-assisted analysis.
    #[cfg(feature = "ai")]
    #[command(subcommand)]
    Ai(AiCmd),
    /// Run the Model Context Protocol server on stdio.
    #[cfg(feature = "mcp")]
    Mcp,
    /// Register rex's MCP server (and a skill) with your AI agents. Backs up configs; reversible.
    Setup {
        /// Agents to configure (default: every detected agent).
        #[arg(short, long, value_enum)]
        agent: Vec<setup::Agent>,
        /// Show what would change without changing anything.
        #[arg(long)]
        dry_run: bool,
        /// Remove rex from the agents instead.
        #[arg(long)]
        uninstall: bool,
        /// Don't install the skill file.
        #[arg(long)]
        no_skill: bool,
        /// Path the agent should launch (default: this executable).
        #[arg(long, value_name = "PATH")]
        command: Option<String>,
    },
    /// Check this build, AI credentials and which companion tools (Ghidra, jadx, ...) are installed.
    Doctor,
    /// List analyzers.
    Analyzers,
    /// Print shell completions.
    Completions { shell: clap_complete::Shell },
}

#[derive(Subcommand)]
enum WebCmd {
    /// Infer an OpenAPI 3.1 spec from a HAR capture (YAML; JSON with --json).
    Har2openapi {
        har: PathBuf,
        /// Emit JSON instead of YAML.
        #[arg(long)]
        json: bool,
        /// Keep static assets (JS, CSS, images).
        #[arg(long)]
        include_static: bool,
        /// Only hosts containing this text (repeatable).
        #[arg(long)]
        host: Vec<String>,
        /// API title.
        #[arg(long)]
        title: Option<String>,
    },
    /// Analyse a JavaScript bundle.
    Js { path: PathBuf },
    /// Recover original sources from a source map (or a bundle with an inline/adjacent map).
    Sourcemap {
        path: PathBuf,
        /// Output directory.
        #[arg(short = 'd', long, default_value = "rex-out/sources")]
        dir: PathBuf,
    },
    /// Extract an Electron app.asar (analyse it first with `rex analyze app.asar`).
    Asar {
        path: PathBuf,
        /// Output directory.
        #[arg(short = 'd', long, default_value = "rex-out/asar")]
        dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum CodeCmd {
    /// Build a codebase atlas (Markdown by default with -o *.md).
    Map { path: PathBuf },
}

#[cfg(feature = "ai")]
#[derive(Subcommand)]
enum AiCmd {
    /// Analyse a file and have an LLM write a briefing.
    Summarize {
        path: PathBuf,
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Explain a function (disassembly) in plain language with pseudo-C.
    Explain {
        path: PathBuf,
        #[arg(short = 'F', long)]
        function: String,
        #[command(flatten)]
        ai: AiArgs,
    },
    /// Suggest names for unnamed (sub_*) functions.
    Name {
        path: PathBuf,
        /// Maximum functions to send.
        #[arg(long, default_value_t = 25)]
        limit: usize,
        #[command(flatten)]
        ai: AiArgs,
    },
}

struct Ctx {
    g: Global,
    opts: AnalysisOptions,
}

impl Ctx {
    fn load(&self, p: &Path) -> Result<Artifact> {
        rex_engine::load(p, self.g.max_size << 20, self.g.as_kind.map(Into::into))
            .with_context(|| format!("cannot load {}", p.display()))
    }

    fn format(&self, default: Format) -> Format {
        self.g
            .format
            .map(Into::into)
            .or_else(|| self.g.output.as_deref().and_then(Format::from_extension))
            .unwrap_or(default)
    }

    fn color(&self) -> bool {
        match self.g.color {
            ColorChoice::Always => true,
            ColorChoice::Never => false,
            ColorChoice::Auto => {
                self.g.output.is_none()
                    && std::io::stdout().is_terminal()
                    && std::env::var_os("NO_COLOR").is_none()
            }
        }
    }

    fn emit_text(&self, text: &str) -> Result<()> {
        match &self.g.output {
            Some(p) => {
                if let Some(parent) = p.parent().filter(|d| !d.as_os_str().is_empty()) {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(p, text).with_context(|| format!("cannot write {}", p.display()))?;
                eprintln!("wrote {}", p.display());
            }
            None => print!("{text}"),
        }
        Ok(())
    }

    fn emit(&self, reports: &[Report]) -> Result<i32> {
        let f = self.format(Format::Text);
        let text = rex_report::render_many(
            reports,
            f,
            RenderOptions {
                color: self.color(),
            },
        );
        self.emit_text(&text)?;
        Ok(self.gate(reports))
    }

    fn gate(&self, reports: &[Report]) -> i32 {
        match self.g.fail_on {
            Some(min)
                if reports
                    .iter()
                    .any(|r| r.max_severity().is_some_and(|s| s >= min)) =>
            {
                eprintln!("rex: findings at or above '{min}' (exit 3)");
                3
            }
            _ => 0,
        }
    }
}

#[cfg(feature = "ai")]
fn add_ai(report: &mut Report, ai: &AiArgs) -> Result<()> {
    let llm = rex_ai::provider(ai.ai_provider.as_deref(), ai.ai_model.as_deref())?;
    eprintln!(
        "rex: asking {} for a briefing (secrets are redacted before sending)…",
        llm.describe()
    );
    let text = rex_ai::summarize(llm.as_ref(), report)?;
    report.sections.insert(
        0,
        rex_engine::rex_core::Section::text(
            "ai.summary",
            format!("AI briefing ({})", llm.describe()),
            text,
        ),
    );
    Ok(())
}

#[cfg(not(feature = "ai"))]
fn add_ai(_: &mut Report, _: &AiArgs) -> Result<()> {
    bail!("this build of rex has no AI support (rebuild with --features ai)")
}

fn run(cli: Cli) -> Result<i32> {
    let ctx = Ctx {
        opts: AnalysisOptions {
            max_rows: cli.global.max_rows,
            max_functions: cli.global.max_functions,
            ..Default::default()
        },
        g: cli.global,
    };
    let o = &ctx.opts;
    match cli.cmd {
        Cmd::Analyze {
            paths,
            only,
            deep,
            ai,
        } => {
            let opts = AnalysisOptions { deep, ..o.clone() };
            let mut reports = Vec::new();
            for p in &paths {
                let a = ctx.load(p)?;
                let mut r = rex_engine::analyze(&a, &opts, &only);
                if r.sections.is_empty() && r.findings.is_empty() && r.errors.is_empty() {
                    r.errors
                        .push(format!("no analyzer applies to {} (try --as)", a.kind()));
                }
                if ai.ai {
                    add_ai(&mut r, &ai)?;
                }
                reports.push(r);
            }
            ctx.emit(&reports)
        }
        Cmd::Apk { path } => {
            let a = ctx.load(&path)?;
            if a.kind() != ArtifactKind::Apk {
                bail!("{} is not an APK (detected {})", path.display(), a.kind());
            }
            ctx.emit(&[rex_engine::analyze(&a, o, &[])])
        }
        Cmd::Info { path } => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::analyze(
                &a,
                o,
                &["binary.info".into(), "binary.hashes".into()],
            )])
        }
        Cmd::Checksec { paths } => {
            let arts = paths
                .iter()
                .map(|p| ctx.load(p))
                .collect::<Result<Vec<_>>>()?;
            ctx.emit(&[rex_engine::checksec_many(&arts)])
        }
        Cmd::Strings {
            path,
            min_len,
            all,
            category,
        } => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::strings_report(&a, min_len, all, &category)])
        }
        Cmd::Functions { path } => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::functions_report(&a, o)?])
        }
        Cmd::Disasm {
            path,
            function,
            addr,
            count,
        } => {
            let a = ctx.load(&path)?;
            let addr = match addr {
                Some(s) => {
                    Some(rex_engine::parse_addr(&s).with_context(|| format!("bad address '{s}'"))?)
                }
                None => None,
            };
            ctx.emit_text(&rex_engine::disasm(
                &a,
                o,
                function.as_deref(),
                addr,
                count,
            )?)?;
            Ok(0)
        }
        Cmd::Cfg {
            path,
            function,
            dot,
        } => {
            let a = ctx.load(&path)?;
            ctx.emit_text(&rex_engine::cfg(
                &a,
                o,
                &function,
                if dot { "dot" } else { "mermaid" },
            )?)?;
            Ok(0)
        }
        Cmd::Callgraph {
            path,
            root,
            max_nodes,
        } => {
            let a = ctx.load(&path)?;
            ctx.emit_text(&rex_engine::callgraph(&a, o, root.as_deref(), max_nodes)?)?;
            Ok(0)
        }
        Cmd::Xrefs { path, target } => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::xrefs(&a, o, &target)?])
        }
        Cmd::Carve { path, extract } => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::carve_report(&a, extract.as_deref())?])
        }
        Cmd::Compare { old, new } => {
            let read = |p: &PathBuf| {
                std::fs::read_to_string(p).with_context(|| format!("cannot read {}", p.display()))
            };
            ctx.emit(&[rex_engine::compare_reports(&read(&old)?, &read(&new)?)?])
        }
        Cmd::Diff { old, new } => {
            let (a, b) = (ctx.load(&old)?, ctx.load(&new)?);
            ctx.emit(&[rex_engine::diff_report(&a, &b, o)?])
        }
        Cmd::Web(WebCmd::Har2openapi {
            har,
            json,
            include_static,
            host,
            title,
        }) => {
            let a = ctx.load(&har)?.with_kind(ArtifactKind::Har);
            let (spec, report) =
                rex_engine::har_to_openapi(&a, include_static, &host, title.as_deref())?;
            let as_json = json
                || ctx
                    .g
                    .output
                    .as_ref()
                    .is_some_and(|p| p.extension().is_some_and(|e| e == "json"));
            let text = if as_json {
                serde_json::to_string_pretty(&spec)? + "\n"
            } else {
                rex_engine::openapi_yaml(&spec)
            };
            ctx.emit_text(&text)?;
            if ctx.g.output.is_some() {
                eprint!(
                    "{}",
                    rex_report::render(
                        &report,
                        Format::Text,
                        RenderOptions {
                            color: std::io::stderr().is_terminal()
                        }
                    )
                );
            }
            Ok(ctx.gate(&[report]))
        }
        Cmd::Web(WebCmd::Js { path }) => {
            let a = ctx.load(&path)?.with_kind(ArtifactKind::JavaScript);
            ctx.emit(&[rex_engine::analyze(&a, o, &["web.js".into()])])
        }
        Cmd::Web(WebCmd::Sourcemap { path, dir }) => {
            let a = ctx.load(&path)?;
            ctx.emit(&[rex_engine::sourcemap_unpack(&a, &dir)?])
        }
        Cmd::Web(WebCmd::Asar { path, dir }) => {
            let a = ctx.load(&path)?;
            if a.kind() != ArtifactKind::Asar {
                bail!("{} is not an Electron ASAR archive", path.display());
            }
            ctx.emit(&[rex_engine::asar_unpack(&a, &dir)?])
        }
        Cmd::Code(CodeCmd::Map { path }) => {
            let a = ctx.load(&path)?;
            if a.kind() != ArtifactKind::Directory {
                bail!("{} is not a directory", path.display());
            }
            let r = rex_engine::analyze(&a, o, &["code.".into()]);
            let f = ctx.format(if ctx.g.output.is_some() {
                Format::Markdown
            } else {
                Format::Text
            });
            ctx.emit_text(&rex_report::render(
                &r,
                f,
                RenderOptions { color: ctx.color() },
            ))?;
            Ok(ctx.gate(&[r]))
        }
        #[cfg(feature = "ai")]
        Cmd::Ai(cmd) => run_ai(&ctx, cmd),
        #[cfg(feature = "mcp")]
        Cmd::Mcp => {
            rex_mcp::serve()?;
            Ok(0)
        }
        Cmd::Analyzers => ctx.emit(&[rex_engine::analyzers_report()]),
        Cmd::Doctor => ctx.emit(&[rex_engine::doctor_report(&|n| setup::which(n))]),
        Cmd::Setup {
            agent,
            dry_run,
            uninstall,
            no_skill,
            command,
        } => run_setup(agent, dry_run, uninstall, no_skill, command),
        Cmd::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "rex", &mut std::io::stdout());
            Ok(0)
        }
    }
}

fn run_setup(
    agent: Vec<setup::Agent>,
    dry_run: bool,
    uninstall: bool,
    no_skill: bool,
    command: Option<String>,
) -> Result<i32> {
    let home = setup::home_dir().context("cannot find your home directory (set HOME)")?;
    let command = match command {
        Some(c) => c,
        None => std::env::current_exe()
            .context("cannot locate the rex executable")?
            .to_string_lossy()
            .into_owned(),
    };
    let force = !agent.is_empty();
    let agents: Vec<setup::Agent> = if force {
        agent
    } else {
        setup::Agent::ALL.to_vec()
    };
    let plan = setup::Plan {
        home,
        command: command.clone(),
        dry_run,
        uninstall,
        skill: !no_skill,
    };
    if !uninstall && !dry_run && command.contains("target/debug") {
        eprintln!(
            "rex: note: registering a debug build ({command}); use --command to point at an installed rex"
        );
    }
    let mut failed = false;
    let mut changed = false;
    for (name, r) in setup::run(&plan, &agents, force) {
        match r {
            Ok(setup::Outcome::Configured(w)) => {
                changed = true;
                println!("✔ {name}: configured ({w})");
            }
            Ok(setup::Outcome::Removed(w)) => {
                changed = true;
                println!("✔ {name}: removed ({w})");
            }
            Ok(setup::Outcome::Already(w)) => println!("• {name}: already configured ({w})"),
            Ok(setup::Outcome::NotPresent) => println!("• {name}: nothing to remove"),
            Ok(setup::Outcome::Skipped(why)) => println!("- {name}: skipped, {why}"),
            Ok(setup::Outcome::Would(what)) => println!("→ {name}: would {what}"),
            Err(e) => {
                failed = true;
                println!("✘ {name}: {e:#}");
            }
        }
    }
    if changed && !dry_run {
        println!(
            "\nRestart your agent to pick up the change. Undo with `rex setup --uninstall` (backups are saved next to each edited file)."
        );
    }
    Ok(i32::from(failed))
}

#[cfg(feature = "ai")]
fn run_ai(ctx: &Ctx, cmd: AiCmd) -> Result<i32> {
    let o = &ctx.opts;
    match cmd {
        AiCmd::Summarize { path, ai } => {
            let a = ctx.load(&path)?;
            let mut r = rex_engine::analyze(&a, o, &[]);
            add_ai(&mut r, &ai)?;
            ctx.emit(&[r])
        }
        AiCmd::Explain { path, function, ai } => {
            let a = ctx.load(&path)?;
            let listing = rex_engine::disasm(&a, o, Some(&function), None, 0)?;
            let llm = rex_ai::provider(ai.ai_provider.as_deref(), ai.ai_model.as_deref())?;
            ctx.emit_text(&(rex_ai::explain(llm.as_ref(), &function, &listing)? + "\n"))?;
            Ok(0)
        }
        AiCmd::Name { path, limit, ai } => {
            let a = ctx.load(&path)?;
            let (_, p) = rex_engine::program(&a, o)?;
            let mut targets: Vec<_> = p
                .functions
                .values()
                .filter(|f| f.name.starts_with("sub_"))
                .collect();
            targets.sort_by_key(|f| std::cmp::Reverse(f.imports_called.len() + f.strings.len()));
            let funcs: Vec<(String, String, String)> = targets
                .into_iter()
                .take(limit)
                .map(|f| {
                    (
                        format!("{:#x}", f.addr),
                        f.name.clone(),
                        rex_engine::function_listing(&p, f),
                    )
                })
                .collect();
            if funcs.is_empty() {
                bail!("no unnamed (sub_*) functions to name");
            }
            let llm = rex_ai::provider(ai.ai_provider.as_deref(), ai.ai_model.as_deref())?;
            eprintln!(
                "rex: asking {} to name {} functions…",
                llm.describe(),
                funcs.len()
            );
            let names = rex_ai::name_functions(llm.as_ref(), &funcs)?;
            let mut r = Report::new(
                format!("rex ai name: {}", a.name()),
                rex_engine::rex_core::ArtifactSummary::of(&a),
            );
            r.push(
                rex_engine::rex_core::Section::table(
                    "ai.names",
                    "Suggested function names",
                    &["address", "current", "suggested", "confidence", "rationale"],
                    names
                        .iter()
                        .map(|n| {
                            let cur = funcs
                                .iter()
                                .find(|f| f.0 == n.address)
                                .map(|f| f.1.clone())
                                .unwrap_or_default();
                            vec![
                                n.address.clone(),
                                cur,
                                n.name.clone(),
                                format!("{:.2}", n.confidence),
                                n.rationale.clone(),
                            ]
                        })
                        .collect(),
                    0,
                )
                .with_data(&names),
            );
            ctx.emit(&[r])
        }
    }
}

fn main() {
    let cli = Cli::parse();
    let level = match cli.global.verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("REX_LOG")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(level)),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .try_init();
    // Analyzer panics are caught and reported; keep the default hook quiet unless debugging.
    if cli.global.verbose < 2 {
        std::panic::set_hook(Box::new(|_| {}));
    }
    let code = match run(cli) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("rex: error: {e:#}");
            1
        }
    };
    std::process::exit(code);
}
