//! # rex-report
//!
//! Turns a [`rex_core::Report`] into something humans or machines can consume.
//!
//! | Format     | Audience                                           |
//! |------------|----------------------------------------------------|
//! | `text`     | Terminal; aligned tables, optional ANSI colour      |
//! | `json`     | Scripts and pipelines; stable schema (v1)           |
//! | `markdown` | PRs, wikis, notes; Mermaid diagrams render on GitHub|
//! | `sarif`    | GitHub code scanning and other SARIF 2.1 consumers  |
//! | `html`     | One self-contained file to share with a team       |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod html;
mod markdown;
mod sarif;
mod text;

use rex_core::Report;
use std::str::FromStr;

/// Output formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Terminal text.
    Text,
    /// Pretty JSON.
    Json,
    /// GitHub-flavoured Markdown.
    Markdown,
    /// SARIF 2.1.0.
    Sarif,
    /// Self-contained HTML.
    Html,
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "text" | "txt" | "term" => Format::Text,
            "json" => Format::Json,
            "md" | "markdown" => Format::Markdown,
            "sarif" => Format::Sarif,
            "html" | "htm" => Format::Html,
            other => {
                return Err(format!(
                    "unknown format '{other}' (text|json|md|sarif|html)"
                ));
            }
        })
    }
}

impl Format {
    /// Guess from an output file extension.
    pub fn from_extension(path: &std::path::Path) -> Option<Self> {
        path.extension()?.to_str()?.parse().ok()
    }
}

/// Render options.
#[derive(Debug, Clone, Copy, Default)]
pub struct RenderOptions {
    /// Use ANSI colours (text format only).
    pub color: bool,
}

/// Render a report in the given format.
pub fn render(report: &Report, format: Format, opts: RenderOptions) -> String {
    match format {
        Format::Text => text::render(report, opts.color),
        Format::Json => {
            serde_json::to_string_pretty(report).unwrap_or_else(|e| e.to_string()) + "\n"
        }
        Format::Markdown => markdown::render(report),
        Format::Sarif => sarif::render(report),
        Format::Html => html::render(report),
    }
}

/// Render several reports (e.g. `rex diff`, multi-file runs) as one document.
pub fn render_many(reports: &[Report], format: Format, opts: RenderOptions) -> String {
    match format {
        Format::Json => serde_json::to_string_pretty(reports).unwrap_or_default() + "\n",
        Format::Sarif => sarif::render_many(reports),
        _ => reports
            .iter()
            .map(|r| render(r, format, opts))
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

pub(crate) fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rex_core::{ArtifactSummary, Finding, Location, Section, Severity};

    pub(crate) fn sample() -> Report {
        let mut r = Report::new(
            "rex analysis: demo",
            ArtifactSummary {
                name: "demo".into(),
                path: Some("/tmp/demo".into()),
                kind: Some(rex_core::ArtifactKind::Elf),
                size: 2048,
                sha256: Some("ab".repeat(32)),
            },
        );
        r.push(Section::kv(
            "k",
            "Overview",
            [("Format", "ELF64"), ("Arch", "x86_64")],
        ));
        r.push(Section::table(
            "t",
            "Sections | pipes",
            &["name", "size"],
            vec![
                vec![".text".into(), "100".into()],
                vec![".da|ta".into(), "<b>".into()],
            ],
            0,
        ));
        r.push(Section::diagram("d", "CFG", "mermaid", "graph TD\n A-->B"));
        r.push(Section::code("c", "Disasm", "asm", "mov eax, 1\nret"));
        r.findings.push(
            Finding::new("BIN-NX", Severity::High, "mitigation", "NX disabled")
                .describe("Stack is executable")
                .evidence("PT_GNU_STACK RWX")
                .at(Location {
                    file: Some("demo".into()),
                    offset: Some(64),
                    ..Default::default()
                }),
        );
        r.findings
            .push(Finding::new("BIN-INFO", Severity::Info, "info", "stripped").attack("T1027"));
        r
    }

    #[test]
    fn all_formats_render() {
        let r = sample();
        for f in [
            Format::Text,
            Format::Json,
            Format::Markdown,
            Format::Sarif,
            Format::Html,
        ] {
            let out = render(&r, f, RenderOptions::default());
            assert!(out.contains("NX disabled"), "{f:?}");
        }
    }

    #[test]
    fn json_roundtrips() {
        let r = sample();
        let s = render(&r, Format::Json, RenderOptions::default());
        let back: Report = serde_json::from_str(&s).unwrap();
        assert_eq!(back.findings.len(), 2);
        assert_eq!(back.sections.len(), 4);
    }

    #[test]
    fn markdown_escapes_pipes() {
        let s = render(&sample(), Format::Markdown, RenderOptions::default());
        assert!(s.contains(".da\\|ta"));
        assert!(s.contains("```mermaid"));
    }

    #[test]
    fn html_escapes() {
        let s = render(&sample(), Format::Html, RenderOptions::default());
        assert!(s.contains("&lt;b&gt;"));
        assert!(!s.contains("<b>"));
        assert!(s.starts_with("<!doctype html>"));
    }

    #[test]
    fn sarif_shape() {
        let s = render(&sample(), Format::Sarif, RenderOptions::default());
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "rex");
        assert_eq!(run["results"][0]["level"], "error");
        assert_eq!(run["results"][0]["ruleId"], "BIN-NX");
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 2);
        assert_eq!(
            run["results"][0]["locations"][0]["physicalLocation"]["region"]["byteOffset"],
            64
        );
    }

    #[test]
    fn untrusted_text_cannot_drive_the_terminal() {
        // Clear screen, OSC window title, cursor-up, a bidi override and a C1 CSI, as they could
        // arrive in a symbol name, a version string or a URL inside an analysed file.
        let evil = "a\x1b[2Jb\x1b]0;pwned\x07c\x1b[1Ad\u{202E}e\u{9b}31mf";
        let mut r = sample();
        r.push(Section::kv("e", evil, [(evil, evil)]));
        r.push(Section::table(
            "t2",
            "T",
            &["c"],
            vec![vec![evil.into()]],
            0,
        ));
        r.findings
            .push(Finding::new("X", Severity::Info, "x", evil).evidence(evil.to_string()));
        for color in [false, true] {
            let s = render(&r, Format::Text, RenderOptions { color });
            for bad in [
                "\x1b[2J", "\x1b]0", "\x07", "\x1b[1A", "\u{202E}", "\u{9b}", "\u{E000}",
            ] {
                assert!(
                    !s.contains(bad),
                    "color={color}: {bad:?} reached the terminal"
                );
            }
            assert!(s.contains("a\\u{1b}[2Jb"), "escapes are shown, not dropped");
            // Our own colouring still works.
            assert_eq!(s.contains("\x1b[1;36m"), color);
        }
    }

    #[test]
    fn text_has_no_ansi_without_color() {
        let s = render(&sample(), Format::Text, RenderOptions { color: false });
        assert!(!s.contains('\x1b'));
        let c = render(&sample(), Format::Text, RenderOptions { color: true });
        assert!(c.contains('\x1b'));
    }

    #[test]
    fn formats_parse() {
        assert_eq!("md".parse::<Format>().unwrap(), Format::Markdown);
        assert!("pdf".parse::<Format>().is_err());
        assert_eq!(human_size(2048), "2.0 KiB");
        assert_eq!(human_size(12), "12 B");
    }
}
