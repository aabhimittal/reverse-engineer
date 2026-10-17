use rex_core::{Report, SectionBody, Severity};
use std::fmt::Write;

struct Style {
    on: bool,
}

// Colour codes are written as placeholders while the report is assembled, because everything
// else in it can come from the file under analysis: symbol names, version strings, URLs. The
// final pass (`finish`) escapes control characters from that text and only then turns the
// placeholders into real ANSI sequences, so a crafted string cannot clear the screen, move the
// cursor, retitle the terminal or hide a finding.
const OPEN: char = '\u{E000}';
const CLOSE: char = '\u{E001}';

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("{OPEN}{code}{CLOSE}{s}{OPEN}0{CLOSE}")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn heading(&self, s: &str) -> String {
        self.paint("1;36", s)
    }
    fn sev(&self, sev: Severity) -> String {
        let label = format!("{:<8}", sev.as_str().to_uppercase());
        let code = match sev {
            Severity::Critical => "1;97;41",
            Severity::High => "1;31",
            Severity::Medium => "33",
            Severity::Low => "34",
            Severity::Info => "2",
        };
        self.paint(code, &label)
    }
}

fn width(s: &str) -> usize {
    s.chars().count()
}

fn clip(s: &str, max: usize) -> String {
    let s = s.replace(['\n', '\r', '\t'], " ");
    if width(&s) <= max {
        s
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

pub(crate) fn render(r: &Report, color: bool) -> String {
    let st = Style { on: color };
    let mut o = String::new();
    let _ = writeln!(o, "{}", st.bold(&r.title));
    let a = &r.artifact;
    let mut meta = vec![format!("size {}", crate::human_size(a.size))];
    if let Some(k) = a.kind {
        meta.insert(0, k.label().to_string());
    }
    if let Some(h) = &a.sha256 {
        meta.push(format!("sha256 {h}"));
    }
    let _ = writeln!(o, "{}", st.dim(&meta.join(" · ")));

    for s in &r.sections {
        let _ = writeln!(o, "\n{}", st.heading(&format!("── {} ", s.title)));
        match &s.body {
            SectionBody::KeyValue { pairs } => {
                let kw = pairs.iter().map(|(k, _)| width(k)).max().unwrap_or(0);
                for (k, v) in pairs {
                    let _ = writeln!(o, "  {}  {}", st.bold(&format!("{k:<kw$}")), v);
                }
            }
            SectionBody::Table {
                columns,
                rows,
                truncated,
            } => {
                const MAX_COL: usize = 60;
                let mut w: Vec<usize> = columns.iter().map(|c| width(c)).collect();
                for row in rows {
                    for (i, c) in row.iter().enumerate() {
                        if i < w.len() {
                            w[i] = w[i].max(width(c).min(MAX_COL));
                        }
                    }
                }
                let line = |cells: &[String]| -> String {
                    cells
                        .iter()
                        .enumerate()
                        .map(|(i, c)| {
                            let c = clip(c, MAX_COL);
                            let pad = w.get(i).copied().unwrap_or(0).saturating_sub(width(&c));
                            format!("{c}{}", " ".repeat(pad))
                        })
                        .collect::<Vec<_>>()
                        .join("  ")
                        .trim_end()
                        .to_string()
                };
                let _ = writeln!(o, "  {}", st.bold(&line(columns)));
                for row in rows {
                    let _ = writeln!(o, "  {}", line(row));
                }
                if *truncated > 0 {
                    let _ = writeln!(
                        o,
                        "  {}",
                        st.dim(&format!(
                            "… {truncated} more rows (use --max-rows 0 or --format json)"
                        ))
                    );
                }
                if rows.is_empty() {
                    let _ = writeln!(o, "  {}", st.dim("(none)"));
                }
            }
            SectionBody::Text { text } => {
                for l in text.lines() {
                    let _ = writeln!(o, "  {l}");
                }
            }
            SectionBody::Code { text, .. } | SectionBody::Diagram { text, .. } => {
                for l in text.lines() {
                    let _ = writeln!(o, "  {}", l);
                }
            }
        }
    }

    let _ = writeln!(o, "\n{}", st.heading("── Findings "));
    if r.findings.is_empty() {
        let _ = writeln!(o, "  {}", st.dim("no findings"));
    }
    for f in &r.findings {
        let _ = writeln!(o, "  {} {}  {}", st.sev(f.severity), f.title, st.dim(&f.id));
        if !f.description.is_empty() {
            let _ = writeln!(o, "           {}", st.dim(&f.description));
        }
        for e in f.evidence.iter().take(5) {
            let _ = writeln!(o, "           • {}", clip(e, 120));
        }
        if f.evidence.len() > 5 {
            let _ = writeln!(
                o,
                "           {}",
                st.dim(&format!("… {} more", f.evidence.len() - 5))
            );
        }
        if !f.attack.is_empty() {
            let _ = writeln!(
                o,
                "           {}",
                st.dim(&format!("ATT&CK: {}", f.attack.join(", ")))
            );
        }
    }
    let counts: Vec<String> = r
        .severity_counts()
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| format!("{n} {s}"))
        .collect();
    let _ = writeln!(
        o,
        "\n{}",
        st.dim(&format!(
            "{} findings{} · {} ms",
            r.findings.len(),
            if counts.is_empty() {
                String::new()
            } else {
                format!(" ({})", counts.join(", "))
            },
            r.duration_ms
        ))
    );
    for e in &r.errors {
        let _ = writeln!(o, "{}", st.paint("33", &format!("warning: {e}")));
    }
    finish(&o, color)
}

/// Make untrusted text safe for a terminal, then apply the colour placeholders.
fn finish(o: &str, color: bool) -> String {
    let mut out = String::with_capacity(o.len());
    let mut chars = o.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            OPEN => {
                let mut code = String::new();
                for d in chars.by_ref() {
                    if d == CLOSE {
                        break;
                    }
                    code.push(d);
                }
                // Only SGR colour codes we generate (digits and ';') become escape sequences.
                if color && !code.is_empty() && code.chars().all(|d| d.is_ascii_digit() || d == ';')
                {
                    let _ = write!(out, "\x1b[{code}m");
                }
            }
            CLOSE => {}
            '\n' => out.push('\n'),
            c if c.is_control() || is_bidi_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Unicode bidirectional overrides and isolates can reorder how text displays
/// ("Trojan Source"): show them instead of obeying them.
fn is_bidi_control(c: char) -> bool {
    matches!(c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}' | '\u{061C}')
}
