use rex_core::{Report, SectionBody, Severity};
use std::fmt::Write;

struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
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
    o
}
