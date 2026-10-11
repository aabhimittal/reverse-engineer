//! Single-file HTML report. No build step, no external CSS. Diagrams are
//! upgraded with Mermaid from a CDN when online, and fall back to their
//! source text when offline.

use rex_core::{Report, SectionBody, Severity};
use std::fmt::Write;

pub(crate) fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn sev_class(s: Severity) -> &'static str {
    s.as_str()
}

const CSS: &str = r#"
:root{--bg:#f7f7f5;--panel:#fff;--text:#1d1d1f;--muted:#6b6b70;--border:#e3e3e0;--accent:#2f6fde;
--crit:#b3261e;--high:#d0421b;--med:#b7791f;--low:#2f6fde;--info:#6b6b70;--code:#f0f0ec;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#121214;--panel:#1b1b1f;--text:#ececf0;--muted:#9a9aa3;--border:#2c2c33;--accent:#7aa7ff;
--crit:#ff6b60;--high:#ff8a5c;--med:#e3b341;--low:#7aa7ff;--info:#9a9aa3;--code:#232329}}
:root[data-theme="dark"]{--bg:#121214;--panel:#1b1b1f;--text:#ececf0;--muted:#9a9aa3;--border:#2c2c33;--accent:#7aa7ff;
--crit:#ff6b60;--high:#ff8a5c;--med:#e3b341;--low:#7aa7ff;--info:#9a9aa3;--code:#232329}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:24px 16px 8px;max-width:1200px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}
.meta{color:var(--muted);font-size:13px;word-break:break-all}
main{max-width:1200px;margin:0 auto;padding:0 16px 48px}
.toolbar{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0 16px}
input[type=search]{flex:1;min-width:200px;padding:8px 10px;border:1px solid var(--border);border-radius:8px;background:var(--panel);color:var(--text)}
button{padding:7px 10px;border:1px solid var(--border);border-radius:8px;background:var(--panel);color:var(--text);cursor:pointer}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid var(--border);color:var(--muted)}
details{background:var(--panel);border:1px solid var(--border);border-radius:10px;margin:10px 0;overflow:hidden}
summary{cursor:pointer;padding:10px 14px;font-weight:600;list-style:none;display:flex;justify-content:space-between;gap:8px}
summary::-webkit-details-marker{display:none}summary .count{color:var(--muted);font-weight:400;font-size:13px}
.body{padding:0 14px 14px;overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--border);vertical-align:top}
th{position:sticky;top:0;background:var(--panel);color:var(--muted);font-weight:600}
td{font-family:var(--mono);word-break:break-word}
pre{background:var(--code);padding:12px;border-radius:8px;overflow-x:auto;font:12.5px/1.45 var(--mono);margin:0}
.sev{display:inline-block;min-width:68px;text-align:center;font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 6px;border-radius:6px;color:#fff}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med)}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.finding{border-top:1px solid var(--border);padding:10px 0}.finding:first-child{border-top:0}
.finding .t{font-weight:600}.finding .id{color:var(--muted);font:12px var(--mono);margin-left:6px}
.finding .d{color:var(--muted);margin:4px 0}.finding ul{margin:4px 0 0 18px;padding:0;font:12.5px var(--mono);word-break:break-all}
.kv td:first-child{font-family:inherit;color:var(--muted);width:30%;white-space:nowrap}
.hidden{display:none!important}.muted{color:var(--muted);font-size:13px}
@media (max-width:640px){.kv td:first-child{white-space:normal;width:40%}}
"#;

const JS: &str = r#"
const q=document.getElementById('q');
q.addEventListener('input',()=>{const v=q.value.toLowerCase();
document.querySelectorAll('[data-search]').forEach(el=>{el.classList.toggle('hidden',v&&!el.textContent.toLowerCase().includes(v));});
document.querySelectorAll('details').forEach(d=>{if(v)d.open=true;});});
document.getElementById('expand').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=true);
document.getElementById('collapse').onclick=()=>document.querySelectorAll('details').forEach(d=>d.open=false);
document.getElementById('theme').onclick=()=>{const r=document.documentElement;const cur=r.dataset.theme||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');r.dataset.theme=cur==='dark'?'light':'dark';};
"#;

pub(crate) fn render(r: &Report) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{}</title><style>{CSS}</style></head><body>",
        esc(&r.title)
    );
    let a = &r.artifact;
    let mut meta = vec![];
    if let Some(k) = a.kind {
        meta.push(esc(k.label()));
    }
    meta.push(crate::human_size(a.size));
    if let Some(h) = &a.sha256 {
        meta.push(format!("sha256 {}", esc(h)));
    }
    meta.push(format!(
        "{} {} · {} ms",
        esc(&r.tool.name),
        esc(&r.tool.version),
        r.duration_ms
    ));
    let _ = write!(
        o,
        "<header><h1>{}</h1><div class=\"meta\">{}</div></header><main>",
        esc(&r.title),
        meta.join(" · ")
    );
    let _ = write!(
        o,
        "<div class=\"toolbar\"><input id=\"q\" type=\"search\" placeholder=\"Filter rows, findings, strings…\" aria-label=\"Filter\">\
<button id=\"expand\">Expand all</button><button id=\"collapse\">Collapse all</button><button id=\"theme\" aria-label=\"Toggle light/dark theme\">Theme</button></div>"
    );
    let chips: Vec<String> = r
        .severity_counts()
        .into_iter()
        .filter(|(_, n)| *n > 0)
        .map(|(s, n)| {
            format!(
                "<span class=\"chip\"><span class=\"sev {}\">{}</span> {n}</span>",
                sev_class(s),
                s
            )
        })
        .collect();
    if !chips.is_empty() {
        let _ = write!(o, "<div class=\"chips\">{}</div>", chips.join(""));
    }

    // Findings first: they are the "so what".
    let _ = write!(
        o,
        "<details open><summary>Findings <span class=\"count\">{}</span></summary><div class=\"body\">",
        r.findings.len()
    );
    if r.findings.is_empty() {
        o.push_str("<p class=\"muted\">No findings.</p>");
    }
    for f in &r.findings {
        let _ = write!(
            o,
            "<div class=\"finding\" data-search><span class=\"sev {}\">{}</span> <span class=\"t\">{}</span><span class=\"id\">{} · {}</span>",
            sev_class(f.severity),
            f.severity,
            esc(&f.title),
            esc(&f.id),
            esc(&f.category)
        );
        if !f.description.is_empty() {
            let _ = write!(o, "<div class=\"d\">{}</div>", esc(&f.description));
        }
        if !f.evidence.is_empty() {
            o.push_str("<ul>");
            for e in f.evidence.iter().take(50) {
                let _ = write!(o, "<li>{}</li>", esc(e));
            }
            o.push_str("</ul>");
        }
        if !f.attack.is_empty() {
            let _ = write!(
                o,
                "<div class=\"d\">ATT&amp;CK: {}</div>",
                esc(&f.attack.join(", "))
            );
        }
        o.push_str("</div>");
    }
    o.push_str("</div></details>");

    for (i, s) in r.sections.iter().enumerate() {
        let count = match &s.body {
            SectionBody::Table {
                rows, truncated, ..
            } => format!("{}", rows.len() + truncated),
            _ => String::new(),
        };
        let open = if i < 6 { " open" } else { "" };
        let _ = write!(
            o,
            "<details{open} id=\"{}\"><summary>{} <span class=\"count\">{}</span></summary><div class=\"body\">",
            esc(&s.id),
            esc(&s.title),
            count
        );
        match &s.body {
            SectionBody::KeyValue { pairs } => {
                o.push_str("<table class=\"kv\">");
                for (k, v) in pairs {
                    let _ = write!(
                        o,
                        "<tr data-search><td>{}</td><td>{}</td></tr>",
                        esc(k),
                        esc(v)
                    );
                }
                o.push_str("</table>");
            }
            SectionBody::Table {
                columns,
                rows,
                truncated,
            } => {
                if rows.is_empty() {
                    o.push_str("<p class=\"muted\">None.</p>");
                } else {
                    o.push_str("<table><thead><tr>");
                    for c in columns {
                        let _ = write!(o, "<th>{}</th>", esc(c));
                    }
                    o.push_str("</tr></thead><tbody>");
                    for row in rows {
                        o.push_str("<tr data-search>");
                        for c in row {
                            let _ = write!(o, "<td>{}</td>", esc(c));
                        }
                        o.push_str("</tr>");
                    }
                    o.push_str("</tbody></table>");
                }
                if *truncated > 0 {
                    let _ = write!(
                        o,
                        "<p class=\"muted\">…and {truncated} more rows (rerun with --max-rows 0).</p>"
                    );
                }
            }
            SectionBody::Text { text } => {
                let _ = write!(o, "<pre style=\"white-space:pre-wrap\">{}</pre>", esc(text));
            }
            SectionBody::Code { text, .. } => {
                let _ = write!(o, "<pre>{}</pre>", esc(text));
            }
            SectionBody::Diagram { kind, text } => {
                let class = if kind == "mermaid" { "mermaid" } else { "" };
                let _ = write!(o, "<pre class=\"{class}\">{}</pre>", esc(text));
            }
        }
        o.push_str("</div></details>");
    }
    if !r.errors.is_empty() {
        o.push_str("<details open><summary>Analyzer warnings</summary><div class=\"body\"><ul>");
        for e in &r.errors {
            let _ = write!(o, "<li>{}</li>", esc(e));
        }
        o.push_str("</ul></div></details>");
    }
    let _ = write!(o, "</main><script>{JS}</script>");
    if r.sections
        .iter()
        .any(|s| matches!(&s.body, SectionBody::Diagram { kind, .. } if kind == "mermaid"))
    {
        o.push_str(
            "<script type=\"module\">try{const m=await import('https://cdn.jsdelivr.net/npm/mermaid@10.9.1/dist/mermaid.esm.min.mjs');\
m.default.initialize({startOnLoad:false,theme:matchMedia('(prefers-color-scheme: dark)').matches?'dark':'default',securityLevel:'strict'});\
await m.default.run({querySelector:'pre.mermaid'});}catch(e){}</script>",
        );
    }
    o.push_str("</body></html>\n");
    o
}
