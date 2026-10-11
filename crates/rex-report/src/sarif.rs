use rex_core::{Report, Severity};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn level(s: Severity) -> &'static str {
    match s {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::Info => "note",
    }
}

fn security_severity(s: Severity) -> &'static str {
    // GitHub code scanning maps this numeric string onto its own severity scale.
    match s {
        Severity::Critical => "9.5",
        Severity::High => "8.0",
        Severity::Medium => "5.5",
        Severity::Low => "3.0",
        Severity::Info => "0.0",
    }
}

fn run(r: &Report) -> Value {
    let mut rules: BTreeMap<&str, Value> = BTreeMap::new();
    let mut results = Vec::new();
    let default_uri = r
        .artifact
        .path
        .clone()
        .unwrap_or_else(|| r.artifact.name.clone());
    for f in &r.findings {
        rules.entry(f.id.as_str()).or_insert_with(|| {
            let mut tags = vec!["security".to_string(), f.category.clone()];
            tags.extend(f.attack.iter().map(|t| format!("attack/{t}")));
            json!({
                "id": f.id,
                "name": f.id.replace('-', "_"),
                "shortDescription": { "text": f.title },
                "fullDescription": { "text": if f.description.is_empty() { &f.title } else { &f.description } },
                "defaultConfiguration": { "level": level(f.severity) },
                "properties": { "tags": tags, "security-severity": security_severity(f.severity) }
            })
        });
        let loc = f.location.clone().unwrap_or_default();
        let uri = loc.file.clone().unwrap_or_else(|| default_uri.clone());
        let mut region = serde_json::Map::new();
        if let Some(line) = loc.line {
            region.insert("startLine".into(), json!(line));
        } else if let Some(off) = loc.offset {
            region.insert("byteOffset".into(), json!(off));
        }
        let mut phys = json!({ "artifactLocation": { "uri": uri.replace('\\', "/") } });
        if !region.is_empty() {
            phys["region"] = Value::Object(region);
        }
        let mut msg = f.title.clone();
        if !f.evidence.is_empty() {
            msg.push_str(": ");
            msg.push_str(
                &f.evidence
                    .iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("; "),
            );
        }
        let mut result = json!({
            "ruleId": f.id,
            "level": level(f.severity),
            "message": { "text": msg },
            "locations": [ { "physicalLocation": phys } ],
        });
        if let Some(addr) = loc.address {
            result["properties"] = json!({ "address": format!("{addr:#x}") });
        }
        results.push(result);
    }
    json!({
        "tool": { "driver": {
            "name": r.tool.name,
            "version": r.tool.version,
            "informationUri": "https://github.com/aabhimittal/reverse-engineer",
            "rules": rules.into_values().collect::<Vec<_>>(),
        }},
        "results": results,
    })
}

pub(crate) fn render(r: &Report) -> String {
    render_many(std::slice::from_ref(r))
}

pub(crate) fn render_many(reports: &[Report]) -> String {
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": reports.iter().map(run).collect::<Vec<_>>(),
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n"
}
