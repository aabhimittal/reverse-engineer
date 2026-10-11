//! A small, dependency-free YAML emitter for JSON values (enough for OpenAPI documents).
//!
//! Strings that YAML could misinterpret (`yes`, `1.0`, `null`, `: `, leading
//! `-`, …) are emitted as JSON-style double-quoted scalars, which are valid YAML.

use serde_json::Value;
use std::fmt::Write;

/// Serialize a JSON value as YAML.
pub fn to_yaml(v: &Value) -> String {
    let mut o = String::new();
    match v {
        Value::Object(m) if !m.is_empty() => emit_map(&mut o, m, 0),
        Value::Array(a) if !a.is_empty() => emit_seq(&mut o, a, 0),
        other => {
            o.push_str(&scalar(other));
            o.push('\n');
        }
    }
    o
}

fn needs_quotes(s: &str) -> bool {
    if s.is_empty() || s.trim() != s {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "true" | "false" | "yes" | "no" | "on" | "off" | "null" | "~" | "y" | "n"
    ) {
        return true;
    }
    if s.parse::<f64>().is_ok() || s.starts_with("0x") || s.starts_with("0o") {
        return true;
    }
    let first = s.chars().next().unwrap_or(' ');
    if "-?:,[]{}#&*!|>'\"%@`".contains(first) {
        return true;
    }
    s.contains(": ") || s.contains(" #") || s.ends_with(':') || s.chars().any(|c| c.is_control())
}

fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn key(k: &str) -> String {
    if needs_quotes(k) {
        quote(k)
    } else {
        k.to_string()
    }
}

fn scalar(v: &Value) -> String {
    match v {
        Value::Null => "null".into(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) if needs_quotes(s) => quote(s),
        Value::String(s) => s.clone(),
        Value::Array(a) if a.is_empty() => "[]".into(),
        Value::Object(m) if m.is_empty() => "{}".into(),
        _ => unreachable!("containers handled by caller"),
    }
}

fn is_container(v: &Value) -> bool {
    matches!(v, Value::Object(m) if !m.is_empty()) || matches!(v, Value::Array(a) if !a.is_empty())
}

fn emit_map(o: &mut String, m: &serde_json::Map<String, Value>, ind: usize) {
    for (k, v) in m {
        let pad = " ".repeat(ind);
        match v {
            Value::Object(c) if !c.is_empty() => {
                let _ = writeln!(o, "{pad}{}:", key(k));
                emit_map(o, c, ind + 2);
            }
            Value::Array(a) if !a.is_empty() => {
                let _ = writeln!(o, "{pad}{}:", key(k));
                emit_seq(o, a, ind);
            }
            _ => {
                let _ = writeln!(o, "{pad}{}: {}", key(k), scalar(v));
            }
        }
    }
}

fn emit_seq(o: &mut String, a: &[Value], ind: usize) {
    let pad = " ".repeat(ind);
    for v in a {
        match v {
            Value::Object(m) if !m.is_empty() => {
                // First key on the dash line, rest indented.
                let mut first = true;
                for (k, val) in m {
                    let prefix = if first {
                        format!("{pad}- ")
                    } else {
                        format!("{pad}  ")
                    };
                    first = false;
                    if is_container(val) {
                        let _ = writeln!(o, "{prefix}{}:", key(k));
                        match val {
                            Value::Object(c) => emit_map(o, c, ind + 4),
                            Value::Array(arr) => emit_seq(o, arr, ind + 2),
                            _ => {}
                        }
                    } else {
                        let _ = writeln!(o, "{prefix}{}: {}", key(k), scalar(val));
                    }
                }
            }
            Value::Array(inner) if !inner.is_empty() => {
                let _ = writeln!(o, "{pad}-");
                emit_seq(o, inner, ind + 2);
            }
            _ => {
                let _ = writeln!(o, "{pad}- {}", scalar(v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn emits_nested_structures() {
        let v = json!({
            "openapi": "3.1.0",
            "paths": {"/users/{id}": {"get": {"parameters": [{"name": "id", "in": "path", "required": true}], "responses": {"200": {"description": "OK"}}}}},
            "tags": ["a", "yes", "1.5", ""],
            "empty": {},
            "nested": [[1, 2], {"k": [3]}],
        });
        let y = to_yaml(&v);
        assert!(y.contains("openapi: 3.1.0\n"));
        assert!(y.contains("  /users/{id}:\n"));
        assert!(y.contains("- name: id\n"));
        assert!(y.contains("  in: path\n"));
        assert!(y.contains("\"200\":"), "numeric keys quoted:\n{y}");
        assert!(y.contains("- \"yes\""));
        assert!(y.contains("- \"1.5\""));
        assert!(y.contains("- \"\""));
        assert!(y.contains("empty: {}"));
    }
}
