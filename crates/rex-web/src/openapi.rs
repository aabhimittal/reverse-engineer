//! OpenAPI 3.1 generation from aggregated endpoints.

use crate::har::{Endpoint, Har, Request};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

/// Identify the auth scheme used by a request, as a security-scheme name.
pub fn auth_scheme(req: &Request) -> Option<String> {
    if let Some(a) = req.header("authorization") {
        let lower = a.to_ascii_lowercase();
        if lower.starts_with("bearer ") {
            return Some("bearerAuth".into());
        }
        if lower.starts_with("basic ") {
            return Some("basicAuth".into());
        }
        return Some("authorizationHeader".into());
    }
    for h in &req.headers {
        let n = h.name.to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "x-api-key" | "api-key" | "apikey" | "x-auth-token" | "x-access-token" | "x-apikey"
        ) {
            return Some(format!("apiKeyHeader:{}", h.name));
        }
    }
    for q in &req.query_string {
        let n = q.name.to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "api_key" | "apikey" | "key" | "access_token" | "token"
        ) {
            return Some(format!("apiKeyQuery:{}", q.name));
        }
    }
    if req.header("cookie").is_some() || !req.cookies.is_empty() {
        let names: Vec<String> = req
            .cookies
            .iter()
            .map(|c| c.name.clone())
            .chain(
                req.header("cookie")
                    .unwrap_or("")
                    .split(';')
                    .filter_map(|kv| kv.split_once('=').map(|(k, _)| k.trim().to_string())),
            )
            .collect();
        if let Some(n) = names.iter().find(|n| {
            let l = n.to_ascii_lowercase();
            l.contains("sess")
                || l.contains("auth")
                || l.contains("token")
                || l.contains("sid")
                || l == "jwt"
        }) {
            return Some(format!("cookieAuth:{n}"));
        }
    }
    None
}

fn scheme_def(name: &str) -> (String, Value) {
    match name.split_once(':') {
        Some(("apiKeyHeader", h)) => (
            format!("apiKey_{}", sanitize(h)),
            json!({"type": "apiKey", "in": "header", "name": h}),
        ),
        Some(("apiKeyQuery", q)) => (
            format!("apiKey_{}", sanitize(q)),
            json!({"type": "apiKey", "in": "query", "name": q}),
        ),
        Some(("cookieAuth", c)) => (
            format!("cookie_{}", sanitize(c)),
            json!({"type": "apiKey", "in": "cookie", "name": c}),
        ),
        _ => match name {
            "bearerAuth" => (
                "bearerAuth".into(),
                json!({"type": "http", "scheme": "bearer"}),
            ),
            "basicAuth" => (
                "basicAuth".into(),
                json!({"type": "http", "scheme": "basic"}),
            ),
            _ => (
                "authorizationHeader".into(),
                json!({"type": "apiKey", "in": "header", "name": "Authorization"}),
            ),
        },
    }
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

fn op_id(method: &str, path: &str) -> String {
    let mut s = method.to_ascii_lowercase();
    for part in path.split('/').filter(|p| !p.is_empty()) {
        let (by, word) = match part.strip_prefix('{').and_then(|p| p.strip_suffix('}')) {
            Some(p) => (true, p),
            None => (false, part),
        };
        if by {
            s.push_str("By");
        }
        let mut chars = word.chars().filter(|c| c.is_ascii_alphanumeric());
        if let Some(f) = chars.next() {
            s.extend(f.to_uppercase());
            s.extend(chars);
        }
    }
    s
}

fn reason(status: i64) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 | 302 | 307 | 308 => "Redirect",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        422 => "Unprocessable Entity",
        429 => "Too Many Requests",
        500..=599 => "Server Error",
        _ => "Response",
    }
}

/// Build an OpenAPI 3.1 document.
pub fn build(har: &Har, endpoints: &[Endpoint], title: Option<&str>) -> Value {
    let mut servers: BTreeMap<String, usize> = BTreeMap::new();
    for e in endpoints {
        for s in &e.servers {
            *servers.entry(s.clone()).or_default() += e.count;
        }
    }
    let mut server_list: Vec<(String, usize)> = servers.into_iter().collect();
    server_list.sort_by_key(|s| std::cmp::Reverse(s.1));
    let main_host = server_list.first().map(|s| s.0.clone()).unwrap_or_default();
    let title = title.map(str::to_string).unwrap_or_else(|| {
        format!(
            "{} (inferred)",
            main_host.split("://").nth(1).unwrap_or("API")
        )
    });

    let mut paths = Map::new();
    let mut schemes = Map::new();
    for e in endpoints {
        let mut op = Map::new();
        op.insert("operationId".into(), json!(op_id(&e.method, &e.path)));
        op.insert(
            "summary".into(),
            json!(format!("{} {} (observed {}×)", e.method, e.path, e.count)),
        );
        if let Some(tag) = e.path.split('/').find(|s| {
            !s.is_empty()
                && !s.starts_with('{')
                && !matches!(*s, "api" | "v1" | "v2" | "v3" | "rest")
        }) {
            op.insert("tags".into(), json!([tag]));
        }
        let mut params = Vec::new();
        for (name, p) in &e.path_params {
            let mut schema = p.shape.to_schema();
            if let Some(o) = schema.as_object_mut() {
                o.remove("examples");
            }
            let example = p
                .shape
                .string
                .as_ref()
                .and_then(|s| s.examples.iter().next().cloned());
            let mut param = json!({"name": name, "in": "path", "required": true, "schema": schema});
            if let Some(x) = example {
                param["example"] = json!(x);
            }
            params.push(param);
        }
        for (name, p) in &e.query {
            params.push(json!({
                "name": name, "in": "query", "required": p.count == e.count,
                "schema": p.shape.to_schema(),
            }));
        }
        for (name, p) in &e.headers {
            if e.auth.iter().any(|a| a.ends_with(&format!(":{name}"))) {
                continue; // documented as a security scheme instead
            }
            params.push(json!({
                "name": name, "in": "header", "required": p.count == e.count,
                "schema": {"type": "string"},
            }));
        }
        if !params.is_empty() {
            op.insert("parameters".into(), Value::Array(params));
        }
        if !e.request_bodies.is_empty() {
            let mut content = Map::new();
            for (ct, shape) in &e.request_bodies {
                let schema = if shape.seen > 0 {
                    shape.to_schema()
                } else {
                    json!({})
                };
                content.insert(ct.clone(), json!({"schema": schema}));
            }
            op.insert("requestBody".into(), json!({"content": content}));
        }
        let mut responses = Map::new();
        for (status, by_ct) in &e.responses {
            let mut r = json!({"description": reason(*status)});
            let mut content = Map::new();
            for (ct, shape) in by_ct {
                if ct == "application/octet-stream" && shape.seen == 0 {
                    continue;
                }
                let schema = if shape.seen > 0 {
                    shape.to_schema()
                } else {
                    json!({})
                };
                content.insert(ct.clone(), json!({"schema": schema}));
            }
            if !content.is_empty() && *status != 204 && *status != 304 {
                r["content"] = Value::Object(content);
            }
            responses.insert(status.to_string(), r);
        }
        if responses.is_empty() {
            responses.insert("default".into(), json!({"description": "Not observed"}));
        }
        op.insert("responses".into(), Value::Object(responses));
        if !e.auth.is_empty() {
            let sec: Vec<Value> = e
                .auth
                .iter()
                .map(|a| {
                    let (n, def) = scheme_def(a);
                    schemes.insert(n.clone(), def);
                    json!({ n: [] })
                })
                .collect();
            op.insert("security".into(), Value::Array(sec));
        }
        if e.examples.len() > 1 || e.examples.iter().any(|x| x != &e.path) {
            op.insert("x-rex-examples".into(), json!(e.examples));
        }
        if e.servers.len() == 1 && e.servers.iter().next() != Some(&main_host) {
            op.insert("servers".into(), json!([{"url": e.servers.iter().next()}]));
        }
        let path_item = paths.entry(e.path.clone()).or_insert_with(|| json!({}));
        path_item[e.method.to_ascii_lowercase()] = Value::Object(op);
    }

    let creator = har
        .log
        .creator
        .as_ref()
        .map(|c| format!("{} {}", c.name, c.version))
        .unwrap_or_default();
    let mut doc = json!({
        "openapi": "3.1.0",
        "info": {
            "title": title,
            "version": "0.0.0-inferred",
            "description": format!(
                "Inferred by rex {} from {} captured requests{}. Review before publishing: schemas reflect only observed traffic.",
                rex_core::VERSION,
                har.log.entries.len(),
                if creator.trim().is_empty() { String::new() } else { format!(" (HAR from {})", creator.trim()) }
            ),
        },
        "servers": server_list.iter().map(|(s, _)| json!({"url": s})).collect::<Vec<_>>(),
        "paths": paths,
    });
    if !schemes.is_empty() {
        doc["components"] = json!({"securitySchemes": schemes});
    }
    doc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_ids() {
        assert_eq!(
            op_id("GET", "/api/v1/users/{userId}/orders"),
            "getApiV1UsersByUserIdOrders"
        );
        assert_eq!(op_id("POST", "/"), "post");
    }
}
