//! # rex-mcp
//!
//! A [Model Context Protocol](https://modelcontextprotocol.io) server over stdio,
//! so agents (Claude Code, Claude Desktop, Cursor, …) can drive rex as tools.
//!
//! The protocol is newline-delimited JSON-RPC 2.0. This implementation is
//! intentionally small and synchronous: it supports `initialize`, `ping`,
//! `tools/list` and `tools/call`, which is all a tool server needs.
//!
//! ```json
//! { "mcpServers": { "rex": { "command": "rex", "args": ["mcp"] } } }
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rex_engine::rex_core::{AnalysisOptions, DEFAULT_MAX_SIZE};
use rex_engine::rex_report::{self, Format};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::path::Path;

/// Protocol versions we can speak (newest first).
pub const PROTOCOL_VERSIONS: &[&str] = &["2025-06-18", "2025-03-26", "2024-11-05"];

/// Maximum characters returned per tool call (agents have finite context).
pub const MAX_OUTPUT: usize = 60_000;

fn tool(name: &str, description: &str, props: Value, required: &[&str]) -> Value {
    json!({
        "name": name,
        "description": description,
        "inputSchema": { "type": "object", "properties": props, "required": required },
        "annotations": { "readOnlyHint": !name.contains("extract"), "openWorldHint": false },
    })
}

/// Tool catalogue.
pub fn tools() -> Vec<Value> {
    let path = json!({"type": "string", "description": "Absolute or relative path to the file or directory to analyse"});
    vec![
        tool(
            "rex_analyze",
            "Auto-detect and fully analyse a file or directory: ELF/PE/Mach-O binaries, firmware blobs, APK/DEX, HAR captures, JS bundles, source maps, or a source tree. Returns a Markdown report with findings (severity, ATT&CK), sections and evidence. Start here.",
            json!({"path": path, "only": {"type": "array", "items": {"type": "string"}, "description": "Restrict to analyzer name prefixes, e.g. [\"binary.checksec\"]"}, "deep": {"type": "boolean"}}),
            &["path"],
        ),
        tool(
            "rex_checksec",
            "Exploit mitigations (NX, PIE/ASLR, RELRO, canaries, CFG, CET, signing) for one or more native binaries.",
            json!({"paths": {"type": "array", "items": {"type": "string"}}}),
            &["paths"],
        ),
        tool(
            "rex_strings",
            "Extract ASCII/UTF-16 strings with classification (url, ip, path, registry, command, secret, email, …).",
            json!({"path": path, "min_len": {"type": "integer", "default": 5}, "categories": {"type": "array", "items": {"type": "string"}}, "all": {"type": "boolean", "description": "Include unclassified strings"}}),
            &["path"],
        ),
        tool(
            "rex_functions",
            "List recovered functions (address, name, size, complexity, callers, imports) of an x86/x64 binary.",
            json!({"path": path}),
            &["path"],
        ),
        tool(
            "rex_disasm",
            "Disassemble a function by name/address (annotated listing with basic blocks, string references and resolved imports), or `count` instructions from an address.",
            json!({"path": path, "function": {"type": "string"}, "address": {"type": "string", "description": "hex like 0x401000"}, "count": {"type": "integer", "default": 64}}),
            &["path"],
        ),
        tool(
            "rex_cfg",
            "Control-flow graph of a function as Mermaid or Graphviz DOT.",
            json!({"path": path, "function": {"type": "string"}, "format": {"type": "string", "enum": ["mermaid", "dot"]}}),
            &["path", "function"],
        ),
        tool(
            "rex_decompile",
            "Decompile a function to pseudo-C with Ghidra (optional: only works when Ghidra is installed; slow, as Ghidra analyses the whole file first). Use rex_disasm when this reports Ghidra missing.",
            json!({"path": path, "function": {"type": "string", "description": "Function name or address"}}),
            &["path", "function"],
        ),
        tool(
            "rex_xrefs",
            "Cross-references: callers/callees/strings of a function, or which functions reference a string or call an import.",
            json!({"path": path, "target": {"type": "string"}}),
            &["path", "target"],
        ),
        tool(
            "rex_diff",
            "Function-level diff of two binaries (patch analysis): changed/added/removed functions, import and string changes.",
            json!({"old": {"type": "string"}, "new": {"type": "string"}}),
            &["old", "new"],
        ),
        tool(
            "rex_carve",
            "Scan a firmware image / blob for embedded files and filesystems (gzip, squashfs, cpio, uImage, ELF, PEM, …) with entropy profile.",
            json!({"path": path}),
            &["path"],
        ),
        tool(
            "rex_har_to_openapi",
            "Infer an OpenAPI 3.1 spec (YAML) from a HAR traffic capture: templated paths, parameters, JSON schemas, auth schemes.",
            json!({"path": path, "include_static": {"type": "boolean"}, "hosts": {"type": "array", "items": {"type": "string"}}}),
            &["path"],
        ),
        tool(
            "rex_code_map",
            "Codebase atlas for a source directory: languages, stack, entry points, HTTP routes, module graph, hotspots, ownership, security smells.",
            json!({"path": path}),
            &["path"],
        ),
    ]
}

/// A workflow prompt: (name, description, arguments `(name, description)`, template with `{arg}` placeholders).
type PromptDef = (
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
    &'static str,
);

/// Reusable workflows. Prompts teach an agent *how to combine* the tools, which is where most
/// of the value is: the same eleven tools get used far better with a plan.
pub static PROMPTS: &[PromptDef] = &[
    (
        "triage_binary",
        "Triage an unknown executable or firmware image and report what it is, what it can do and where to look next",
        &[("path", "Path to the file")],
        "Triage `{path}` with rex, using static analysis only (never execute it).\n\
         1. Call rex_analyze on the path. Read the findings first, then packing, capabilities and strings.\n\
         2. If it is a native binary, call rex_functions, then rex_xrefs on the most suspicious import or string, then rex_disasm on the one or two functions that matter (rex_decompile gives pseudo-C for one of them when Ghidra is installed; skip it if it reports Ghidra missing).\n\
         3. Report: what it is; what it can do (cite finding ids and ATT&CK ids); risk with justification and benign explanations; indicators (hashes, hosts, paths); and the 3 next steps a human should take.\n\
         Separate facts (from tool output) from inferences, and say what you could not determine.",
    ),
    (
        "patch_diff",
        "Compare two builds of a binary and find what a security update changed",
        &[
            ("old", "Path to the old build"),
            ("new", "Path to the new build"),
        ],
        "Compare `{old}` (before) and `{new}` (after) with rex_diff.\n\
         Focus on functions marked as small surgical changes, newly added imports, and new or removed strings. For the top candidates call rex_disasm on both builds and describe the logical change (for example a new length check before a copy). \n\
         Conclude with a hypothesis about what the update fixes, how confident you are, and what evidence would confirm it.",
    ),
    (
        "reverse_api",
        "Turn a HAR traffic capture into an API spec and a security review",
        &[("path", "Path to the .har file")],
        "Call rex_har_to_openapi on `{path}`.\n\
         1. Summarise the API: hosts, endpoint groups, auth scheme, notable request/response shapes.\n\
         2. List the traffic-audit findings (cleartext, credentials in the capture, JWT lifetime, cookie flags, CORS) ordered by severity. Values are masked; do not try to recover them.\n\
         3. Point out anything in the inferred spec that looks incomplete because it was never exercised in the capture.",
    ),
    (
        "map_codebase",
        "Build a mental model of an unfamiliar repository",
        &[("path", "Path to the repository root")],
        "Call rex_code_map on `{path}`.\n\
         Explain the system to a new engineer: what it is and its stack; how it starts and its HTTP routes; the 5 most central modules to read first and why; the hotspots (frequently changed, complex files); who owns what; and any risky patterns or hard-coded secrets (masked). \n\
         End with a suggested reading order.",
    ),
    (
        "audit_apk",
        "Review an Android app's manifest, components and risky behaviours",
        &[("path", "Path to the .apk")],
        "Call rex_analyze on `{path}`.\n\
         Review the manifest (debuggable, backup, cleartext, exported components without permissions, deep links), requested permissions, risky API usage and native libraries. \n\
         Rank issues by real-world exploitability and give a concrete fix for each.",
    ),
    (
        "audit_electron",
        "Review an Electron app (app.asar) for window-security mistakes, IPC exposure, secrets and risky dependencies",
        &[("path", "Path to app.asar")],
        "Call rex_analyze on `{path}`.\n\
         1. List the BrowserWindow security findings (nodeIntegration, contextIsolation, sandbox, webSecurity) and, for each, what an attacker needs first (an XSS, a remote page, a malicious file) to turn it into code execution.\n\
         2. Walk the IPC channel table: which channels accept file paths, URLs or commands from a renderer without validation, and what the worst call would do.\n\
         3. Report masked secrets, shipped source maps and bundled native code, then rank everything by exploitability and give one concrete fix each.",
    ),
];

fn prompts_list() -> Value {
    json!({ "prompts": PROMPTS.iter().map(|(name, desc, args, _)| json!({
        "name": name,
        "description": desc,
        "arguments": args.iter().map(|(n, d)| json!({ "name": n, "description": d, "required": true })).collect::<Vec<_>>(),
    })).collect::<Vec<_>>() })
}

/// Render a prompt; `Err` carries a JSON-RPC error message.
pub fn prompt_get(name: &str, args: &Value) -> Result<Value, String> {
    let (_, desc, params, template) = PROMPTS
        .iter()
        .find(|p| p.0 == name)
        .ok_or_else(|| format!("unknown prompt '{name}'"))?;
    let mut text = template.to_string();
    for (arg, _) in params.iter() {
        let v = args
            .get(*arg)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("missing required argument '{arg}'"))?;
        text = text.replace(&format!("{{{arg}}}"), v);
    }
    Ok(
        json!({ "description": desc, "messages": [{ "role": "user", "content": { "type": "text", "text": text } }] }),
    )
}

fn s<'a>(args: &'a Value, k: &str) -> Option<&'a str> {
    args.get(k).and_then(Value::as_str)
}

fn md(r: &rex_engine::rex_core::Report) -> String {
    rex_report::render(r, Format::Markdown, Default::default())
}

fn truncate(mut s: String) -> String {
    if s.len() > MAX_OUTPUT {
        let mut cut = MAX_OUTPUT;
        while !s.is_char_boundary(cut) {
            cut -= 1;
        }
        s.truncate(cut);
        s.push_str(
            "\n\n…[truncated: narrow the request, e.g. `only`, a single function, or categories]",
        );
    }
    s
}

/// Execute a tool; returns text or an error message.
pub fn call(name: &str, args: &Value) -> Result<String, String> {
    let opts = AnalysisOptions::default();
    let load = |k: &str| -> Result<rex_engine::rex_core::Artifact, String> {
        let p = s(args, k).ok_or_else(|| format!("missing '{k}'"))?;
        rex_engine::load(Path::new(p), DEFAULT_MAX_SIZE, None).map_err(|e| e.to_string())
    };
    let out = match name {
        "rex_analyze" => {
            let a = load("path")?;
            let only: Vec<String> = args
                .get("only")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let o = AnalysisOptions {
                deep: args.get("deep").and_then(Value::as_bool).unwrap_or(false),
                ..opts
            };
            md(&rex_engine::analyze(&a, &o, &only))
        }
        "rex_checksec" => {
            let paths = args
                .get("paths")
                .and_then(Value::as_array)
                .ok_or("missing 'paths'")?;
            let arts = paths
                .iter()
                .filter_map(Value::as_str)
                .map(|p| {
                    rex_engine::load(Path::new(p), DEFAULT_MAX_SIZE, None)
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, _>>()?;
            md(&rex_engine::checksec_many(&arts))
        }
        "rex_strings" => {
            let a = load("path")?;
            let cats: Vec<String> = args
                .get("categories")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let min = args.get("min_len").and_then(Value::as_u64).unwrap_or(5) as usize;
            md(&rex_engine::strings_report(
                &a,
                min,
                args.get("all").and_then(Value::as_bool).unwrap_or(false),
                &cats,
            ))
        }
        "rex_functions" => {
            md(&rex_engine::functions_report(&load("path")?, &opts).map_err(|e| e.to_string())?)
        }
        "rex_disasm" => {
            let a = load("path")?;
            let addr = s(args, "address").and_then(rex_engine::parse_addr);
            let count = args
                .get("count")
                .and_then(Value::as_u64)
                .unwrap_or(64)
                .min(5000) as usize;
            format!(
                "```asm\n{}```",
                rex_engine::disasm(&a, &opts, s(args, "function"), addr, count)
                    .map_err(|e| e.to_string())?
            )
        }
        "rex_cfg" => {
            let a = load("path")?;
            let f = s(args, "function").ok_or("missing 'function'")?;
            let fmt = s(args, "format").unwrap_or("mermaid");
            format!(
                "```{fmt}\n{}```",
                rex_engine::cfg(&a, &opts, f, fmt).map_err(|e| e.to_string())?
            )
        }
        "rex_decompile" => {
            let headless =
                rex_engine::ghidra::locate(&|k| std::env::var(k).ok(), &rex_engine::which);
            md(&rex_engine::decompile_report(
                &load("path")?,
                &opts,
                Some(s(args, "function").ok_or("missing 'function'")?),
                false,
                rex_engine::ghidra::DEFAULT_TIMEOUT,
                headless.as_deref(),
            )
            .map_err(|e| e.to_string())?)
        }
        "rex_xrefs" => md(&rex_engine::xrefs(
            &load("path")?,
            &opts,
            s(args, "target").ok_or("missing 'target'")?,
        )
        .map_err(|e| e.to_string())?),
        "rex_diff" => md(
            &rex_engine::diff_report(&load("old")?, &load("new")?, &opts)
                .map_err(|e| e.to_string())?,
        ),
        "rex_carve" => {
            md(&rex_engine::carve_report(&load("path")?, None).map_err(|e| e.to_string())?)
        }
        "rex_har_to_openapi" => {
            let a = load("path")?;
            let hosts: Vec<String> = args
                .get("hosts")
                .and_then(Value::as_array)
                .map(|v| {
                    v.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let (spec, rep) = rex_engine::har_to_openapi(
                &a,
                args.get("include_static")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                &hosts,
                None,
            )
            .map_err(|e| e.to_string())?;
            format!(
                "{}\n\n## OpenAPI\n\n```yaml\n{}```",
                md(&rep),
                rex_engine::openapi_yaml(&spec)
            )
        }
        "rex_code_map" => {
            let a = load("path")?;
            md(&rex_engine::analyze(&a, &opts, &["code.".into()]))
        }
        other => return Err(format!("unknown tool '{other}'")),
    };
    Ok(truncate(out))
}

/// Handle one JSON-RPC message. Returns a response for requests, `None` for notifications.
pub fn handle(msg: &Value) -> Option<Value> {
    let id = msg.get("id").cloned();
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(Value::Null);
    let id = id?; // notifications get no reply
    let result = match method {
        "initialize" => {
            let requested = params
                .get("protocolVersion")
                .and_then(Value::as_str)
                .unwrap_or(PROTOCOL_VERSIONS[0]);
            let version = if PROTOCOL_VERSIONS.contains(&requested) {
                requested
            } else {
                PROTOCOL_VERSIONS[0]
            };
            Ok(json!({
                "protocolVersion": version,
                "capabilities": { "tools": { "listChanged": false }, "prompts": { "listChanged": false } },
                "serverInfo": { "name": "rex", "title": "rex reverse-engineering toolkit", "version": rex_engine::rex_core::VERSION },
                "instructions": "rex statically analyses binaries (ELF/PE/Mach-O), firmware, Android apps, HAR traffic, JS bundles and source trees. It never executes inputs. Start with rex_analyze, then drill down with rex_functions / rex_disasm / rex_xrefs (binaries, plus rex_decompile when Ghidra is installed), rex_har_to_openapi (traffic) or rex_code_map (source). Ready-made workflows are available via prompts/list."
            }))
        }
        "ping" => Ok(json!({})),
        "tools/list" => Ok(json!({ "tools": tools() })),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            // Tool failures are reported in-band (isError) so the agent can react.
            let r = std::panic::catch_unwind(|| call(name, &args))
                .unwrap_or_else(|_| Err("internal error while analysing input".into()));
            Ok(match r {
                Ok(text) => {
                    json!({ "content": [{ "type": "text", "text": text }], "isError": false })
                }
                Err(e) => json!({ "content": [{ "type": "text", "text": e }], "isError": true }),
            })
        }
        "resources/list" => Ok(json!({ "resources": [] })),
        "prompts/list" => Ok(prompts_list()),
        "prompts/get" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("");
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            prompt_get(name, &args).map_err(|m| json!({ "code": -32602, "message": m }))
        }
        _ => Err(json!({ "code": -32601, "message": format!("method not found: {method}") })),
    };
    Some(match result {
        Ok(r) => json!({ "jsonrpc": "2.0", "id": id, "result": r }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e }),
    })
}

/// Serve on stdin/stdout until EOF.
pub fn serve() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout().lock();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Value>(&line) {
            Ok(Value::Array(batch)) => {
                let v: Vec<Value> = batch.iter().filter_map(handle).collect();
                (!v.is_empty()).then_some(Value::Array(v))
            }
            Ok(msg) => handle(&msg),
            Err(e) => Some(
                json!({ "jsonrpc": "2.0", "id": null, "error": { "code": -32700, "message": format!("parse error: {e}") } }),
            ),
        };
        if let Some(r) = reply {
            writeln!(stdout, "{}", serde_json::to_string(&r).unwrap_or_default())?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_flow() {
        let init = handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})).unwrap();
        assert_eq!(init["result"]["protocolVersion"], "2025-03-26");
        assert!(
            handle(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"})).is_none()
        );
        let list = handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})).unwrap();
        let names: Vec<&str> = list["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"rex_analyze") && names.contains(&"rex_disasm"));
        let bad = handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "nope"})).unwrap();
        assert_eq!(bad["error"]["code"], -32601);
    }

    #[test]
    fn prompts_list_and_get() {
        let list = handle(&json!({"jsonrpc": "2.0", "id": 1, "method": "prompts/list"})).unwrap();
        let names: Vec<&str> = list["result"]["prompts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["name"].as_str().unwrap())
            .collect();
        for n in [
            "triage_binary",
            "patch_diff",
            "reverse_api",
            "map_codebase",
            "audit_apk",
            "audit_electron",
        ] {
            assert!(names.contains(&n), "{n}");
        }
        let got = handle(&json!({"jsonrpc": "2.0", "id": 2, "method": "prompts/get", "params": {"name": "patch_diff", "arguments": {"old": "a.bin", "new": "b.bin"}}})).unwrap();
        let text = got["result"]["messages"][0]["content"]["text"]
            .as_str()
            .unwrap();
        assert!(
            text.contains("`a.bin`")
                && text.contains("`b.bin`")
                && text.contains("rex_diff")
                && !text.contains("{old}")
        );
        let missing = handle(&json!({"jsonrpc": "2.0", "id": 3, "method": "prompts/get", "params": {"name": "patch_diff", "arguments": {"old": "a"}}})).unwrap();
        assert_eq!(missing["error"]["code"], -32602);
        let unknown = handle(&json!({"jsonrpc": "2.0", "id": 4, "method": "prompts/get", "params": {"name": "nope"}})).unwrap();
        assert_eq!(unknown["error"]["code"], -32602);
        let init =
            handle(&json!({"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": {}}))
                .unwrap();
        assert!(init["result"]["capabilities"]["prompts"].is_object());
    }

    #[test]
    fn prompts_only_reference_real_tools() {
        let names: Vec<String> = tools()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect();
        for (pname, _, _, template) in PROMPTS {
            for word in template
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter(|w| w.starts_with("rex_"))
            {
                assert!(
                    names.iter().any(|n| n == word),
                    "prompt {pname} references unknown tool {word}"
                );
            }
        }
    }

    #[test]
    fn tool_calls() {
        let fx = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../rex-binary/tests/fixtures/crackme.elf"
        );
        let r = handle(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "rex_disasm", "arguments": {"path": fx, "function": "check_password"}}})).unwrap();
        assert_eq!(r["result"]["isError"], false);
        assert!(
            r["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("strlen@plt")
        );
        let r = handle(&json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "rex_analyze", "arguments": {"path": "/definitely/missing"}}})).unwrap();
        assert_eq!(r["result"]["isError"], true);
        let har = concat!(env!("CARGO_MANIFEST_DIR"), "/../../labs/web/sample.har");
        let r = call("rex_har_to_openapi", &json!({"path": har})).unwrap();
        assert!(r.contains("openapi: 3.1.0"));
    }
}
