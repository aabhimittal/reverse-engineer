//! # rex-ai
//!
//! Optional LLM assistance layered on top of rex's deterministic analysis.
//!
//! Static analysis tells you *what is there*; a language model is good at
//! the next step, *what it probably means*: naming `sub_401a20` as
//! `decrypt_config`, or turning 40 findings into a three-paragraph
//! briefing. rex keeps the two strictly separate:
//!
//! * Nothing leaves your machine unless you pass `--ai` (or call this crate).
//! * Secrets found in the input are masked before sending ([`redact`]).
//! * `--ai-provider ollama` keeps everything local.
//!
//! Providers:
//!
//! | Provider | Env | Default model |
//! |---|---|---|
//! | `anthropic` (default) | `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; optional `ANTHROPIC_BASE_URL` | `claude-opus-5-5` |
//! | `ollama` | optional `OLLAMA_HOST` (default `http://localhost:11434`) | `llama3.1` |
#![forbid(unsafe_code)]
#![warn(missing_docs)]

use rex_core::{Error, Report, Result};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Duration;

/// Default Claude model.
pub const DEFAULT_ANTHROPIC_MODEL: &str = "claude-opus-5-5";
/// Default local model.
pub const DEFAULT_OLLAMA_MODEL: &str = "llama3.1";
/// Characters of report context sent per request.
pub const MAX_CONTEXT_CHARS: usize = 400_000;

/// One request to a model.
#[derive(Debug, Clone)]
pub struct Prompt {
    /// System prompt.
    pub system: String,
    /// User content.
    pub user: String,
    /// Optional JSON Schema the reply must follow.
    pub schema: Option<Value>,
    /// Output token cap.
    pub max_tokens: u32,
}

/// A chat-completion backend.
pub trait Llm {
    /// Human-readable `provider/model`.
    fn describe(&self) -> String;
    /// Run one completion and return the text (JSON text when a schema is given).
    fn complete(&self, p: &Prompt) -> Result<String>;
}

fn agent(timeout_secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(timeout_secs)))
        .http_status_as_error(false)
        .proxy(ureq::Proxy::try_from_env())
        .build()
        .into()
}

// ───────────────────────────── Anthropic ─────────────────────────────

enum Auth {
    ApiKey(String),
    Bearer(String),
}

/// Claude via the Anthropic Messages API (raw HTTP; Rust has no official SDK).
pub struct Anthropic {
    auth: Auth,
    base_url: String,
    /// Model id.
    pub model: String,
    /// `output_config.effort` (`low` … `max`). Set explicitly: the default differs per model.
    pub effort: String,
    /// Ask the API to retry policy refusals on Anthropic's recommended fallback model.
    pub fallbacks: bool,
}

impl Anthropic {
    /// Build from environment variables.
    pub fn from_env(model: Option<&str>) -> Result<Self> {
        let auth = match (
            std::env::var("ANTHROPIC_API_KEY"),
            std::env::var("ANTHROPIC_AUTH_TOKEN"),
        ) {
            (Ok(k), _) if !k.is_empty() => Auth::ApiKey(k),
            (_, Ok(t)) if !t.is_empty() => Auth::Bearer(t),
            _ => {
                return Err(Error::Other(
                    "no Claude credentials: set ANTHROPIC_API_KEY (or ANTHROPIC_AUTH_TOKEN), or use --ai-provider ollama".into(),
                ));
            }
        };
        Ok(Self {
            auth,
            base_url: std::env::var("ANTHROPIC_BASE_URL")
                .unwrap_or_else(|_| "https://api.anthropic.com".into())
                .trim_end_matches('/')
                .to_string(),
            model: model
                .map(str::to_string)
                .or_else(|| std::env::var("REX_AI_MODEL").ok())
                .unwrap_or_else(|| DEFAULT_ANTHROPIC_MODEL.into()),
            effort: std::env::var("REX_AI_EFFORT").unwrap_or_else(|_| "medium".into()),
            fallbacks: std::env::var_os("REX_AI_NO_FALLBACK").is_none(),
        })
    }

    /// The JSON body sent to `POST /v1/messages`.
    pub fn request_body(&self, p: &Prompt) -> Value {
        let mut output_config = json!({ "effort": self.effort });
        if let Some(schema) = &p.schema {
            output_config["format"] = json!({ "type": "json_schema", "schema": schema });
        }
        // Adaptive thinking is the default on current models, so `thinking` is omitted.
        let mut body = json!({
            "model": self.model,
            "max_tokens": p.max_tokens,
            "system": p.system,
            "messages": [{ "role": "user", "content": p.user }],
            "output_config": output_config,
        });
        if self.fallbacks {
            // Security-research content can trip safety classifiers on legitimate work;
            // let the API re-run declined requests on the recommended fallback model.
            body["fallbacks"] = json!("default");
        }
        body
    }

    /// Extract the answer text from a Messages API response.
    pub fn parse_response(v: &Value) -> Result<String> {
        if let Some(err) = v.get("error") {
            return Err(Error::Other(format!(
                "Claude API error ({}): {}",
                err.get("type").and_then(Value::as_str).unwrap_or("unknown"),
                err.get("message").and_then(Value::as_str).unwrap_or("")
            )));
        }
        // Always branch on stop_reason before reading content.
        match v.get("stop_reason").and_then(Value::as_str) {
            Some("refusal") => {
                let cat = v
                    .pointer("/stop_details/category")
                    .and_then(Value::as_str)
                    .unwrap_or("unspecified");
                return Err(Error::Other(format!(
                    "the model declined this request (category: {cat}); try --ai-provider ollama or a narrower question"
                )));
            }
            Some("max_tokens") => {} // return what we have; callers note truncation
            _ => {}
        }
        let text: String = v
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                    .filter_map(|b| b.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();
        if text.is_empty() {
            return Err(Error::Other("empty response from Claude".into()));
        }
        Ok(text)
    }
}

impl Llm for Anthropic {
    fn describe(&self) -> String {
        format!("anthropic/{}", self.model)
    }

    fn complete(&self, p: &Prompt) -> Result<String> {
        let mut req = agent(600)
            .post(&format!("{}/v1/messages", self.base_url))
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json");
        let mut betas = Vec::new();
        if self.fallbacks {
            betas.push("server-side-fallback-2026-07-01");
        }
        req = match &self.auth {
            Auth::ApiKey(k) => req.header("x-api-key", k),
            Auth::Bearer(t) => {
                betas.push("oauth-2025-04-20");
                req.header("authorization", &format!("Bearer {t}"))
            }
        };
        if !betas.is_empty() {
            req = req.header("anthropic-beta", &betas.join(","));
        }
        let mut resp = req
            .send_json(self.request_body(p))
            .map_err(|e| Error::Other(format!("Claude API request failed: {e}")))?;
        let status = resp.status().as_u16();
        let v: Value = resp.body_mut().read_json().map_err(|e| {
            Error::Other(format!(
                "Claude API returned HTTP {status} with an unreadable body: {e}"
            ))
        })?;
        Self::parse_response(&v)
    }
}

// ───────────────────────────── Ollama ─────────────────────────────

/// A local model served by Ollama: nothing leaves the machine.
pub struct Ollama {
    host: String,
    /// Model name.
    pub model: String,
}

impl Ollama {
    /// Build from environment.
    pub fn from_env(model: Option<&str>) -> Self {
        let host = std::env::var("OLLAMA_HOST").unwrap_or_else(|_| "http://localhost:11434".into());
        let host = if host.starts_with("http") {
            host
        } else {
            format!("http://{host}")
        };
        Self {
            host: host.trim_end_matches('/').to_string(),
            model: model
                .map(str::to_string)
                .or_else(|| std::env::var("REX_AI_MODEL").ok())
                .unwrap_or_else(|| DEFAULT_OLLAMA_MODEL.into()),
        }
    }
}

impl Llm for Ollama {
    fn describe(&self) -> String {
        format!("ollama/{}", self.model)
    }

    fn complete(&self, p: &Prompt) -> Result<String> {
        let mut body = json!({
            "model": self.model,
            "stream": false,
            "messages": [{ "role": "system", "content": p.system }, { "role": "user", "content": p.user }],
            "options": { "num_predict": p.max_tokens },
        });
        if let Some(s) = &p.schema {
            body["format"] = s.clone();
        }
        let mut resp = agent(1800)
            .post(&format!("{}/api/chat", self.host))
            .send_json(body)
            .map_err(|e| {
                Error::Other(format!(
                    "Ollama request to {} failed: {e} (is `ollama serve` running?)",
                    self.host
                ))
            })?;
        let v: Value = resp
            .body_mut()
            .read_json()
            .map_err(|e| Error::Other(format!("Ollama returned an unreadable body: {e}")))?;
        if let Some(e) = v.get("error").and_then(Value::as_str) {
            return Err(Error::Other(format!("Ollama error: {e}")));
        }
        v.pointer("/message/content")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| Error::Other("Ollama response had no message content".into()))
    }
}

/// Pick a provider by name (`anthropic` | `ollama`).
pub fn provider(name: Option<&str>, model: Option<&str>) -> Result<Box<dyn Llm>> {
    match name.unwrap_or("anthropic") {
        "anthropic" | "claude" => Ok(Box::new(Anthropic::from_env(model)?)),
        "ollama" | "local" => Ok(Box::new(Ollama::from_env(model))),
        other => Err(Error::Other(format!(
            "unknown AI provider '{other}' (anthropic|ollama)"
        ))),
    }
}

// ───────────────────────────── tasks ─────────────────────────────

/// Mask credentials before anything is sent to a model.
pub fn redact(text: &str) -> String {
    let mut out = text.to_string();
    for h in rex_core::secrets::scan(text) {
        out = out.replace(&h.value, &format!("[REDACTED {}]", h.kind));
    }
    out
}

fn bounded(text: String) -> (String, bool) {
    if text.len() <= MAX_CONTEXT_CHARS {
        return (text, false);
    }
    let mut cut = MAX_CONTEXT_CHARS;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_string(), true)
}

const ANALYST: &str = "You are a senior reverse engineer and malware/security analyst. You are given the output of `rex`, \
a static analysis toolkit. The input was never executed. Be precise and evidence-driven: tie every claim to a specific \
finding, string, import, function or address in the report, distinguish facts from inferences, and say when the evidence \
is insufficient. Write in clear Markdown.";

/// Executive summary of a report.
pub fn summarize(llm: &dyn Llm, report: &Report) -> Result<String> {
    let md = rex_report::render(report, rex_report::Format::Markdown, Default::default());
    let (ctx, truncated) = bounded(redact(&md));
    let note = if truncated {
        format!(
            "\n\nNOTE: the report was {} characters and only the first {MAX_CONTEXT_CHARS} are included; say so if it limits your conclusions.",
            md.len()
        )
    } else {
        String::new()
    };
    llm.complete(&Prompt {
        system: ANALYST.into(),
        user: format!(
            "Write a briefing on this artifact with these sections:\n\
             1. **What it is**: one paragraph.\n\
             2. **What it does**: behaviours and capabilities, with evidence.\n\
             3. **Risk assessment**: severity with justification; benign explanations where plausible.\n\
             4. **Indicators**: IOCs worth tracking (hashes, hosts, paths, mutexes).\n\
             5. **Next steps**: the 3–5 most valuable things a human analyst should do next, with concrete rex commands where useful.\n\n\
             <report>\n{ctx}\n</report>{note}"
        ),
        schema: None,
        max_tokens: 16_000,
    })
}

/// Explain one function's disassembly or source.
pub fn explain(llm: &dyn Llm, name: &str, listing: &str) -> Result<String> {
    let (ctx, _) = bounded(redact(listing));
    llm.complete(&Prompt {
        system: ANALYST.into(),
        user: format!(
            "Explain what `{name}` does. Give: a one-line summary, a step-by-step walkthrough referencing addresses, \
             pseudo-C for the core logic, and anything security-relevant (input handling, crypto, anti-analysis).\n\n<listing>\n{ctx}\n</listing>"
        ),
        schema: None,
        max_tokens: 16_000,
    })
}

/// A suggested function name.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct NameSuggestion {
    /// Address (hex string, as given).
    pub address: String,
    /// Suggested snake_case name.
    pub name: String,
    /// Confidence 0–1.
    pub confidence: f64,
    /// Why.
    pub rationale: String,
}

/// JSON Schema for [`NameSuggestion`] lists (structured outputs).
pub fn names_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["functions"],
        "properties": {
            "functions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["address", "name", "confidence", "rationale"],
                    "properties": {
                        "address": { "type": "string" },
                        "name": { "type": "string" },
                        "confidence": { "type": "number" },
                        "rationale": { "type": "string" }
                    }
                }
            }
        }
    })
}

/// Suggest names for unnamed functions from their listings: `(address, current name, listing)`.
pub fn name_functions(
    llm: &dyn Llm,
    funcs: &[(String, String, String)],
) -> Result<Vec<NameSuggestion>> {
    let mut body = String::new();
    for (addr, name, listing) in funcs {
        body.push_str(&format!(
            "<function address=\"{addr}\" current=\"{name}\">\n{listing}\n</function>\n"
        ));
    }
    let (ctx, _) = bounded(redact(&body));
    let text = llm.complete(&Prompt {
        system: ANALYST.into(),
        user: format!(
            "Suggest a descriptive snake_case name for each function below, as a reverse engineer would in IDA or Ghidra \
             (e.g. `parse_config`, `xor_decrypt_string`, `send_beacon`). Base names on called imports, referenced strings, \
             constants and control flow. Use confidence below 0.5 when guessing. Return one entry per function.\n\n{ctx}"
        ),
        schema: Some(names_schema()),
        max_tokens: 16_000,
    })?;
    let v: Value = serde_json::from_str(text.trim())
        .map_err(|e| Error::Other(format!("model did not return valid JSON: {e}")))?;
    serde_json::from_value(v.get("functions").cloned().unwrap_or(Value::Null))
        .map_err(|e| Error::Other(format!("unexpected JSON shape: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;
    impl Llm for Echo {
        fn describe(&self) -> String {
            "echo".into()
        }
        fn complete(&self, p: &Prompt) -> Result<String> {
            if p.schema.is_some() {
                return Ok(r#"{"functions":[{"address":"0x10","name":"check_password","confidence":0.9,"rationale":"strlen + xor loop"}]}"#.into());
            }
            Ok(p.user.clone())
        }
    }

    fn client() -> Anthropic {
        Anthropic {
            auth: Auth::ApiKey("k".into()),
            base_url: "x".into(),
            model: DEFAULT_ANTHROPIC_MODEL.into(),
            effort: "medium".into(),
            fallbacks: true,
        }
    }

    #[test]
    fn request_shape() {
        let b = client().request_body(&Prompt {
            system: "s".into(),
            user: "u".into(),
            schema: Some(names_schema()),
            max_tokens: 100,
        });
        assert_eq!(b["model"], "claude-opus-5-5");
        assert_eq!(b["output_config"]["effort"], "medium");
        assert_eq!(b["output_config"]["format"]["type"], "json_schema");
        assert_eq!(b["fallbacks"], "default");
        assert!(b.get("thinking").is_none());
        assert_eq!(b["messages"][0]["role"], "user");
    }

    #[test]
    fn response_parsing() {
        let ok = json!({"stop_reason": "end_turn", "content": [{"type": "thinking", "thinking": ""}, {"type": "text", "text": "hi"}]});
        assert_eq!(Anthropic::parse_response(&ok).unwrap(), "hi");
        let refused = json!({"stop_reason": "refusal", "content": [], "stop_details": {"type": "refusal", "category": "cyber"}});
        assert!(
            Anthropic::parse_response(&refused)
                .unwrap_err()
                .to_string()
                .contains("cyber")
        );
        let err = json!({"type": "error", "error": {"type": "authentication_error", "message": "invalid x-api-key"}});
        assert!(
            Anthropic::parse_response(&err)
                .unwrap_err()
                .to_string()
                .contains("authentication_error")
        );
    }

    #[test]
    fn tasks_redact_and_parse() {
        let key = format!("AKIA{}", "ABCDEFGHIJKLMNOP");
        let out = explain(&Echo, "f", &format!("mov rdi, \"{key}\"")).unwrap();
        assert!(!out.contains(&key) && out.contains("[REDACTED"));
        let names = name_functions(
            &Echo,
            &[("0x10".into(), "sub_10".into(), "call strlen".into())],
        )
        .unwrap();
        assert_eq!(names[0].name, "check_password");
        let r = Report::new("t", Default::default());
        assert!(summarize(&Echo, &r).unwrap().contains("<report>"));
    }
}
