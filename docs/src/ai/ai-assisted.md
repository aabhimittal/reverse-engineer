# AI-assisted reverse engineering and MCP

## What a model is good at, and what it is not

Static analysis tells you **what is there**. A language model helps with the next step,
**what it probably means**: naming `sub_401a20` as `parse_config`, or turning 40 findings
into a short briefing. It is not a source of facts. Treat output as hypotheses to check
against the evidence in the report.

## Privacy model

- AI is **opt-in**: nothing is sent unless you pass `--ai` or run `rex ai ...`.
- Secrets detected in the content are **redacted** before sending.
- `--ai-provider ollama` keeps everything on your machine.

## Commands

```sh
export ANTHROPIC_API_KEY=...                 # or use a local model: --ai-provider ollama
rex analyze sample.bin --ai                  # adds an "AI briefing" section
rex ai explain labs/build/crackme -F check_password
rex ai name labs/build/crackme.stripped      # suggested names for sub_* functions
```

Defaults: `claude-opus-5-5` with an explicit `effort` (`REX_AI_EFFORT`, default `medium`),
structured outputs for naming, refusal handling, and the API's server-side fallback so that
legitimate security work isn't dropped by a false-positive classifier.

## rex as an MCP server

The Model Context Protocol lets agents call tools. `rex mcp` serves eleven of them
(`rex_analyze`, `rex_disasm`, `rex_xrefs`, `rex_har_to_openapi`, `rex_code_map`, …) over stdio:

```json
{ "mcpServers": { "rex": { "command": "rex", "args": ["mcp"] } } }
```

Tool output is Markdown and capped at 60 000 characters so agents keep their context.

## Exercises

1. Compare an AI-suggested function name with the one you derived by hand. Which evidence did the model use?
2. Add a tool to `crates/rex-mcp/src/lib.rs` that exposes `rex_callgraph`.
