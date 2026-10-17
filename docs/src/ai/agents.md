# Use rex from your AI coding agent

`rex` is built so an agent can drive it: every verb is also an MCP tool, and the output is Markdown
sized to fit a context window. The shortest path:

```sh
rex setup            # detects Claude Code, Claude Desktop, Cursor, Gemini CLI and Codex CLI; configures each
rex setup --dry-run  # show what would change, touch nothing
rex setup --uninstall
rex doctor           # what this build and machine can do; which companion tools are present
```

Then ask your agent something like *"triage ./app.asar"* or *"what changed between these two builds?"*.

## What `rex setup` changes

| Agent | Edit |
|---|---|
| Claude Code | runs `claude mcp add --scope user rex -- <rex> mcp` and writes `~/.claude/skills/rex/SKILL.md` |
| Claude Desktop | adds `mcpServers.rex` to its JSON config |
| Cursor | adds `mcpServers.rex` to `~/.cursor/mcp.json` |
| Gemini CLI | adds `mcpServers.rex` to `~/.gemini/settings.json` |
| Codex CLI | adds `[mcp_servers.rex]` to `~/.codex/config.toml` |

Safety properties, all covered by tests: it only configures agents it detects (or the ones you name with
`--agent`), it is idempotent, it refuses to overwrite a config file it cannot parse, it preserves your
other servers and settings, and `--uninstall` removes only the `rex` entry.

## Tools and workflows

The MCP server exposes `rex_analyze`, `rex_checksec`, `rex_strings`, `rex_functions`, `rex_disasm`,
`rex_cfg`, `rex_xrefs`, `rex_diff`, `rex_carve`, `rex_core`, `rex_har_to_openapi` and
`rex_code_map`. It also publishes **prompts**, which are reusable plans for combining them. Clients that support MCP prompts
show them as slash-style commands:

| Prompt | Does |
|---|---|
| `triage_binary` | analyze → functions → xrefs → disasm, then a sourced report |
| `patch_diff` | diff two builds, read the small surgical changes, hypothesise the fix |
| `reverse_api` | HAR → OpenAPI plus a traffic security review |
| `map_codebase` | atlas of an unfamiliar repository with a reading order |
| `audit_apk` | manifest, components, permissions, risky APIs |
| `audit_electron` | window security, IPC surface, secrets, dependencies |

## Trust boundaries

- rex never executes the file it analyses and makes no network calls on its own.
- Secrets found in inputs are masked in every report an agent sees.
- The agent, not rex, decides what to do with the output. Findings are leads: ask it to cite evidence.
- The MCP server runs with your user's permissions and reads whatever path the agent passes. Use your
  agent's permission prompts for file access as you would for any tool.
