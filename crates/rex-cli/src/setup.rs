//! `rex setup`: register the rex MCP server (and a skill) with AI coding agents.
//!
//! Design rules, because this edits files the user did not write:
//! * **Never clobber.** A config that exists but is not valid JSON is left alone with an error.
//! * **Back up first.** Every modified file is copied to `<file>.rex-backup-<unix-time>`.
//! * **Idempotent.** Running twice reports "already configured" and changes nothing.
//! * **Reversible.** `--uninstall` removes exactly the `rex` entry.
//! * **Previewable.** `--dry-run` prints what would change without touching anything.

use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Skill file installed for agents that read skills (kept identical to `.agents/skills/rex/SKILL.md`).
pub const SKILL: &str = include_str!("../assets/SKILL.md");

/// Supported agents.
#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
pub enum Agent {
    /// Claude Code (via the `claude` CLI).
    ClaudeCode,
    /// Claude Desktop (`claude_desktop_config.json`).
    ClaudeDesktop,
    /// Cursor (`~/.cursor/mcp.json`).
    Cursor,
    /// Gemini CLI (`~/.gemini/settings.json`).
    Gemini,
    /// OpenAI Codex CLI (`~/.codex/config.toml`).
    Codex,
}

impl Agent {
    /// All agents in display order.
    pub const ALL: [Agent; 5] = [
        Agent::ClaudeCode,
        Agent::ClaudeDesktop,
        Agent::Cursor,
        Agent::Gemini,
        Agent::Codex,
    ];

    fn label(self) -> &'static str {
        match self {
            Agent::ClaudeCode => "Claude Code",
            Agent::ClaudeDesktop => "Claude Desktop",
            Agent::Cursor => "Cursor",
            Agent::Gemini => "Gemini CLI",
            Agent::Codex => "Codex CLI",
        }
    }
}

/// What happened for one target.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Newly configured.
    Configured(String),
    /// Already up to date.
    Already(String),
    /// Removed by `--uninstall`.
    Removed(String),
    /// Nothing to remove.
    NotPresent,
    /// Not detected or not applicable.
    Skipped(String),
    /// Dry run: what would be done.
    Would(String),
}

/// Inputs for one run.
#[derive(Clone, Debug)]
pub struct Plan {
    /// User home directory.
    pub home: PathBuf,
    /// Absolute path (or name) of the rex binary the agent should launch.
    pub command: String,
    /// Preview only.
    pub dry_run: bool,
    /// Remove instead of add.
    pub uninstall: bool,
    /// Also install the skill file.
    pub skill: bool,
}

/// Home directory from the environment.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .or_else(|| std::env::var_os("USERPROFILE").filter(|h| !h.is_empty()))
        .map(PathBuf::from)
}

/// Find an executable on `PATH`.
pub use rex_engine::which;

fn json_config_path(agent: Agent, home: &Path) -> Option<PathBuf> {
    Some(match agent {
        Agent::Cursor => home.join(".cursor/mcp.json"),
        Agent::Gemini => home.join(".gemini/settings.json"),
        Agent::ClaudeDesktop => {
            if cfg!(target_os = "macos") {
                home.join("Library/Application Support/Claude/claude_desktop_config.json")
            } else if cfg!(windows) {
                std::env::var_os("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| home.join("AppData/Roaming"))
                    .join("Claude/claude_desktop_config.json")
            } else {
                home.join(".config/Claude/claude_desktop_config.json")
            }
        }
        _ => return None,
    })
}

fn codex_path(home: &Path) -> PathBuf {
    home.join(".codex/config.toml")
}

/// Is the agent installed (its config directory exists, or its CLI is on PATH)?
pub fn detected(agent: Agent, home: &Path) -> bool {
    match agent {
        Agent::ClaudeCode => which("claude").is_some(),
        Agent::Codex => codex_path(home).parent().is_some_and(Path::is_dir),
        other => json_config_path(other, home)
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .is_some_and(|d| d.is_dir()),
    }
}

fn backup(path: &Path) -> Result<Option<PathBuf>> {
    if !path.is_file() {
        return Ok(None);
    }
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".rex-backup-{ts}"));
    let dest = path.with_file_name(name);
    std::fs::copy(path, &dest).with_context(|| format!("cannot back up {}", path.display()))?;
    Ok(Some(dest))
}

fn write_atomic(path: &Path, text: &str) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".rex-tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, text).with_context(|| format!("cannot write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("cannot replace {}", path.display()))
}

fn server_entry(command: &str) -> Value {
    json!({ "command": command, "args": ["mcp"] })
}

/// Read a JSON config, tolerating a missing or empty file but refusing invalid JSON.
fn read_json(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(json!({})),
        Ok(t) => {
            let v: Value = serde_json::from_str(&t).with_context(|| {
                format!(
                    "{} is not valid JSON; refusing to modify it (fix or remove it, then retry)",
                    path.display()
                )
            })?;
            if !v.is_object() {
                bail!(
                    "{} is not a JSON object; refusing to modify it",
                    path.display()
                );
            }
            Ok(v)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e).with_context(|| format!("cannot read {}", path.display())),
    }
}

/// Add or remove `mcpServers.rex` in a JSON config.
pub fn edit_json(path: &Path, plan: &Plan) -> Result<Outcome> {
    let mut v = read_json(path)?;
    let servers = v
        .as_object_mut()
        .expect("object")
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(servers) = servers.as_object_mut() else {
        bail!(
            "{}: `mcpServers` is not an object; refusing to modify it",
            path.display()
        );
    };
    let wanted = server_entry(&plan.command);
    if plan.uninstall {
        if servers.remove("rex").is_none() {
            return Ok(Outcome::NotPresent);
        }
        if plan.dry_run {
            return Ok(Outcome::Would(format!(
                "remove `rex` from {}",
                path.display()
            )));
        }
        backup(path)?;
        write_atomic(path, &(serde_json::to_string_pretty(&v)? + "\n"))?;
        return Ok(Outcome::Removed(path.display().to_string()));
    }
    if servers.get("rex") == Some(&wanted) {
        return Ok(Outcome::Already(path.display().to_string()));
    }
    servers.insert("rex".into(), wanted);
    if plan.dry_run {
        return Ok(Outcome::Would(format!("add `rex` to {}", path.display())));
    }
    backup(path)?;
    write_atomic(path, &(serde_json::to_string_pretty(&v)? + "\n"))?;
    Ok(Outcome::Configured(path.display().to_string()))
}

fn toml_quote(s: &str) -> String {
    if !s.contains('\'') && !s.contains('\n') {
        format!("'{s}'") // literal string: backslashes need no escaping (Windows paths)
    } else {
        format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
    }
}

const TOML_HEADER: &str = "[mcp_servers.rex]";

/// Does the TOML text already define `[mcp_servers.rex]`?
pub fn toml_has_rex(text: &str) -> bool {
    text.lines().any(|l| l.trim() == TOML_HEADER)
}

/// Append the rex server block.
pub fn toml_add(text: &str, command: &str) -> String {
    let mut out = text.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "{TOML_HEADER}\ncommand = {}\nargs = [\"mcp\"]\n",
        toml_quote(command)
    ));
    out
}

/// Remove the `[mcp_servers.rex]` table (up to the next table header or end of file).
pub fn toml_remove(text: &str) -> String {
    let mut out = Vec::new();
    let mut skipping = false;
    for line in text.lines() {
        let t = line.trim();
        if t == TOML_HEADER {
            skipping = true;
            continue;
        }
        if skipping && t.starts_with('[') {
            skipping = false;
        }
        if !skipping {
            out.push(line);
        }
    }
    let mut s = out.join("\n").trim_end().to_string();
    if !s.is_empty() {
        s.push('\n');
    }
    s
}

/// Add or remove the rex table in Codex's `config.toml`.
pub fn edit_codex(path: &Path, plan: &Plan) -> Result<Outcome> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
    };
    let has = toml_has_rex(&text);
    let new = if plan.uninstall {
        if !has {
            return Ok(Outcome::NotPresent);
        }
        toml_remove(&text)
    } else {
        if has {
            // Keep the user's block untouched even if the command differs; they may have customised it.
            return Ok(Outcome::Already(path.display().to_string()));
        }
        toml_add(&text, &plan.command)
    };
    if plan.dry_run {
        return Ok(Outcome::Would(format!(
            "{} `rex` in {}",
            if plan.uninstall { "remove" } else { "add" },
            path.display()
        )));
    }
    backup(path)?;
    write_atomic(path, &new)?;
    Ok(if plan.uninstall {
        Outcome::Removed(path.display().to_string())
    } else {
        Outcome::Configured(path.display().to_string())
    })
}

/// Register with Claude Code through its own CLI (it owns its config format).
pub fn edit_claude_code(plan: &Plan) -> Result<Outcome> {
    let Some(claude) = which("claude") else {
        return Ok(Outcome::Skipped("`claude` CLI not found on PATH".into()));
    };
    let args: Vec<&str> = if plan.uninstall {
        vec!["mcp", "remove", "--scope", "user", "rex"]
    } else {
        vec![
            "mcp",
            "add",
            "--scope",
            "user",
            "rex",
            "--",
            &plan.command,
            "mcp",
        ]
    };
    let shown = format!("claude {}", args.join(" "));
    if !plan.uninstall {
        let list = Command::new(&claude)
            .args(["mcp", "list"])
            .output()
            .context("cannot run `claude mcp list`")?;
        if String::from_utf8_lossy(&list.stdout)
            .lines()
            .any(|l| l.trim_start().starts_with("rex:"))
        {
            return Ok(Outcome::Already("claude mcp list".into()));
        }
    }
    if plan.dry_run {
        return Ok(Outcome::Would(shown));
    }
    let out = Command::new(&claude)
        .args(&args)
        .output()
        .with_context(|| format!("cannot run `{shown}`"))?;
    if !out.status.success() {
        let msg = String::from_utf8_lossy(&out.stderr);
        if plan.uninstall && (msg.contains("No MCP server found") || msg.contains("not found")) {
            return Ok(Outcome::NotPresent);
        }
        bail!("`{shown}` failed: {}", msg.trim());
    }
    Ok(if plan.uninstall {
        Outcome::Removed("claude mcp".into())
    } else {
        Outcome::Configured(shown)
    })
}

/// Install or remove the skill file under `<home>/<dir>/rex/SKILL.md`.
pub fn edit_skill(home: &Path, dir: &str, plan: &Plan) -> Result<Outcome> {
    let path = home.join(dir).join("rex/SKILL.md");
    if plan.uninstall {
        if !path.is_file() {
            return Ok(Outcome::NotPresent);
        }
        if plan.dry_run {
            return Ok(Outcome::Would(format!("remove {}", path.display())));
        }
        std::fs::remove_file(&path)?;
        return Ok(Outcome::Removed(path.display().to_string()));
    }
    if std::fs::read_to_string(&path).is_ok_and(|t| t == SKILL) {
        return Ok(Outcome::Already(path.display().to_string()));
    }
    if plan.dry_run {
        return Ok(Outcome::Would(format!("write {}", path.display())));
    }
    backup(&path)?;
    write_atomic(&path, SKILL)?;
    Ok(Outcome::Configured(path.display().to_string()))
}

/// Run setup for the chosen agents; returns `(label, result)` rows.
pub fn run(plan: &Plan, agents: &[Agent], force_all: bool) -> Vec<(String, Result<Outcome>)> {
    let mut rows = Vec::new();
    for &agent in agents {
        let name = agent.label().to_string();
        if !force_all && !detected(agent, &plan.home) {
            rows.push((
                name,
                Ok(Outcome::Skipped(
                    "not detected (use --agent to force)".into(),
                )),
            ));
            continue;
        }
        let r = match agent {
            Agent::ClaudeCode => edit_claude_code(plan),
            Agent::Codex => edit_codex(&codex_path(&plan.home), plan),
            other => edit_json(
                &json_config_path(other, &plan.home).expect("json agent"),
                plan,
            ),
        };
        let ok = r.is_ok();
        rows.push((name.clone(), r));
        if plan.skill && ok {
            let dir = if agent == Agent::ClaudeCode {
                Some(".claude/skills")
            } else if matches!(agent, Agent::Cursor | Agent::Gemini | Agent::Codex) {
                Some(".agents/skills")
            } else {
                None
            };
            if let Some(dir) = dir {
                rows.push((format!("{name} skill"), edit_skill(&plan.home, dir, plan)));
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(home: &Path) -> Plan {
        Plan {
            home: home.to_path_buf(),
            command: "/opt/rex/rex".into(),
            dry_run: false,
            uninstall: false,
            skill: true,
        }
    }

    #[test]
    fn json_roundtrip_preserves_other_servers_and_backs_up() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".cursor/mcp.json");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(
            &p,
            r#"{"mcpServers":{"other":{"command":"x"}},"theme":"dark"}"#,
        )
        .unwrap();
        let pl = plan(d.path());
        assert!(matches!(
            edit_json(&p, &pl).unwrap(),
            Outcome::Configured(_)
        ));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(v["mcpServers"]["rex"]["args"], json!(["mcp"]));
        assert_eq!(v["mcpServers"]["other"]["command"], "x");
        assert_eq!(v["theme"], "dark");
        let backups = std::fs::read_dir(p.parent().unwrap())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("rex-backup"))
            .count();
        assert_eq!(backups, 1);
        assert!(
            matches!(edit_json(&p, &pl).unwrap(), Outcome::Already(_)),
            "idempotent"
        );
        let un = Plan {
            uninstall: true,
            ..pl
        };
        assert!(matches!(edit_json(&p, &un).unwrap(), Outcome::Removed(_)));
        let v: Value = serde_json::from_str(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert!(v["mcpServers"].get("rex").is_none() && v["mcpServers"]["other"].is_object());
        assert_eq!(edit_json(&p, &un).unwrap(), Outcome::NotPresent);
    }

    #[test]
    fn refuses_invalid_json_and_dry_run_writes_nothing() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.json");
        std::fs::write(&p, "{ not json").unwrap();
        let err = edit_json(&p, &plan(d.path())).unwrap_err().to_string();
        assert!(err.contains("not valid JSON"), "{err}");
        assert_eq!(
            std::fs::read_to_string(&p).unwrap(),
            "{ not json",
            "left untouched"
        );
        let q = d.path().join("new.json");
        let dry = Plan {
            dry_run: true,
            ..plan(d.path())
        };
        assert!(matches!(edit_json(&q, &dry).unwrap(), Outcome::Would(_)));
        assert!(!q.exists());
        // A missing file is created.
        assert!(matches!(
            edit_json(&q, &plan(d.path())).unwrap(),
            Outcome::Configured(_)
        ));
        assert!(q.is_file());
    }

    #[test]
    fn toml_add_remove_keeps_neighbours() {
        let base = "model = \"gpt\"\n\n[mcp_servers.other]\ncommand = \"o\"\n";
        let added = toml_add(base, r"C:\tools\rex.exe");
        assert!(added.contains("command = 'C:\\tools\\rex.exe'"));
        assert!(toml_has_rex(&added));
        let removed = toml_remove(&added);
        assert_eq!(removed, base);
        let mid = format!(
            "{}\n[mcp_servers.after]\ncommand = \"a\"\n",
            toml_add("", "/x/rex")
        );
        assert_eq!(toml_remove(&mid), "[mcp_servers.after]\ncommand = \"a\"\n");
        assert_eq!(toml_quote("it's"), "\"it's\"");
    }

    #[test]
    fn codex_and_skill() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join(".codex/config.toml");
        let pl = plan(d.path());
        assert!(matches!(
            edit_codex(&p, &pl).unwrap(),
            Outcome::Configured(_)
        ));
        assert!(matches!(edit_codex(&p, &pl).unwrap(), Outcome::Already(_)));
        assert!(matches!(
            edit_skill(d.path(), ".agents/skills", &pl).unwrap(),
            Outcome::Configured(_)
        ));
        assert!(matches!(
            edit_skill(d.path(), ".agents/skills", &pl).unwrap(),
            Outcome::Already(_)
        ));
        let un = Plan {
            uninstall: true,
            ..pl
        };
        assert!(matches!(
            edit_skill(d.path(), ".agents/skills", &un).unwrap(),
            Outcome::Removed(_)
        ));
        assert!(matches!(edit_codex(&p, &un).unwrap(), Outcome::Removed(_)));
    }

    #[test]
    fn embedded_skill_matches_repo_copy() {
        let repo = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.agents/skills/rex/SKILL.md"),
        )
        .unwrap();
        assert_eq!(
            repo, SKILL,
            "keep crates/rex-cli/assets/SKILL.md and .agents/skills/rex/SKILL.md identical"
        );
        assert!(SKILL.starts_with("---\nname: rex\n"));
    }
}
