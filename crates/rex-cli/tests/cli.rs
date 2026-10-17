//! End-to-end tests of the `rex` binary.

use assert_cmd::Command;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn fx(name: &str) -> PathBuf {
    root().join("crates/rex-binary/tests/fixtures").join(name)
}

fn rex() -> Command {
    let mut c = Command::cargo_bin("rex").unwrap();
    c.env("NO_COLOR", "1")
        .env_remove("ANTHROPIC_API_KEY")
        .env_remove("ANTHROPIC_AUTH_TOKEN");
    c
}

fn stdout(c: &mut Command) -> String {
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn analyze_json_is_machine_readable() {
    let s = stdout(rex().args(["analyze", "-f", "json"]).arg(fx("crackme.elf")));
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v[0]["schema_version"], 1);
    assert_eq!(v[0]["artifact"]["kind"], "elf");
    assert!(
        v[0]["sections"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s["id"] == "binary.functions")
    );
}

#[test]
fn fail_on_gates_ci() {
    let out = rex()
        .args(["analyze", "--fail-on", "high"])
        .arg(fx("vuln.elf"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let out = rex()
        .args(["analyze", "--fail-on", "critical"])
        .arg(fx("crackme.elf"))
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn output_format_from_extension() {
    let d = tempfile::tempdir().unwrap();
    for ext in ["html", "md", "sarif", "json"] {
        let p = d.path().join(format!("r.{ext}"));
        rex()
            .arg("analyze")
            .arg(fx("sample.exe"))
            .arg("-o")
            .arg(&p)
            .assert()
            .success();
        let body = std::fs::read_to_string(&p).unwrap();
        match ext {
            "html" => assert!(body.starts_with("<!doctype html>")),
            "md" => assert!(body.starts_with("# rex analysis")),
            "sarif" => assert!(body.contains("\"version\": \"2.1.0\"")),
            _ => assert!(body.trim_start().starts_with('[')),
        }
    }
}

#[test]
fn binary_subcommands() {
    assert!(
        stdout(
            rex()
                .arg("disasm")
                .arg(fx("crackme.elf"))
                .args(["-F", "check_password"])
        )
        .contains("call strlen@plt")
    );
    assert!(
        stdout(
            rex()
                .arg("cfg")
                .arg(fx("crackme.elf"))
                .args(["check_password", "--dot"])
        )
        .starts_with("digraph")
    );
    assert!(stdout(rex().arg("callgraph").arg(fx("crackme.stripped.elf"))).contains("flowchart"));
    assert!(stdout(rex().arg("xrefs").arg(fx("vuln.elf")).arg("gets")).contains("main"));
    assert!(stdout(rex().arg("functions").arg(fx("hello.macho"))).contains("_verify"));
    assert!(
        stdout(
            rex()
                .arg("strings")
                .arg(fx("sample.exe"))
                .args(["-c", "url"])
        )
        .contains("gate.php")
    );
    assert!(
        stdout(
            rex()
                .arg("checksec")
                .arg(fx("vuln.elf"))
                .arg(fx("sample.exe"))
        )
        .contains("PE mitigations")
    );
    assert!(
        stdout(
            rex()
                .arg("diff")
                .arg(fx("crackme.elf"))
                .arg(fx("crackme.stripped.elf"))
        )
        .contains("Identical")
    );
    assert!(stdout(rex().arg("info").arg(fx("sample.exe"))).contains("imphash"));
}

#[test]
fn core_dump_triage() {
    let s = stdout(rex().arg("core").arg(fx("core_x64.elf")));
    assert!(s.contains("SIGSEGV") && s.contains("SEGV_MAPERR"), "{s}");
    assert!(
        s.contains("crashme+0x1139") && s.contains("BIN-CORE-NULL-DEREF"),
        "{s}"
    );
    let v: serde_json::Value = serde_json::from_str(&stdout(
        rex().args(["core", "-f", "json"]).arg(fx("core_a64.elf")),
    ))
    .unwrap();
    assert_eq!(v[0]["sections"][0]["id"], "binary.core");
    assert_eq!(v[0]["sections"][0]["data"]["fault_addr"], 0x10);
    assert!(
        v[0]["findings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["id"] == "BIN-CORE-CRASH")
    );
    // Code-level verbs refuse a core instead of analysing memory as a program.
    let out = rex()
        .arg("functions")
        .arg(fx("core_x64.elf"))
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("rex core"));
    let out = rex().arg("core").arg(fx("vuln.elf")).output().unwrap();
    assert!(!out.status.success());
}

#[test]
fn web_and_code_subcommands() {
    let d = tempfile::tempdir().unwrap();
    let spec = d.path().join("api.yaml");
    rex()
        .args(["web", "har2openapi"])
        .arg(root().join("labs/web/sample.har"))
        .arg("-o")
        .arg(&spec)
        .assert()
        .success();
    assert!(
        std::fs::read_to_string(&spec)
            .unwrap()
            .contains("/api/v1/products/{productId}:")
    );
    let src = d.path().join("src");
    rex()
        .args(["web", "sourcemap"])
        .arg(root().join("labs/web/bundle/app.min.js"))
        .arg("-d")
        .arg(&src)
        .assert()
        .success();
    assert!(src.join("src/api/client.ts").exists());
    assert!(
        stdout(rex().arg("apk").arg(root().join("labs/android/rexlab.apk")))
            .contains("APK-DEBUGGABLE")
    );
    let atlas = d.path().join("ATLAS.md");
    rex()
        .args(["code", "map"])
        .arg(root().join("crates/rex-core"))
        .arg("-o")
        .arg(&atlas)
        .assert()
        .success();
    assert!(
        std::fs::read_to_string(&atlas)
            .unwrap()
            .contains("## Where to start reading")
    );
}

#[test]
fn errors_are_friendly() {
    let out = rex().args(["disasm", "/no/such/file"]).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot load"));
    let out = rex()
        .arg("disasm")
        .arg(root().join("labs/web/sample.har"))
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("not an ELF/PE/Mach-O"));
    let out = rex()
        .args(["analyze", "--ai"])
        .arg(fx("crackme.elf"))
        .output()
        .unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("ANTHROPIC_API_KEY"),
        "AI needs explicit credentials"
    );
}

#[test]
fn mcp_over_stdio() {
    let input = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n"
    );
    let s = stdout(rex().arg("mcp").write_stdin(input));
    let lines: Vec<serde_json::Value> = s
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["result"]["serverInfo"]["name"], "rex");
    assert!(lines[1]["result"]["tools"].as_array().unwrap().len() >= 10);
}

#[test]
fn completions_generate() {
    assert!(stdout(rex().args(["completions", "bash"])).contains("rex"));
}

// ───────────────────────── rex setup / doctor ─────────────────────────

/// A rex command with an isolated HOME and a PATH that contains no real agent CLIs.
fn rex_home(home: &std::path::Path, path_dir: &std::path::Path) -> Command {
    let mut c = rex();
    c.env("HOME", home)
        .env("USERPROFILE", home)
        .env("APPDATA", home.join("AppData/Roaming"))
        .env("PATH", path_dir);
    c
}

#[test]
fn setup_configures_detected_agents_idempotently_and_uninstalls() {
    let home = tempfile::tempdir().unwrap();
    let empty_path = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    std::fs::create_dir_all(home.path().join(".codex")).unwrap();
    std::fs::write(
        home.path().join(".cursor/mcp.json"),
        r#"{"mcpServers":{"keep":{"command":"k"}}}"#,
    )
    .unwrap();

    // Dry run changes nothing.
    let out = stdout(rex_home(home.path(), empty_path.path()).args([
        "setup",
        "--dry-run",
        "--command",
        "/opt/rex",
    ]));
    assert!(out.contains("Cursor: would add"), "{out}");
    assert!(
        !std::fs::read_to_string(home.path().join(".cursor/mcp.json"))
            .unwrap()
            .contains("\"rex\"")
    );

    let out =
        stdout(rex_home(home.path(), empty_path.path()).args(["setup", "--command", "/opt/rex"]));
    assert!(
        out.contains("Cursor: configured") && out.contains("Codex CLI: configured"),
        "{out}"
    );
    assert!(
        out.contains("Claude Code: skipped") && out.contains("Gemini CLI: skipped"),
        "undetected agents are skipped: {out}"
    );
    let cursor: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(home.path().join(".cursor/mcp.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(cursor["mcpServers"]["rex"]["command"], "/opt/rex");
    assert_eq!(
        cursor["mcpServers"]["keep"]["command"], "k",
        "other servers preserved"
    );
    assert!(
        std::fs::read_to_string(home.path().join(".codex/config.toml"))
            .unwrap()
            .contains("[mcp_servers.rex]")
    );
    assert!(home.path().join(".agents/skills/rex/SKILL.md").is_file());

    let again =
        stdout(rex_home(home.path(), empty_path.path()).args(["setup", "--command", "/opt/rex"]));
    assert!(again.contains("Cursor: already configured"), "{again}");

    let un = stdout(rex_home(home.path(), empty_path.path()).args(["setup", "--uninstall"]));
    assert!(
        un.contains("Cursor: removed") && un.contains("Codex CLI: removed"),
        "{un}"
    );
    assert!(
        !std::fs::read_to_string(home.path().join(".cursor/mcp.json"))
            .unwrap()
            .contains("\"rex\"")
    );
    assert!(!home.path().join(".agents/skills/rex/SKILL.md").exists());
}

#[test]
fn setup_refuses_to_clobber_invalid_config() {
    let home = tempfile::tempdir().unwrap();
    let empty_path = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(home.path().join(".gemini")).unwrap();
    std::fs::write(
        home.path().join(".gemini/settings.json"),
        "{ // user comments, not JSON",
    )
    .unwrap();
    let out = rex_home(home.path(), empty_path.path())
        .args(["setup", "-a", "gemini", "--command", "/opt/rex"])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stdout).contains("refusing to modify"));
    assert_eq!(
        std::fs::read_to_string(home.path().join(".gemini/settings.json")).unwrap(),
        "{ // user comments, not JSON"
    );
}

#[cfg(unix)]
#[test]
fn setup_drives_the_claude_cli() {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::tempdir().unwrap();
    let bin = tempfile::tempdir().unwrap();
    let log = home.path().join("claude.log");
    let stub = bin.path().join("claude");
    // Stub: `mcp list` prints nothing; every call is logged.
    std::fs::write(
        &stub,
        format!("#!/bin/sh\necho \"$@\" >> '{}'\nexit 0\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
    let out = stdout(rex_home(home.path(), bin.path()).args([
        "setup",
        "-a",
        "claude-code",
        "--command",
        "/opt/rex",
    ]));
    assert!(out.contains("Claude Code: configured"), "{out}");
    let calls = std::fs::read_to_string(&log).unwrap();
    assert!(
        calls.contains("mcp add --scope user rex -- /opt/rex mcp"),
        "{calls}"
    );
    assert!(home.path().join(".claude/skills/rex/SKILL.md").is_file());
}

#[test]
fn doctor_reports_without_running_anything() {
    let empty = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let out = stdout(rex_home(home.path(), empty.path()).arg("doctor"));
    assert!(
        out.contains("This build")
            && out.contains("Companion tools")
            && out.contains("✘ not found"),
        "{out}"
    );
}

#[test]
fn analyzes_wasm_and_electron_labs_and_gates_on_severity() {
    let s = stdout(
        rex()
            .args(["analyze", "-f", "json"])
            .arg(root().join("labs/wasm/sample.wasm")),
    );
    let v: serde_json::Value = serde_json::from_str(&s).unwrap();
    assert_eq!(v[0]["artifact"]["kind"], "wasm");

    let asar = root().join("labs/electron/app.asar");
    let out = rex()
        .args(["analyze", "--fail-on", "high"])
        .arg(&asar)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3), "high findings must gate CI");
    assert!(String::from_utf8_lossy(&out.stdout).contains("ELECTRON-NODE-INTEGRATION"));
}

#[test]
fn web_asar_extracts_and_refuses_other_inputs() {
    let tmp = tempfile::tempdir().unwrap();
    let dest = tmp.path().join("out");
    stdout(
        rex()
            .args(["web", "asar"])
            .arg(root().join("labs/electron/app.asar"))
            .arg("-d")
            .arg(&dest),
    );
    assert!(dest.join("main.js").is_file() && dest.join("renderer/index.html").is_file());
    rex()
        .args(["web", "asar"])
        .arg(fx("crackme.elf"))
        .arg("-d")
        .arg(tmp.path().join("nope"))
        .assert()
        .failure();
}

#[test]
fn compare_reports_gates_on_regressions() {
    let d = tempfile::tempdir().unwrap();
    let save = |name: &str| {
        let p = d.path().join(format!("{name}.json"));
        let s = stdout(rex().args(["analyze", "-f", "json"]).arg(fx(name)));
        std::fs::write(&p, s).unwrap();
        p
    };
    let (good, bad) = (save("crackme.elf"), save("vuln.elf"));
    // Same report twice: nothing changed, nothing to fail on.
    let same = stdout(
        rex()
            .args(["compare", "--fail-on", "low"])
            .arg(&good)
            .arg(&good),
    );
    assert!(same.contains("no findings"), "{same}");
    // Hardened → unhardened: NX/PIE/RELRO regressions are new high/medium findings.
    let out = rex()
        .args(["compare", "-f", "json", "--fail-on", "high"])
        .arg(&good)
        .arg(&bad)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let ids: Vec<&str> = v[0]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    assert!(ids.contains(&"COMPARE-NEW-BIN-MITIGATION-NX"), "{ids:?}");
    // Garbage in is a clean error.
    let junk = d.path().join("junk.json");
    std::fs::write(&junk, "not json").unwrap();
    let e = rex().arg("compare").arg(&junk).arg(&good).output().unwrap();
    assert_eq!(e.status.code(), Some(1));
}
