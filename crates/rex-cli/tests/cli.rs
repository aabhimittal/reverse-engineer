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
