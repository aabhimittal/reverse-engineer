//! The Ghidra bridge against a real Ghidra. Skipped when Ghidra is not installed, unless
//! `REX_REQUIRE_GHIDRA` is set (CI's `ghidra` job sets it, so the test never silently skips there).

use assert_cmd::Command;
use std::path::PathBuf;

#[test]
fn decompiles_a_function_with_real_ghidra() {
    let found = rex_engine::ghidra::locate(&|k| std::env::var(k).ok(), &rex_engine::which);
    if found.is_none() {
        assert!(
            std::env::var_os("REX_REQUIRE_GHIDRA").is_none(),
            "REX_REQUIRE_GHIDRA is set but Ghidra was not found (set GHIDRA_INSTALL_DIR)"
        );
        eprintln!("skipping: Ghidra is not installed");
        return;
    }
    let fixture =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../rex-binary/tests/fixtures/crackme.elf");
    let out = Command::cargo_bin("rex")
        .unwrap()
        .env("NO_COLOR", "1")
        .args(["decompile", "--timeout", "900"])
        .arg(&fixture)
        .arg("check_password")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // PIE: Ghidra loads it at 0x100000, rex addresses it from 0; the script maps between them.
    assert!(stdout.contains("check_password @ 0x"), "{stdout}");
    assert!(stdout.contains("strlen"), "{stdout}");
}
