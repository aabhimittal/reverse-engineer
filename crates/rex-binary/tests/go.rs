//! Go binaries, built on the fly with the local Go toolchain (Go binaries are megabytes, too big
//! to commit as fixtures). Without `go` on PATH the tests skip, unless `REX_REQUIRE_GO` is set,
//! which CI does so a missing toolchain fails loudly instead of silently testing nothing.

use rex_binary::{Binary, functions, model::MitigationStatus};
use std::path::{Path, PathBuf};
use std::process::Command;

const SRC: &str = r#"package main

import "os"

//go:noinline
func check(pw string) bool { return pw == "open-sesame" }

func main() {
	if len(os.Args) > 1 && check(os.Args[1]) {
		println("granted")
	}
}
"#;

fn build(dir: &Path, goos: &str, goarch: &str) -> Option<PathBuf> {
    if Command::new("go").arg("version").output().is_err() {
        assert!(
            std::env::var_os("REX_REQUIRE_GO").is_none(),
            "REX_REQUIRE_GO is set but `go` is not on PATH"
        );
        eprintln!("skipping: no Go toolchain");
        return None;
    }
    std::fs::write(dir.join("main.go"), SRC).unwrap();
    std::fs::write(dir.join("go.mod"), "module example.com/rexgo\n\ngo 1.21\n").unwrap();
    let out = dir.join(format!("hello-{goos}-{goarch}"));
    let st = Command::new("go")
        .args(["build", "-trimpath", "-ldflags=-s -w", "-o"])
        .arg(&out)
        .arg(".")
        .current_dir(dir)
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .env("CGO_ENABLED", "0")
        .env("GOFLAGS", "-mod=mod")
        .env("GOCACHE", dir.join("cache"))
        .status()
        .unwrap();
    assert!(st.success());
    Some(out)
}

#[test]
fn stripped_go_binaries_are_named_from_the_pclntab() {
    let d = tempfile::tempdir().unwrap();
    for (os, arch) in [
        ("linux", "amd64"),
        ("linux", "arm64"),
        ("windows", "amd64"),
        ("darwin", "arm64"),
        ("linux", "riscv64"),
    ] {
        let Some(p) = build(d.path(), os, arch) else {
            return;
        };
        let data = std::fs::read(&p).unwrap();
        let b = Binary::parse(&data).unwrap();
        let go =
            b.go.as_ref()
                .unwrap_or_else(|| panic!("{os}/{arch}: not recognised as Go"));
        assert!(go.go_version.starts_with("go1."), "{os}/{arch}: {go:?}");
        assert_eq!(go.path.as_deref(), Some("example.com/rexgo"));
        assert!(
            go.settings.iter().any(|(k, v)| k == "GOARCH" && v == arch),
            "{go:?}"
        );
        let names: Vec<&str> = b.symbols.iter().map(|s| s.name.as_str()).collect();
        assert!(
            names.contains(&"main.main") && names.contains(&"main.check"),
            "{os}/{arch}"
        );
        assert!(
            names.len() > 1000,
            "{os}/{arch}: only {} names",
            names.len()
        );
        let fortify = b.mitigations.iter().find(|m| m.name == "FORTIFY_SOURCE");
        assert!(fortify.is_none_or(|m| m.status == MitigationStatus::Unknown));
        if arch == "riscv64" {
            continue; // names only: no CFG recovery for RISC-V
        }
        if !cfg!(feature = "multiarch") && arch != "amd64" {
            continue;
        }
        // Even with a small function budget, the program's own code is recovered first.
        let opts = rex_core::AnalysisOptions {
            max_functions: 200,
            ..Default::default()
        };
        let prog = functions::analyze(&b, &data, &opts);
        for want in ["main.main", "main.check"] {
            assert!(
                prog.functions.values().any(|f| f.name == want),
                "{os}/{arch}: {want} not recovered within 200 functions"
            );
        }
    }
}
