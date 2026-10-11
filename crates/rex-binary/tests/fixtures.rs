//! Integration tests against real executables built from `labs/` sources
//! (see `scripts/build-fixtures.sh`).

use rex_binary::functions;
use rex_binary::model::{Arch, BinFormat, MitigationStatus};
use rex_binary::{Binary, capabilities, diff, fingerprint, strings};
use rex_core::{AnalysisOptions, Artifact, ArtifactKind, Registry, Severity};
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

fn mitigation(b: &Binary, name: &str) -> MitigationStatus {
    b.mitigations
        .iter()
        .find(|m| m.name == name)
        .unwrap_or_else(|| panic!("no {name}"))
        .status
}

fn report(name: &str) -> rex_core::Report {
    let a = Artifact::from_bytes(name, fixture(name));
    let mut r = Registry::new();
    rex_binary::register(&mut r);
    r.run(&a, &AnalysisOptions::default(), &[])
}

#[test]
fn elf_hardened_crackme() {
    let data = fixture("crackme.elf");
    let b = Binary::parse(&data).unwrap();
    assert_eq!(b.format, BinFormat::Elf);
    assert_eq!(b.arch, Arch::X86_64);
    assert_eq!(b.file_type, "PIE executable");
    assert_eq!(mitigation(&b, "NX"), MitigationStatus::Enabled);
    assert_eq!(mitigation(&b, "PIE"), MitigationStatus::Enabled);
    assert_eq!(mitigation(&b, "RELRO"), MitigationStatus::Enabled);
    assert_eq!(mitigation(&b, "FORTIFY_SOURCE"), MitigationStatus::Enabled);
    assert!(
        b.imports
            .iter()
            .any(|i| i.name == "strlen" && i.slot.is_some())
    );

    let prog = functions::analyze(&b, &data, &AnalysisOptions::default());
    let main = prog.find("main").expect("main");
    let check = prog.find("check_password").expect("check_password");
    assert!(main.calls.contains(&check.addr), "main → check_password");
    assert!(main.imports_called.contains(&"puts".to_string()));
    assert!(check.imports_called.contains(&"strlen".to_string()));
    assert!(check.blocks.len() >= 3, "loop + early returns");
    assert!(check.cyclomatic() >= 3);
    // XOR-encoded secret is referenced by the checker.
    assert!(
        check.strings.iter().any(|s| s == "1,3&10&z"),
        "{:?}",
        check.strings
    );
    assert!(main.strings.iter().any(|s| s.contains("crackme")));
    assert!(prog.stubs.values().any(|n| n == "puts"));
    // CFG renderers produce something sensible.
    assert!(functions::cfg_dot(check).contains("->"));
    assert!(functions::cfg_mermaid(check, 4).starts_with("flowchart TD"));
    assert!(functions::callgraph_mermaid(&prog, main.addr, 10).contains("check_password"));
    let listing = functions::function_listing(&prog, check);
    assert!(listing.contains("call strlen@plt"), "{listing}");
}

#[test]
fn elf_stripped_main_is_inferred() {
    let full = fixture("crackme.elf");
    let stripped = fixture("crackme.stripped.elf");
    let bf = Binary::parse(&full).unwrap();
    let bs = Binary::parse(&stripped).unwrap();
    assert!(bs.stripped && !bf.stripped);
    let pf = functions::analyze(&bf, &full, &AnalysisOptions::default());
    let ps = functions::analyze(&bs, &stripped, &AnalysisOptions::default());
    assert_eq!(ps.main, Some(pf.find("main").unwrap().addr));
    // check_password is still discovered via the call from main.
    let check = pf.find("check_password").unwrap().addr;
    assert!(ps.functions.contains_key(&check));
    assert!(ps.functions[&check].name.starts_with("sub_"));

    // ...and diffing recovers its identity by instruction hash.
    let d = diff::diff((&bf, &pf, &[]), (&bs, &ps, &[]));
    let row = d
        .functions
        .iter()
        .find(|r| r.old_addr == Some(check))
        .unwrap();
    assert_eq!(row.change, diff::Change::Identical);
    assert_eq!(row.matched_by, "hash");
}

#[test]
fn elf_without_mitigations() {
    let data = fixture("vuln.elf");
    let b = Binary::parse(&data).unwrap();
    assert_eq!(mitigation(&b, "NX"), MitigationStatus::Disabled);
    assert_eq!(mitigation(&b, "PIE"), MitigationStatus::Disabled);
    assert_eq!(mitigation(&b, "RELRO"), MitigationStatus::Disabled);
    assert_eq!(mitigation(&b, "Stack canary"), MitigationStatus::Disabled);

    let r = report("vuln.elf");
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(ids.contains(&"BIN-MITIGATION-NX"));
    let unsafe_api = r
        .findings
        .iter()
        .find(|f| f.id == "BIN-UNSAFE-API")
        .unwrap();
    assert_eq!(unsafe_api.severity, Severity::High);
    assert!(
        unsafe_api
            .evidence
            .iter()
            .any(|e| e.starts_with("gets ← main"))
    );
    assert!(
        unsafe_api
            .evidence
            .iter()
            .any(|e| e.starts_with("strcpy ← greet"))
    );
    assert_eq!(r.findings[0].severity, Severity::High, "sorted by severity");
    assert!(r.errors.is_empty(), "{:?}", r.errors);
}

#[test]
fn pe_imports_iat_and_capabilities() {
    let data = fixture("sample.exe");
    assert_eq!(rex_core::detect_bytes(&data, None), ArtifactKind::Pe);
    let b = Binary::parse(&data).unwrap();
    assert_eq!(b.format, BinFormat::Pe);
    assert_eq!(b.image_base, 0x1_4000_0000);
    assert_eq!(b.imports.len(), 6);
    assert_eq!(mitigation(&b, "ASLR"), MitigationStatus::Enabled);
    assert_eq!(mitigation(&b, "DEP/NX"), MitigationStatus::Enabled);
    assert_eq!(mitigation(&b, "Authenticode"), MitigationStatus::Disabled);
    // Independently computed with Python's hashlib over pefile's imphash format.
    assert_eq!(
        fingerprint::imphash(&b).as_deref(),
        Some("39eeb24e1aa74be5849718c24104c224")
    );

    let prog = functions::analyze(&b, &data, &AnalysisOptions::default());
    assert_eq!(
        prog.functions.len(),
        2,
        ".pdata seeds the uncalled function"
    );
    let entry = &prog.functions[&b.entry];
    assert!(
        entry
            .imports_called
            .contains(&"IsDebuggerPresent".to_string())
    );
    assert!(entry.strings.iter().any(|s| s.contains("gate.php")));

    let strs: Vec<String> = strings::extract(&data, 5)
        .into_iter()
        .map(|s| s.text)
        .collect();
    let caps = capabilities::detect(&capabilities::Evidence {
        imports: &b.import_names(),
        strings: &strs,
        data: &data,
    });
    let ids: Vec<&str> = caps.iter().map(|c| c.id).collect();
    assert!(ids.contains(&"CAP-INJECT-REMOTE-THREAD"));
    assert!(ids.contains(&"CAP-ANTI-DEBUG-WIN"));
    assert!(ids.contains(&"CAP-PERSIST-RUNKEY"));
}

#[test]
fn macho_entry_stubs_and_strings() {
    let data = fixture("hello.macho");
    let b = Binary::parse(&data).unwrap();
    assert_eq!(b.format, BinFormat::MachO);
    assert_eq!(b.entry, 0x1_0000_0600);
    assert_eq!(mitigation(&b, "PIE"), MitigationStatus::Enabled);
    assert!(b.code_sections().all(|s| !s.name.contains("cstring")));
    let prog = functions::analyze(&b, &data, &AnalysisOptions::default());
    let main = prog
        .find("main")
        .expect("_main via underscore-insensitive lookup");
    let verify = prog.find("_verify").unwrap();
    // clang -O1 inlines verify() into main, so both call strcmp directly.
    assert!(main.imports_called.contains(&"strcmp".to_string()));
    assert!(main.imports_called.contains(&"printf".to_string()));
    assert!(verify.imports_called.contains(&"strcmp".to_string()));
    assert!(verify.strings.contains(&"open-sesame".to_string()));
}

#[test]
fn truncated_inputs_never_panic() {
    for name in ["crackme.elf", "sample.exe", "hello.macho"] {
        let data = fixture(name);
        let mut cut = 0;
        while cut < data.len() {
            let slice = &data[..cut];
            if let Ok(b) = Binary::parse(slice) {
                let _ = functions::analyze(&b, slice, &AnalysisOptions::default());
                let _ = rex_binary::packer::detect(&b, slice);
            }
            cut += 97;
        }
        // Also flip bytes in the headers.
        let mut d = data.clone();
        for i in (0..d.len().min(4096)).step_by(13) {
            d[i] ^= 0x5a;
            if let Ok(b) = Binary::parse(&d) {
                let _ = functions::analyze(&b, &d, &AnalysisOptions::default());
            }
        }
    }
}

#[test]
fn full_registry_reports_are_clean() {
    for name in [
        "crackme.elf",
        "crackme.stripped.elf",
        "vuln.elf",
        "sample.exe",
        "hello.macho",
    ] {
        let r = report(name);
        assert!(r.errors.is_empty(), "{name}: {:?}", r.errors);
        assert!(r.section("binary.overview").is_some());
        assert!(r.section("binary.functions").is_some());
        for f in [
            rex_report::Format::Json,
            rex_report::Format::Html,
            rex_report::Format::Sarif,
        ] {
            assert!(!rex_report::render(&r, f, Default::default()).is_empty());
        }
    }
}
