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

#[test]
fn wasm_lab_flags_wasi_reach_and_names_the_start_function() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../labs/wasm/sample.wasm");
    let data = std::fs::read(&p).unwrap();
    assert_eq!(rex_core::detect_bytes(&data, None), ArtifactKind::Wasm);
    let a = Artifact::from_bytes("sample.wasm", data);
    let mut r = Registry::new();
    rex_binary::register(&mut r);
    let rep = r.run(&a, &AnalysisOptions::default(), &[]);
    assert!(rep.errors.is_empty(), "{:?}", rep.errors);
    let f = rep
        .findings
        .iter()
        .find(|f| f.id == "WASM-WASI-REACH")
        .expect("WASI reach finding");
    assert_eq!(f.severity, Severity::Medium);
    assert!(f.evidence.iter().any(|e| e.starts_with("sock_connect")));
    let funcs = serde_json::to_string(rep.section("wasm.functions").unwrap()).unwrap();
    assert!(funcs.contains("decrypt_config"));
}

// ───────────────────────── ARM / AArch64 ─────────────────────────

#[cfg(feature = "multiarch")]
mod arm {
    use super::*;
    use rex_binary::functions::{self, EdgeKind};

    fn program(name: &str) -> (Binary, functions::Program) {
        let data = fixture(name);
        let b = Binary::parse(&data).unwrap();
        let p = functions::analyze(&b, &data, &AnalysisOptions::default());
        (b, p)
    }

    fn func<'a>(p: &'a functions::Program, name: &str) -> &'a functions::Function {
        p.find(name).unwrap_or_else(|| {
            panic!(
                "no {name}; have {:?}",
                p.functions.values().map(|f| &f.name).collect::<Vec<_>>()
            )
        })
    }

    #[test]
    fn aarch64_functions_blocks_and_calls_are_recovered() {
        let (b, p) = program("sample_a64.elf");
        assert_eq!(b.arch, Arch::AArch64);
        assert!(!p.unsupported_arch);
        for n in ["check", "checksum", "main"] {
            func(&p, n);
        }
        // `check` is a loop with an early exit: several blocks and real branching.
        let check = func(&p, "check");
        assert!(check.cyclomatic() >= 3, "cyclomatic {}", check.cyclomatic());
        assert!(
            check
                .blocks
                .iter()
                .any(|b| b.succs.iter().any(|(_, k)| *k == EdgeKind::True)
                    && b.succs.iter().any(|(_, k)| *k == EdgeKind::False)),
            "a conditional branch must yield true and false successors"
        );
        // checksum is a counted loop: it has a back edge.
        let sum = func(&p, "checksum");
        assert!(
            sum.blocks
                .iter()
                .any(|b| b.succs.iter().any(|(t, _)| *t <= b.start)),
            "back edge"
        );
        // Call graph: main calls check, and nothing else does.
        let callers = p.callers();
        assert_eq!(callers.get(&check.addr), Some(&vec![func(&p, "main").addr]));
    }

    #[test]
    fn aarch64_plt_stubs_name_the_imports() {
        let (_, p) = program("sample_a64.elf");
        let main = func(&p, "main");
        assert_eq!(main.imports_called, vec!["stub_exit", "stub_log"]);
        assert!(p.stubs.values().any(|n| n == "stub_log"));
        assert!(p.names.values().any(|n| n == "stub_log@plt"));
    }

    #[test]
    fn aarch64_string_references_resolve_through_adrp_pairs() {
        let (_, p) = program("sample_a64.elf");
        let main = func(&p, "main");
        for s in ["access granted", "denied"] {
            assert!(
                main.strings.iter().any(|x| x == s),
                "{s} in {:?}",
                main.strings
            );
        }
        assert!(func(&p, "check").strings.iter().any(|s| s == "open-sesame"));
    }

    #[test]
    fn aarch64_main_is_inferred_in_a_stripped_binary() {
        let (_, p) = program("sample_a64.stripped.elf");
        let main = func(&p, "main");
        assert_eq!(p.main, Some(main.addr));
        assert_eq!(main.imports_called, vec!["stub_exit", "stub_log"]);
        assert!(
            p.functions
                .values()
                .filter(|f| f.name.starts_with("sub_"))
                .count()
                >= 2
        );
    }

    #[test]
    fn aarch64_main_is_inferred_through_a_relocated_got_slot() {
        // glibc-style PIE _start: `adrp x0, :got:main; ldr x0, [x0, ...]`. The slot holds 0 on
        // disk; main's address only exists as the addend of an R_AARCH64_RELATIVE relocation.
        let (b, p) = program("sample_a64_got.stripped.elf");
        assert!(!b.relocated_ptrs.is_empty());
        let main = func(&p, "main");
        assert_eq!(p.main, Some(main.addr));
        assert_eq!(main.imports_called, vec!["stub_exit", "stub_log"]);
    }

    #[test]
    fn arm32_functions_and_loops_are_recovered() {
        let (b, p) = program("sample_arm32.elf");
        assert_eq!(b.arch, Arch::Arm);
        assert!(!p.unsupported_arch);
        let check = func(&p, "check");
        assert!(check.cyclomatic() >= 3);
        func(&p, "checksum");
        let main = func(&p, "main");
        assert!(main.calls.contains(&check.addr));
        // PIC code reaches strings through literal pools of pc-relative offsets
        // (`ldr r0, [pc, #n]; add r0, pc, r0`).
        assert!(
            main.strings.iter().any(|s| s == "access granted"),
            "{:?}",
            main.strings
        );
        // ARM PLT entries (`add ip, pc, …; ldr pc, [ip, #n]!`) are named after their import.
        assert!(p.stubs.values().any(|n| n == "stub_log"), "{:?}", p.stubs);
        assert!(main.imports_called.iter().any(|n| n == "stub_log"));
    }

    #[test]
    fn thumb2_functions_are_decoded_in_thumb_mode() {
        // ARM-mode _start and PLT, Thumb-2 functions: a mixed binary like most armhf builds.
        let (b, p) = program("sample_thumb.elf");
        assert!(!p.unsupported_arch);
        assert_eq!(
            b.arm_map.iter().find(|m| m.0 == b.entry).map(|m| m.1),
            Some('a')
        );
        let check = func(&p, "check");
        assert_eq!(
            check.addr & 1,
            0,
            "the Thumb bit is not part of the address"
        );
        assert!(check.cyclomatic() >= 3, "{}", check.cyclomatic());
        // Thumb instructions are 2 or 4 bytes; decoding them as ARM would give 4-byte garbage.
        assert!(check.blocks[0].insns.iter().any(|i| i.bytes.len() == 2));
        func(&p, "checksum");
        let main = func(&p, "main");
        assert!(main.calls.contains(&check.addr));
        assert!(
            main.strings.iter().any(|s| s == "access granted"),
            "{:?}",
            main.strings
        );
        // Thumb main calls the ARM PLT through `blx`.
        assert!(main.imports_called.iter().any(|n| n == "stub_log"));
        let start = func(&p, "_start");
        assert!(
            start
                .imports_called
                .iter()
                .any(|n| n == "__libc_start_main")
        );
    }

    #[test]
    fn stripped_thumb2_main_is_found_through_its_got_slot() {
        // glibc PIE _start: `ldr r0, [sl, ip]` loads main | 1 from main's GOT slot.
        let (_, p) = program("sample_thumb.stripped.elf");
        let main = p.main.expect("main inferred");
        assert_eq!(main & 1, 0);
        let f = &p.functions[&main];
        assert_eq!(f.name, "main");
        assert!(f.strings.iter().any(|s| s == "denied"), "{:?}", f.strings);
        assert!(!f.calls.is_empty(), "main's Thumb code was followed");
    }
}

#[cfg(not(feature = "multiarch"))]
#[test]
fn arm_without_multiarch_degrades_to_unsupported_not_to_wrong_answers() {
    let data = fixture("sample_a64.elf");
    let b = Binary::parse(&data).unwrap();
    let p = functions::analyze(&b, &data, &AnalysisOptions::default());
    assert!(p.unsupported_arch && p.functions.is_empty());
}

#[test]
fn dotnet_metadata_is_read_from_a_real_assembly() {
    // Microsoft.Bcl.AsyncInterfaces 8.0.0 (netstandard2.1), MIT licensed; see THIRD_PARTY.md.
    let data = fixture("dotnet_asyncinterfaces.dll");
    let b = Binary::parse(&data).unwrap();
    let dn = b.dotnet.as_ref().expect("CLI metadata");
    assert_eq!(dn.runtime, "v4.0.30319");
    assert_eq!(
        dn.assembly,
        Some(("Microsoft.Bcl.AsyncInterfaces".into(), "8.0.0.0".into()))
    );
    assert!(
        dn.assembly_refs.iter().any(|(n, _)| n == "netstandard"),
        "{:?}",
        dn.assembly_refs
    );
    assert!(
        dn.types.iter().any(|t| t.starts_with("System.")),
        "{:?}",
        dn.types
    );
    assert!(dn.method_count > 0 && dn.type_count > 0);
    assert!(dn.il_only && dn.strong_named);
    assert!(dn.pinvokes.is_empty());
}

#[test]
fn pe_version_info_and_manifest_elevation() {
    let dll = Binary::parse(&fixture("dotnet_asyncinterfaces.dll")).unwrap();
    let get = |b: &Binary, k: &str| {
        b.extras
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        get(&dll, "Version: CompanyName").as_deref(),
        Some("Microsoft Corporation")
    );
    assert_eq!(
        get(&dll, "Version: OriginalFilename").as_deref(),
        Some("Microsoft.Bcl.AsyncInterfaces.dll")
    );

    let exe = Binary::parse(&fixture("elevated.exe")).unwrap();
    assert_eq!(
        get(&exe, "Manifest: requestedExecutionLevel").as_deref(),
        Some("requireAdministrator")
    );
    let r = report("elevated.exe");
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    assert!(
        ids.contains(&"BIN-PE-MANIFEST-ELEVATION") && ids.contains(&"BIN-PE-MANIFEST-UIACCESS"),
        "{ids:?}"
    );
}
