//! Exploit-mitigation inventory ("checksec").
//!
//! Analogy: a house's security features. NX is "windows don't open from the
//! outside" (data can't be executed), ASLR/PIE is "the furniture moves every
//! night" (addresses are unpredictable), stack canaries are "a tripwire on
//! the hallway" (overflows get noticed), RELRO is "bolting the address book
//! shut" (the GOT can't be overwritten), and CFG/CET/BTI are "guards who
//! check that you only walk through real doors" (control-flow integrity).

use crate::model::{Binary, Mitigation, MitigationStatus::*};
use goblin::{elf, mach, pe};

fn m(
    name: &'static str,
    status: crate::model::MitigationStatus,
    detail: impl Into<String>,
) -> Mitigation {
    Mitigation {
        name,
        status,
        detail: detail.into(),
    }
}

/// GNU property note bits (x86 CET and AArch64 BTI/PAC).
fn gnu_properties(e: &elf::Elf, data: &[u8]) -> (Option<u32>, Option<u32>) {
    const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
    const X86_FEATURE_1_AND: u32 = 0xc000_0002;
    const AARCH64_FEATURE_1_AND: u32 = 0xc000_0000;
    let (mut x86, mut a64) = (None, None);
    let align = if e.is_64 { 8 } else { 4 };
    let Some(notes) = e.iter_note_headers(data) else {
        return (None, None);
    };
    for n in notes.flatten() {
        if n.n_type != NT_GNU_PROPERTY_TYPE_0 || n.name != "GNU" {
            continue;
        }
        let d = n.desc;
        let mut i = 0usize;
        while i + 8 <= d.len() {
            let rd = |o: usize| -> u32 {
                let b = &d[o..o + 4];
                if e.little_endian {
                    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
                } else {
                    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
                }
            };
            let pr_type = rd(i);
            let sz = rd(i + 4) as usize;
            if i + 8 + sz > d.len() {
                break;
            }
            if sz >= 4 {
                let v = rd(i + 8);
                match pr_type {
                    X86_FEATURE_1_AND => x86 = Some(v),
                    AARCH64_FEATURE_1_AND => a64 = Some(v),
                    _ => {}
                }
            }
            i += 8 + sz.div_ceil(align) * align;
        }
    }
    (x86, a64)
}

pub(crate) fn elf(e: &elf::Elf, b: &Binary, data: &[u8]) -> Vec<Mitigation> {
    use elf::dynamic::*;
    use elf::program_header::*;
    let mut out = Vec::new();

    // NX
    match e.program_headers.iter().find(|p| p.p_type == PT_GNU_STACK) {
        Some(p) if p.p_flags & PF_X == 0 => out.push(m("NX", Enabled, "PT_GNU_STACK is RW")),
        Some(_) => out.push(m("NX", Disabled, "PT_GNU_STACK is RWX (executable stack)")),
        None => out.push(m(
            "NX",
            Disabled,
            "no PT_GNU_STACK; stack is executable by default",
        )),
    }

    // PIE
    let flags_1 = e.dynamic.as_ref().map(|d| d.info.flags_1).unwrap_or(0);
    let flags = e.dynamic.as_ref().map(|d| d.info.flags).unwrap_or(0);
    match e.header.e_type {
        elf::header::ET_DYN if e.interpreter.is_some() || flags_1 & DF_1_PIE != 0 => {
            out.push(m("PIE", Enabled, "position-independent executable"))
        }
        elf::header::ET_DYN => out.push(m("PIE", Enabled, "shared object (always relocatable)")),
        elf::header::ET_EXEC => out.push(m("PIE", Disabled, "fixed load address (ET_EXEC)")),
        _ => out.push(m("PIE", Unknown, "not an executable image")),
    }

    // RELRO
    let has_relro = e.program_headers.iter().any(|p| p.p_type == PT_GNU_RELRO);
    let bind_now = flags & DF_BIND_NOW != 0 || flags_1 & DF_1_NOW != 0;
    out.push(match (has_relro, bind_now) {
        (true, true) => m("RELRO", Enabled, "full RELRO (GOT read-only after load)"),
        (true, false) => m(
            "RELRO",
            Partial,
            "partial RELRO (lazy binding; .got.plt writable)",
        ),
        (false, _) => m("RELRO", Disabled, "no PT_GNU_RELRO"),
    });

    // Stack canary / FORTIFY
    let names: Vec<&str> = b
        .imports
        .iter()
        .map(|i| i.name.as_str())
        .chain(b.symbols.iter().map(|s| s.name.as_str()))
        .collect();
    let canary = names.iter().any(|n| {
        *n == "__stack_chk_fail" || *n == "__stack_chk_guard" || *n == "__intel_security_cookie"
    });
    out.push(if canary {
        m("Stack canary", Enabled, "references __stack_chk_fail")
    } else if b.stripped && b.imports.is_empty() {
        m(
            "Stack canary",
            Unknown,
            "static & stripped; cannot tell from symbols",
        )
    } else {
        m("Stack canary", Disabled, "no __stack_chk_fail reference")
    });
    let fortified: Vec<&str> = names
        .iter()
        .copied()
        .filter(|n| n.starts_with("__") && n.ends_with("_chk") && *n != "__stack_chk_fail")
        .collect();
    out.push(if fortified.is_empty() {
        m("FORTIFY_SOURCE", Disabled, "no *_chk functions")
    } else {
        let mut f = fortified.clone();
        f.sort_unstable();
        f.dedup();
        m(
            "FORTIFY_SOURCE",
            Enabled,
            format!(
                "{} fortified: {}",
                f.len(),
                f.iter().take(4).copied().collect::<Vec<_>>().join(", ")
            ),
        )
    });

    // RPATH
    out.push(if !e.rpaths.is_empty() {
        m(
            "No RPATH",
            Disabled,
            format!(
                "RPATH={} (searched before LD_LIBRARY_PATH)",
                e.rpaths.join(":")
            ),
        )
    } else if !e.runpaths.is_empty() {
        m(
            "No RPATH",
            Partial,
            format!("RUNPATH={}", e.runpaths.join(":")),
        )
    } else {
        m("No RPATH", Enabled, "no RPATH/RUNPATH")
    });

    // CFI: CET / BTI / PAC
    let (x86, a64) = gnu_properties(e, data);
    match &b.arch {
        crate::model::Arch::X86 | crate::model::Arch::X86_64 => {
            let v = x86.unwrap_or(0);
            out.push(m(
                "CET IBT",
                if v & 1 != 0 { Enabled } else { Disabled },
                "indirect-branch tracking (endbr64 landing pads)",
            ));
            out.push(m(
                "CET SHSTK",
                if v & 2 != 0 { Enabled } else { Disabled },
                "hardware shadow stack",
            ));
        }
        crate::model::Arch::AArch64 => {
            let v = a64.unwrap_or(0);
            out.push(m(
                "BTI",
                if v & 1 != 0 { Enabled } else { Disabled },
                "branch target identification",
            ));
            out.push(m(
                "PAC",
                if v & 2 != 0 { Enabled } else { Disabled },
                "pointer authentication",
            ));
        }
        _ => {}
    }
    out
}

pub(crate) fn pe(p: &pe::PE, b: &Binary) -> Vec<Mitigation> {
    let mut out = Vec::new();
    let Some(opt) = p.header.optional_header else {
        out.push(m("Optional header", Unknown, "missing"));
        return out;
    };
    let dc = opt.windows_fields.dll_characteristics;
    let relocs_stripped =
        p.header.coff_header.characteristics & pe::characteristic::IMAGE_FILE_RELOCS_STRIPPED != 0;
    const HIGH_ENTROPY_VA: u16 = 0x0020;
    const DYNAMIC_BASE: u16 = 0x0040;
    const FORCE_INTEGRITY: u16 = 0x0080;
    const NX_COMPAT: u16 = 0x0100;
    const NO_SEH: u16 = 0x0400;
    const GUARD_CF: u16 = 0x4000;

    out.push(match (dc & DYNAMIC_BASE != 0, relocs_stripped) {
        (true, false) => m("ASLR", Enabled, "DYNAMIC_BASE"),
        (true, true) => m("ASLR", Partial, "DYNAMIC_BASE set but relocations stripped"),
        (false, _) => m("ASLR", Disabled, "no DYNAMIC_BASE"),
    });
    if p.is_64 {
        out.push(m(
            "High-entropy ASLR",
            if dc & HIGH_ENTROPY_VA != 0 {
                Enabled
            } else {
                Disabled
            },
            "64-bit address space randomisation",
        ));
    }
    out.push(m(
        "DEP/NX",
        if dc & NX_COMPAT != 0 {
            Enabled
        } else {
            Disabled
        },
        "NX_COMPAT",
    ));
    out.push(m(
        "CFG",
        if dc & GUARD_CF != 0 {
            Enabled
        } else {
            Disabled
        },
        "Control Flow Guard",
    ));
    let lc = p.load_config_data.as_ref().map(|l| &l.directory);
    if p.is_64 {
        out.push(m(
            "SafeSEH",
            Enabled,
            "x64 uses table-based exception handling",
        ));
    } else if dc & NO_SEH != 0 {
        out.push(m("SafeSEH", Enabled, "NO_SEH: image has no SEH handlers"));
    } else if lc.and_then(|l| l.se_handler_table).unwrap_or(0) != 0 {
        out.push(m(
            "SafeSEH",
            Enabled,
            format!(
                "{} registered handlers",
                lc.and_then(|l| l.se_handler_count).unwrap_or(0)
            ),
        ));
    } else {
        out.push(m("SafeSEH", Disabled, "no SEHandlerTable"));
    }
    out.push(match lc.and_then(|l| l.security_cookie) {
        Some(c) if c != 0 => m("GS cookie", Enabled, format!("security cookie at {c:#x}")),
        _ => m("GS cookie", Unknown, "no load-config security cookie"),
    });
    let cet = p
        .debug_data
        .as_ref()
        .and_then(|d| d.ex_dll_characteristics_info.as_ref())
        .map(|x| x.characteristics_ex & 1 != 0)
        .unwrap_or(false);
    out.push(m(
        "CET shadow stack",
        if cet { Enabled } else { Disabled },
        "CET_COMPAT",
    ));
    out.push(m(
        "Force integrity",
        if dc & FORCE_INTEGRITY != 0 {
            Enabled
        } else {
            Disabled
        },
        "signature checked at load",
    ));
    let signed = opt
        .data_directories
        .get_certificate_table()
        .map(|d| d.size > 0)
        .unwrap_or(false);
    out.push(m(
        "Authenticode",
        if signed { Enabled } else { Disabled },
        if signed {
            "signature present (not verified)"
        } else {
            "unsigned"
        },
    ));
    if b.overlay_offset.is_some() {
        out.push(m(
            "No overlay",
            Disabled,
            "data appended after the last section",
        ));
    }
    out
}

pub(crate) fn macho(mo: &mach::MachO, b: &Binary, data: &[u8]) -> Vec<Mitigation> {
    use mach::header::*;
    use mach::load_command::CommandVariant;
    let mut out = Vec::new();
    let f = mo.header.flags;
    let exe = mo.header.filetype == MH_EXECUTE;
    out.push(if !exe {
        m("PIE", Enabled, "library / bundle (always relocatable)")
    } else if f & MH_PIE != 0 {
        m("PIE", Enabled, "MH_PIE")
    } else {
        m("PIE", Disabled, "no MH_PIE")
    });
    out.push(if f & MH_ALLOW_STACK_EXECUTION != 0 {
        m("NX stack", Disabled, "MH_ALLOW_STACK_EXECUTION")
    } else {
        m("NX stack", Enabled, "stack not executable")
    });
    out.push(m(
        "NX heap",
        if f & MH_NO_HEAP_EXECUTION != 0 {
            Enabled
        } else {
            Partial
        },
        if f & MH_NO_HEAP_EXECUTION != 0 {
            "MH_NO_HEAP_EXECUTION"
        } else {
            "default (enforced on arm64)"
        },
    ));
    let names: Vec<&str> = b.imports.iter().map(|i| i.name.as_str()).collect();
    out.push(m(
        "Stack canary",
        if names.contains(&"__stack_chk_fail") {
            Enabled
        } else {
            Disabled
        },
        "___stack_chk_fail import",
    ));
    out.push(m(
        "ARC",
        if names.contains(&"objc_release") {
            Enabled
        } else {
            Unknown
        },
        "Objective-C automatic reference counting",
    ));
    let mut signed = false;
    let mut hardened = false;
    let mut encrypted = None;
    for lc in &mo.load_commands {
        match &lc.command {
            CommandVariant::CodeSignature(cs) => {
                signed = true;
                hardened =
                    code_signature_has_runtime(data, cs.dataoff as usize, cs.datasize as usize);
            }
            CommandVariant::EncryptionInfo64(e) => encrypted = Some(e.cryptid),
            CommandVariant::EncryptionInfo32(e) => encrypted = Some(e.cryptid),
            _ => {}
        }
    }
    out.push(m(
        "Code signature",
        if signed { Enabled } else { Disabled },
        "LC_CODE_SIGNATURE",
    ));
    out.push(m(
        "Hardened runtime",
        if hardened { Enabled } else { Disabled },
        "CS_RUNTIME flag in CodeDirectory",
    ));
    if let Some(id) = encrypted {
        out.push(m(
            "Encrypted",
            if id != 0 { Enabled } else { Disabled },
            if id != 0 {
                "FairPlay encrypted (decrypt before analysis)"
            } else {
                "cryptid=0"
            },
        ));
    }
    out
}

/// Walk the code-signing SuperBlob to find the CodeDirectory flags.
fn code_signature_has_runtime(data: &[u8], off: usize, size: usize) -> bool {
    let Some(blob) = data.get(off..off.saturating_add(size)) else {
        return false;
    };
    let be = |o: usize| -> Option<u32> {
        blob.get(o..o + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    if be(0) != Some(0xfade_0cc0) {
        return false;
    }
    let count = be(8).unwrap_or(0).min(64) as usize;
    for i in 0..count {
        let Some(btype) = be(12 + i * 8) else { break };
        let Some(boff) = be(16 + i * 8) else { break };
        if btype == 0 {
            let boff = boff as usize;
            if be(boff) == Some(0xfade_0c02) {
                if let Some(flags) = be(boff + 12) {
                    return flags & 0x0001_0000 != 0;
                }
            }
        }
    }
    false
}
