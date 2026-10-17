//! ELF dynamic relocations: every entry of the RELA, REL, PLT and RELR tables, with its type
//! name, symbol, addend and where it lands.
//!
//! A relocation is an instruction to the loader: "write this value into that slot". Reading them
//! shows what the binary links against (`JUMP_SLOT`/`GLOB_DAT` name the import in each GOT slot),
//! which pointers are fixed up at load (`RELATIVE`), and whether code pages are patched at run
//! time (a text relocation, which needs a writable code page).

use crate::model::Binary;
use goblin::elf;
use serde::Serialize;

/// Stop after this many relocations (a large binary has a few hundred thousand).
pub const MAX_RELOCS: usize = 1_000_000;

/// `DT_RELRSZ`, `DT_RELR`: goblin does not parse RELR tables.
const DT_RELRSZ: u64 = 35;
const DT_RELR: u64 = 36;

/// One dynamic relocation.
#[derive(Debug, Clone, Serialize)]
pub struct Reloc {
    /// Address of the slot the loader writes.
    pub offset: u64,
    /// Relocation type number.
    pub kind: u32,
    /// Relocation type name, e.g. `R_X86_64_JUMP_SLOT`.
    pub kind_name: String,
    /// Symbol whose value is written, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// The explicit addend (RELA), or the value stored in the slot (REL, RELR).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addend: Option<i64>,
    /// Table: `rela`, `rel`, `plt` (DT_JMPREL) or `relr`.
    pub table: &'static str,
    /// Section holding the slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// The slot is in a writable section (a non-writable one is a text relocation).
    pub writable: bool,
    /// The slot is covered by PT_GNU_RELRO: read-only once the loader is done.
    pub relro: bool,
}

/// Read every dynamic relocation. The flag is true when [`MAX_RELOCS`] cut the list short.
pub fn elf(e: &elf::Elf, b: &Binary, data: &[u8]) -> (Vec<Reloc>, bool) {
    use elf::program_header::PT_GNU_RELRO;
    let relro: Vec<(u64, u64)> = e
        .program_headers
        .iter()
        .filter(|p| p.p_type == PT_GNU_RELRO)
        .map(|p| (p.p_vaddr, p.p_vaddr.saturating_add(p.p_memsz)))
        .collect();
    let machine = e.header.e_machine;
    let width = if e.is_64 { 8 } else { 4 };
    let mut out = Vec::new();
    let make = |offset: u64, kind: u32, symbol: Option<String>, addend: Option<i64>, table| {
        let sec = b.section_for(offset);
        Reloc {
            offset,
            kind,
            kind_name: format!("R_{}", elf::reloc::r_to_str(kind, machine)),
            symbol,
            addend,
            table,
            section: sec.map(|s| s.name.clone()),
            writable: sec.is_none_or(|s| s.perms.w),
            relro: relro.iter().any(|&(s, e)| offset >= s && offset < e),
        }
    };
    let slot_value = |va: u64| read_word(b, data, va, width).map(|v| v as i64);
    let tables = [
        (&e.dynrelas, "rela"),
        (&e.dynrels, "rel"),
        (&e.pltrelocs, "plt"),
    ];
    let mut n = 0usize;
    for (tab, name) in tables {
        for r in tab.iter() {
            if n >= MAX_RELOCS {
                return (out, true);
            }
            n += 1;
            let symbol = (r.r_sym != 0)
                .then(|| e.dynsyms.get(r.r_sym))
                .flatten()
                .and_then(|s| e.dynstrtab.get_at(s.st_name))
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let addend = r.r_addend.or_else(|| slot_value(r.r_offset));
            out.push(make(r.r_offset, r.r_type, symbol, addend, name));
        }
    }
    let relative = relative_type(machine);
    let mut cut = false;
    if let Some(kind) = relative {
        for slot in relr_slots(e, b, data, width) {
            if n >= MAX_RELOCS {
                cut = true;
                break;
            }
            n += 1;
            out.push(make(slot, kind, None, slot_value(slot), "relr"));
        }
    }
    (out, cut)
}

/// The machine's RELATIVE relocation type (what every RELR entry is).
fn relative_type(machine: u16) -> Option<u32> {
    use elf::header::*;
    use elf::reloc::*;
    Some(match machine {
        EM_X86_64 => R_X86_64_RELATIVE,
        EM_386 => R_386_RELATIVE,
        EM_AARCH64 => R_AARCH64_RELATIVE,
        EM_ARM => R_ARM_RELATIVE,
        EM_RISCV => R_RISCV_RELATIVE,
        EM_PPC64 => R_PPC64_RELATIVE,
        EM_PPC => R_PPC_RELATIVE,
        _ => return None,
    })
}

fn read_word(b: &Binary, data: &[u8], va: u64, width: usize) -> Option<u64> {
    let w = b.bytes_at(data, va)?.get(..width)?;
    let mut buf = [0u8; 8];
    Some(if b.little_endian {
        buf[..width].copy_from_slice(w);
        u64::from_le_bytes(buf)
    } else {
        buf[8 - width..].copy_from_slice(w);
        u64::from_be_bytes(buf)
    })
}

/// Decode the compact RELR table (`-z pack-relative-relocs`): an even word is the address of a
/// slot to relocate; an odd word is a bitmap of which of the following 63 (or 31) words are.
fn relr_slots(e: &elf::Elf, b: &Binary, data: &[u8], width: usize) -> Vec<u64> {
    let Some(dynamic) = &e.dynamic else {
        return Vec::new();
    };
    let tag = |t: u64| dynamic.dyns.iter().find(|d| d.d_tag == t).map(|d| d.d_val);
    let (Some(addr), Some(size)) = (tag(DT_RELR), tag(DT_RELRSZ)) else {
        return Vec::new();
    };
    let Some(bytes) = b.bytes_at(data, addr) else {
        return Vec::new();
    };
    let bytes = &bytes[..bytes.len().min(usize::try_from(size).unwrap_or(usize::MAX))];
    let step = width as u64;
    let bits = width * 8 - 1;
    let mut out = Vec::new();
    let mut next = 0u64;
    for word in bytes.chunks_exact(width) {
        let mut buf = [0u8; 8];
        let v = if b.little_endian {
            buf[..width].copy_from_slice(word);
            u64::from_le_bytes(buf)
        } else {
            buf[8 - width..].copy_from_slice(word);
            u64::from_be_bytes(buf)
        };
        if v & 1 == 0 {
            out.push(v);
            next = v.wrapping_add(step);
        } else {
            for i in 0..bits {
                if (v >> (i + 1)) & 1 == 1 {
                    out.push(next.wrapping_add(i as u64 * step));
                }
            }
            next = next.wrapping_add(bits as u64 * step);
        }
        if out.len() >= MAX_RELOCS {
            out.truncate(MAX_RELOCS);
            break;
        }
    }
    out
}

/// `BIN-ELF-TEXTREL` when the loader has to patch read-only (code) pages.
pub fn textrel_finding(b: &Binary) -> Option<rex_core::Finding> {
    let text: Vec<&Reloc> = text_relocs(&b.relocs).collect();
    let flagged = b.extras.iter().any(|(k, _)| k == "TEXTREL");
    if text.is_empty() && !flagged {
        return None;
    }
    let mut f = rex_core::Finding::new(
        "BIN-ELF-TEXTREL",
        rex_core::Severity::Medium,
        "hardening",
        "Text relocations: the loader patches read-only code pages",
    )
    .describe(
        "To apply these relocations the loader makes code pages writable, which defeats W^X for \
         them and stops the pages being shared between processes. Usually non-PIC code linked \
         into a PIE or shared library; rebuild with -fPIC.",
    );
    for r in text.iter().take(10) {
        f = f.evidence(format!(
            "{} at {:#x} in {}{}",
            r.kind_name,
            r.offset,
            r.section.as_deref().unwrap_or("?"),
            r.symbol
                .as_deref()
                .map(|s| format!(" ({s})"))
                .unwrap_or_default()
        ));
    }
    if text.len() > 10 {
        f = f.evidence(format!("… {} more", text.len() - 10));
    }
    Some(f)
}

/// Text relocations: slots in mapped, non-writable sections, which the loader can only patch by
/// making code pages writable.
pub fn text_relocs(relocs: &[Reloc]) -> impl Iterator<Item = &Reloc> {
    relocs.iter().filter(|r| !r.writable && r.section.is_some())
}
