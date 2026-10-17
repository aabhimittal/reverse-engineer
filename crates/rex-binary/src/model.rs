//! A format-agnostic model of a native executable.
//!
//! ELF, PE and Mach-O disagree on almost every name (sections vs. segments,
//! IAT vs. GOT, `LC_MAIN` vs. `AddressOfEntryPoint`), but they all answer the
//! same questions: *what CPU, where does code live, what does it import, where
//! does execution start?* [`Binary`] is that common answer, so every later
//! pass (checksec, disassembly, capabilities) is written once.

use goblin::{Object, elf, mach, pe};
use rex_core::{Error, Result, hash};
use serde::Serialize;

/// Container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BinFormat {
    /// ELF.
    Elf,
    /// PE / COFF.
    Pe,
    /// Mach-O.
    MachO,
}

impl BinFormat {
    /// Label.
    pub fn as_str(self) -> &'static str {
        match self {
            BinFormat::Elf => "ELF",
            BinFormat::Pe => "PE",
            BinFormat::MachO => "Mach-O",
        }
    }
}

/// CPU architecture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Arch {
    /// 32-bit x86.
    X86,
    /// x86-64 / AMD64.
    X86_64,
    /// 32-bit ARM.
    Arm,
    /// AArch64 / ARM64.
    AArch64,
    /// MIPS (32-bit).
    Mips,
    /// MIPS64.
    Mips64,
    /// PowerPC.
    PowerPc,
    /// PowerPC64.
    PowerPc64,
    /// RISC-V.
    RiscV,
    /// Anything else (raw machine id / name).
    Other(String),
}

impl Arch {
    /// Label.
    pub fn name(&self) -> String {
        match self {
            Arch::X86 => "x86".into(),
            Arch::X86_64 => "x86_64".into(),
            Arch::Arm => "arm".into(),
            Arch::AArch64 => "aarch64".into(),
            Arch::Mips => "mips".into(),
            Arch::Mips64 => "mips64".into(),
            Arch::PowerPc => "powerpc".into(),
            Arch::PowerPc64 => "powerpc64".into(),
            Arch::RiscV => "riscv".into(),
            Arch::Other(s) => s.clone(),
        }
    }

    /// True if the built-in (iced-x86) disassembler handles it.
    pub fn is_x86(&self) -> bool {
        matches!(self, Arch::X86 | Arch::X86_64)
    }
}

/// Memory permissions.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Perms {
    /// Readable.
    pub r: bool,
    /// Writable.
    pub w: bool,
    /// Executable.
    pub x: bool,
}

impl std::fmt::Display for Perms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.r { 'r' } else { '-' },
            if self.w { 'w' } else { '-' },
            if self.x { 'x' } else { '-' }
        )
    }
}

/// A section (or Mach-O section within a segment).
#[derive(Debug, Clone, Serialize)]
pub struct SectionInfo {
    /// Name (e.g. `.text`, `__TEXT,__text`).
    pub name: String,
    /// Virtual address.
    pub addr: u64,
    /// Size in memory.
    pub size: u64,
    /// File offset of the section bytes.
    pub offset: u64,
    /// Bytes present in the file (0 for `.bss`-like sections).
    pub file_size: u64,
    /// Permissions.
    pub perms: Perms,
    /// Shannon entropy of the file bytes.
    pub entropy: f64,
}

impl SectionInfo {
    /// Whether `va` falls inside this section.
    pub fn contains(&self, va: u64) -> bool {
        va >= self.addr && va < self.addr.saturating_add(self.size.max(self.file_size))
    }
}

/// An imported function.
#[derive(Debug, Clone, Serialize)]
pub struct Import {
    /// Library (DLL / dylib / `None` for ELF where binding is global).
    pub library: Option<String>,
    /// Symbol name (demangled where possible).
    pub name: String,
    /// Address of the pointer slot (IAT / GOT / lazy pointer) if known.
    pub slot: Option<u64>,
}

/// Symbol kinds we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SymKind {
    /// Function / code.
    Func,
    /// Data object.
    Object,
    /// Other / unknown.
    Other,
}

/// A defined symbol.
#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    /// Raw name.
    pub name: String,
    /// Demangled name, if the raw one was mangled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demangled: Option<String>,
    /// Address.
    pub addr: u64,
    /// Size (0 if unknown).
    pub size: u64,
    /// Kind.
    pub kind: SymKind,
}

impl Symbol {
    /// Best display name.
    pub fn display(&self) -> &str {
        self.demangled.as_deref().unwrap_or(&self.name)
    }
}

/// Status of a security mitigation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MitigationStatus {
    /// Fully enabled.
    Enabled,
    /// Partially enabled.
    Partial,
    /// Disabled.
    Disabled,
    /// Not applicable / cannot be determined statically.
    Unknown,
}

impl MitigationStatus {
    /// Label with a glyph for terminals.
    pub fn label(self) -> &'static str {
        match self {
            MitigationStatus::Enabled => "✔ enabled",
            MitigationStatus::Partial => "◐ partial",
            MitigationStatus::Disabled => "✘ disabled",
            MitigationStatus::Unknown => "? unknown",
        }
    }
}

/// One checksec row.
#[derive(Debug, Clone, Serialize)]
pub struct Mitigation {
    /// Name, e.g. `NX`, `PIE`, `RELRO`.
    pub name: &'static str,
    /// Status.
    pub status: MitigationStatus,
    /// Detail.
    pub detail: String,
}

/// The unified binary model.
#[derive(Debug, Clone, Serialize)]
pub struct Binary {
    /// Container format.
    pub format: BinFormat,
    /// CPU.
    pub arch: Arch,
    /// 32 or 64.
    pub bits: u8,
    /// Little endian?
    pub little_endian: bool,
    /// File type (executable, shared library, object, driver …).
    pub file_type: String,
    /// Entry point virtual address (0 if none).
    pub entry: u64,
    /// Preferred load address.
    pub image_base: u64,
    /// Sections.
    pub sections: Vec<SectionInfo>,
    /// Imported functions.
    pub imports: Vec<Import>,
    /// Exported symbols.
    pub exports: Vec<Symbol>,
    /// Defined symbols (functions & objects).
    pub symbols: Vec<Symbol>,
    /// Linked libraries.
    pub libraries: Vec<String>,
    /// ELF interpreter / dynamic loader.
    pub interpreter: Option<String>,
    /// No local symbol table.
    pub stripped: bool,
    /// Security mitigations.
    pub mitigations: Vec<Mitigation>,
    /// Extra format-specific facts (build-id, PDB path, timestamp, …).
    pub extras: Vec<(String, String)>,
    /// Offset of this image inside the file (non-zero for fat Mach-O slices).
    pub slice_offset: u64,
    /// File offset where appended (overlay) data begins, if any.
    pub overlay_offset: Option<u64>,
    /// Size of the file slice this model describes.
    pub slice_size: u64,
    /// Function start addresses from unwind / metadata tables
    /// (PE `.pdata`, Mach-O `LC_FUNCTION_STARTS`).
    pub function_starts: Vec<u64>,
    /// Pointer slots whose on-disk value is not the value at run time, sorted by slot address.
    /// In ELF RELA binaries a slot covered by a RELATIVE relocation holds 0 on disk and the
    /// pointer lives in the relocation addend (e.g. the GOT slot glibc's PIE `_start` loads
    /// `main` from).
    pub relocated_ptrs: Vec<(u64, u64)>,
}

impl Binary {
    /// Parse an artifact once and share the result with every other caller on the same artifact
    /// (a full `rex analyze` used to parse the same file once per analyzer).
    pub fn of(a: &rex_core::Artifact) -> Result<std::sync::Arc<Self>> {
        a.memo(|a| {
            Self::parse(a.data())
                .map(std::sync::Arc::new)
                .map_err(|e| e.to_string())
        })
        .as_ref()
        .clone()
        .map_err(|e| Error::parse("binary", e))
    }

    /// Parse any supported format.
    ///
    /// Third-party parsers occasionally panic on hostile input; such panics are
    /// converted into [`Error::Parse`] so callers never crash on a malformed file.
    pub fn parse(data: &[u8]) -> Result<Self> {
        std::panic::catch_unwind(|| Self::parse_inner(data))
            .unwrap_or_else(|_| Err(Error::parse("binary", "malformed input (parser panicked)")))
    }

    fn parse_inner(data: &[u8]) -> Result<Self> {
        let obj = Object::parse(data).map_err(|e| Error::parse("binary", e.to_string()))?;
        match obj {
            Object::Elf(e) => Ok(from_elf(&e, data)),
            Object::PE(p) => Ok(from_pe(&p, data)),
            Object::Mach(mach::Mach::Binary(m)) => Ok(from_macho(&m, data, 0, data.len() as u64)),
            Object::Mach(mach::Mach::Fat(fat)) => {
                // The header's slice count is attacker-controlled (a fuzzed file claimed ~2^31):
                // stop at the first unreadable entry and never look past what 20-byte entries
                // after the 8-byte header could fit in the file.
                let fits = data.len().saturating_sub(8) / 20;
                let arches: Vec<_> = fat
                    .iter_arches()
                    .take(fits.min(256))
                    .map_while(|a| a.ok())
                    .collect();
                let mut chosen = None;
                let mut names = Vec::new();
                for (i, a) in arches.iter().enumerate() {
                    let name =
                        mach::constants::cputype::get_arch_name_from_types(a.cputype, a.cpusubtype)
                            .unwrap_or("unknown");
                    names.push(name.to_string());
                    // Prefer x86_64 (disassemblable without extra features), then the first.
                    if chosen.is_none() || a.cputype == mach::constants::cputype::CPU_TYPE_X86_64 {
                        chosen = Some(i);
                    }
                }
                let i =
                    chosen.ok_or_else(|| Error::parse("Mach-O", "fat binary with no slices"))?;
                let a = &arches[i];
                let start = a.offset as usize;
                let end = start.saturating_add(a.size as usize).min(data.len());
                let slice = data
                    .get(start..end)
                    .ok_or_else(|| Error::parse("Mach-O", "fat slice out of bounds"))?;
                let m = mach::MachO::parse(slice, 0)
                    .map_err(|e| Error::parse("Mach-O", e.to_string()))?;
                let mut b = from_macho(&m, slice, a.offset as u64, slice.len() as u64);
                b.extras.insert(0, ("Fat slices".into(), names.join(", ")));
                b.extras
                    .insert(1, ("Analysed slice".into(), names[i].clone()));
                Ok(b)
            }
            Object::Archive(_) => Err(Error::Unsupported(
                "static archive (.a); extract members with `ar x` first".into(),
            )),
            _ => Err(Error::Unsupported("unrecognised object format".into())),
        }
    }

    /// Executable sections.
    pub fn code_sections(&self) -> impl Iterator<Item = &SectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.perms.x && s.file_size > 0)
    }

    /// Sections that are mapped into memory at runtime (excludes ELF
    /// non-allocated sections such as `.symtab` or `.comment`, which sit at
    /// address 0 and would otherwise alias real code addresses).
    fn mapped(&self) -> impl Iterator<Item = &SectionInfo> {
        self.sections
            .iter()
            .filter(|s| s.perms.r || s.perms.w || s.perms.x)
    }

    /// Section containing a virtual address.
    pub fn section_for(&self, va: u64) -> Option<&SectionInfo> {
        self.mapped()
            .filter(|s| s.file_size > 0 || s.size > 0)
            .find(|s| s.contains(va))
    }

    /// Translate a virtual address to an offset in `data` (the original file).
    pub fn va_to_offset(&self, va: u64) -> Option<u64> {
        let s = self
            .mapped()
            .filter(|s| s.file_size > 0)
            .find(|s| va >= s.addr && va - s.addr < s.file_size)?;
        self.slice_offset
            .checked_add(s.offset)?
            .checked_add(va - s.addr)
    }

    /// Translate a file offset (in the original file) to a virtual address.
    pub fn offset_to_va(&self, off: u64) -> Option<u64> {
        let off = off.checked_sub(self.slice_offset)?;
        let s = self
            .mapped()
            .filter(|s| s.file_size > 0)
            .find(|s| off >= s.offset && off - s.offset < s.file_size)?;
        s.addr.checked_add(off - s.offset)
    }

    /// Borrow bytes starting at a virtual address, bounded by its section.
    pub fn bytes_at<'d>(&self, data: &'d [u8], va: u64) -> Option<&'d [u8]> {
        let s = self
            .mapped()
            .filter(|s| s.file_size > 0)
            .find(|s| va >= s.addr && va - s.addr < s.file_size)?;
        let base = self.slice_offset.checked_add(s.offset)?;
        let start = usize::try_from(base.checked_add(va - s.addr)?).ok()?;
        let end = usize::try_from(base.saturating_add(s.file_size)).unwrap_or(usize::MAX);
        data.get(start..end.min(data.len()))
    }

    /// Bytes of a section.
    pub fn section_bytes<'d>(&self, data: &'d [u8], s: &SectionInfo) -> &'d [u8] {
        let start =
            usize::try_from(self.slice_offset.saturating_add(s.offset)).unwrap_or(usize::MAX);
        let end = start.saturating_add(s.file_size as usize).min(data.len());
        data.get(start..end).unwrap_or(&[])
    }

    /// Look up a symbol (function) by exact or demangled name.
    pub fn find_symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols
            .iter()
            .chain(self.exports.iter())
            .find(|s| s.name == name || s.demangled.as_deref() == Some(name))
            .or_else(|| {
                // Mach-O prefixes C symbols with an underscore.
                let alt = format!("_{name}");
                self.symbols.iter().find(|s| s.name == alt)
            })
    }

    /// Import names, lower-cased, without library.
    pub fn import_names(&self) -> Vec<String> {
        self.imports.iter().map(|i| i.name.clone()).collect()
    }
}

/// Demangle Itanium C++ (`_Z…`) and Rust (`_R…`, legacy `_ZN…h<hash>E`) names.
pub fn demangle(name: &str) -> Option<String> {
    let stripped = name
        .strip_prefix('_')
        .filter(|n| n.starts_with("_Z") || n.starts_with("_R"));
    let candidate = stripped.unwrap_or(name);
    if let Ok(d) = rustc_demangle::try_demangle(candidate) {
        let s = format!("{d:#}");
        if s != candidate {
            return Some(s);
        }
    }
    if candidate.starts_with("_Z") {
        if let Ok(sym) = cpp_demangle::Symbol::new(candidate) {
            if let Ok(s) = sym.demangle() {
                return Some(s);
            }
        }
    }
    None
}

fn sym(name: &str, addr: u64, size: u64, kind: SymKind) -> Symbol {
    Symbol {
        name: name.to_string(),
        demangled: demangle(name),
        addr,
        size,
        kind,
    }
}

fn section_entropy(data: &[u8], off: u64, size: u64) -> f64 {
    let start = off as usize;
    let end = start.saturating_add(size as usize).min(data.len());
    data.get(start..end).map(hash::entropy).unwrap_or(0.0)
}

// ───────────────────────────── ELF ─────────────────────────────

fn elf_arch(machine: u16, bits64: bool) -> Arch {
    use elf::header::*;
    match machine {
        EM_386 => Arch::X86,
        EM_X86_64 => Arch::X86_64,
        EM_ARM => Arch::Arm,
        EM_AARCH64 => Arch::AArch64,
        EM_MIPS if bits64 => Arch::Mips64,
        EM_MIPS => Arch::Mips,
        EM_PPC => Arch::PowerPc,
        EM_PPC64 => Arch::PowerPc64,
        EM_RISCV => Arch::RiscV,
        m => Arch::Other(format!("{} ({m})", elf::header::machine_to_str(m))),
    }
}

/// RELATIVE relocations with an explicit addend: slot address -> pointer value at load time
/// (relative to a zero load base, which is how the rest of the model addresses things).
fn elf_relative_relocs(e: &elf::Elf) -> Vec<(u64, u64)> {
    use goblin::elf::reloc::*;
    let relative = match e.header.e_machine {
        elf::header::EM_X86_64 => R_X86_64_RELATIVE,
        elf::header::EM_386 => R_386_RELATIVE,
        elf::header::EM_AARCH64 => R_AARCH64_RELATIVE,
        elf::header::EM_ARM => R_ARM_RELATIVE,
        elf::header::EM_RISCV => R_RISCV_RELATIVE,
        elf::header::EM_PPC64 => R_PPC64_RELATIVE,
        elf::header::EM_PPC => R_PPC_RELATIVE,
        _ => return Vec::new(),
    };
    let mut out: Vec<(u64, u64)> = e
        .dynrelas
        .iter()
        .filter(|r| r.r_type == relative && r.r_sym == 0)
        .filter_map(|r| Some((r.r_offset, u64::try_from(r.r_addend?).ok()?)))
        .collect();
    out.sort_unstable();
    out.dedup_by_key(|p| p.0);
    out
}

fn from_elf(e: &elf::Elf, data: &[u8]) -> Binary {
    use elf::program_header::*;
    use elf::section_header::*;

    let bits64 = e.is_64;
    let arch = elf_arch(e.header.e_machine, bits64);
    let mut sections = Vec::new();
    for sh in &e.section_headers {
        if sh.sh_type == SHT_NULL {
            continue;
        }
        let name = e.shdr_strtab.get_at(sh.sh_name).unwrap_or("").to_string();
        let file_size = if sh.sh_type == SHT_NOBITS {
            0
        } else {
            sh.sh_size
        };
        sections.push(SectionInfo {
            entropy: section_entropy(data, sh.sh_offset, file_size),
            name,
            addr: sh.sh_addr,
            size: sh.sh_size,
            offset: sh.sh_offset,
            file_size,
            perms: Perms {
                r: sh.sh_flags & SHF_ALLOC as u64 != 0,
                w: sh.sh_flags & SHF_WRITE as u64 != 0,
                x: sh.sh_flags & SHF_EXECINSTR as u64 != 0,
            },
        });
    }
    // Section headers are optional at runtime; fall back to PT_LOAD segments.
    if sections.iter().all(|s| s.addr == 0) {
        for (i, ph) in e.program_headers.iter().enumerate() {
            if ph.p_type == PT_LOAD {
                sections.push(SectionInfo {
                    entropy: section_entropy(data, ph.p_offset, ph.p_filesz),
                    name: format!("LOAD{i}"),
                    addr: ph.p_vaddr,
                    size: ph.p_memsz,
                    offset: ph.p_offset,
                    file_size: ph.p_filesz,
                    perms: Perms {
                        r: ph.p_flags & PF_R != 0,
                        w: ph.p_flags & PF_W != 0,
                        x: ph.p_flags & PF_X != 0,
                    },
                });
            }
        }
    }

    // Imports: PLT relocations give us the GOT slot for each lazily bound function.
    let mut imports = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for rel in e
        .pltrelocs
        .iter()
        .chain(e.dynrelas.iter())
        .chain(e.dynrels.iter())
    {
        if rel.r_sym == 0 {
            continue;
        }
        if let Some(s) = e.dynsyms.get(rel.r_sym) {
            if s.st_shndx != 0 {
                continue; // defined locally, not an import
            }
            let name = e.dynstrtab.get_at(s.st_name).unwrap_or("");
            if name.is_empty() || (s.st_type() != elf::sym::STT_FUNC && s.st_type() != 0) {
                continue;
            }
            if seen.insert((name.to_string(), rel.r_offset)) {
                imports.push(Import {
                    library: None,
                    name: name.to_string(),
                    slot: Some(rel.r_offset),
                });
            }
        }
    }
    // Undefined dynamic function symbols without relocations (rare, but e.g. -z now variations).
    let named: std::collections::HashSet<String> = imports.iter().map(|i| i.name.clone()).collect();
    for s in e.dynsyms.iter() {
        if s.st_shndx == 0 && s.st_type() == elf::sym::STT_FUNC {
            let name = e.dynstrtab.get_at(s.st_name).unwrap_or("");
            if !name.is_empty() && !named.contains(name) {
                imports.push(Import {
                    library: None,
                    name: name.to_string(),
                    slot: None,
                });
            }
        }
    }

    let mut symbols = Vec::new();
    let mut exports = Vec::new();
    for (tab, strtab, is_dyn) in [
        (&e.syms, &e.strtab, false),
        (&e.dynsyms, &e.dynstrtab, true),
    ] {
        for s in tab.iter() {
            if s.st_shndx == 0 || s.st_value == 0 {
                continue;
            }
            let name = strtab.get_at(s.st_name).unwrap_or("");
            if name.is_empty() {
                continue;
            }
            let kind = match s.st_type() {
                elf::sym::STT_FUNC => SymKind::Func,
                elf::sym::STT_OBJECT => SymKind::Object,
                _ => SymKind::Other,
            };
            if kind == SymKind::Other {
                continue;
            }
            let item = sym(name, s.st_value, s.st_size, kind);
            if is_dyn && s.st_bind() != elf::sym::STB_LOCAL {
                exports.push(item.clone());
            }
            symbols.push(item);
        }
    }
    symbols.sort_by_key(|s| (s.addr, s.name.clone()));
    symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
    exports.sort_by_key(|s| s.addr);
    exports.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);

    let file_type = match e.header.e_type {
        elf::header::ET_EXEC => "executable",
        elf::header::ET_DYN if e.interpreter.is_some() => "PIE executable",
        elf::header::ET_DYN => "shared library",
        elf::header::ET_REL => "relocatable object",
        elf::header::ET_CORE => "core dump",
        _ => "unknown",
    }
    .to_string();

    let mut extras = vec![(
        "OS/ABI".to_string(),
        format!("{}", e.header.e_ident[elf::header::EI_OSABI]),
    )];
    if let Some(notes) = e.iter_note_headers(data) {
        for n in notes.take(4096).map_while(|r| r.ok()) {
            if n.n_type == elf::note::NT_GNU_BUILD_ID && n.name == "GNU" {
                extras.push(("Build ID".into(), hash::hex(n.desc)));
            }
        }
    }
    if let Some(so) = e.soname {
        extras.push(("SONAME".into(), so.to_string()));
    }
    if let Some(comment) = sections.iter().find(|s| s.name == ".comment") {
        let start = comment.offset as usize;
        let end = start
            .saturating_add(comment.file_size as usize)
            .min(data.len());
        if let Some(bytes) = data.get(start..end) {
            let compilers: Vec<String> = bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<std::collections::BTreeSet<_>>()
                .into_iter()
                .collect();
            if !compilers.is_empty() {
                extras.push(("Compiler".into(), compilers.join("; ")));
            }
        }
    }
    if sections
        .iter()
        .any(|s| s.name == ".go.buildinfo" || s.name == ".gopclntab")
    {
        extras.push(("Language hint".into(), "Go".into()));
    } else if symbols
        .iter()
        .any(|s| s.name.starts_with("_ZN") && s.name.ends_with('E') && s.name.contains("17h"))
    {
        extras.push(("Language hint".into(), "Rust".into()));
    }
    if !e.rpaths.is_empty() {
        extras.push(("RPATH".into(), e.rpaths.join(":")));
    }
    if !e.runpaths.is_empty() {
        extras.push(("RUNPATH".into(), e.runpaths.join(":")));
    }

    let stripped = !e.section_headers.iter().any(|s| s.sh_type == SHT_SYMTAB);
    let slice_end = elf_end(e);
    let overlay_offset = (slice_end > 0 && (slice_end as usize) < data.len()).then_some(slice_end);

    let mut b = Binary {
        format: BinFormat::Elf,
        arch,
        bits: if bits64 { 64 } else { 32 },
        little_endian: e.little_endian,
        file_type,
        entry: e.entry,
        image_base: e
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| p.p_vaddr)
            .min()
            .unwrap_or(0),
        sections,
        imports,
        exports,
        symbols,
        libraries: e.libraries.iter().map(|s| s.to_string()).collect(),
        interpreter: e.interpreter.map(str::to_string),
        stripped,
        mitigations: Vec::new(),
        extras,
        slice_offset: 0,
        overlay_offset,
        slice_size: data.len() as u64,
        function_starts: Vec::new(),
        relocated_ptrs: elf_relative_relocs(e),
    };
    b.function_starts = elf_eh_frame_starts(&b, data);
    b.mitigations = crate::checksec::elf(e, &b, data);
    b
}

/// Function starts from `.eh_frame` FDEs. Even stripped binaries keep these,
/// because C++ exceptions and stack unwinding need them at runtime.
fn elf_eh_frame_starts(b: &Binary, data: &[u8]) -> Vec<u64> {
    use gimli::UnwindSection;
    let Some(sec) = b
        .sections
        .iter()
        .find(|s| s.name == ".eh_frame" && s.file_size > 0)
    else {
        return Vec::new();
    };
    let bytes = b.section_bytes(data, sec);
    let mut out = Vec::new();
    let mut run = |eh: gimli::EhFrame<gimli::EndianSlice<'_, gimli::RunTimeEndian>>| {
        let text = b
            .sections
            .iter()
            .find(|s| s.name == ".text")
            .map(|s| s.addr)
            .unwrap_or(0);
        let mut bases = gimli::BaseAddresses::default()
            .set_eh_frame(sec.addr)
            .set_text(text);
        if let Some(got) = b.sections.iter().find(|s| s.name == ".got") {
            bases = bases.set_got(got.addr);
        }
        let mut entries = eh.entries(&bases);
        let mut guard = 0;
        while let Ok(Some(entry)) = entries.next() {
            guard += 1;
            if guard > 1_000_000 {
                break;
            }
            if let gimli::CieOrFde::Fde(partial) = entry {
                if let Ok(fde) = partial.parse(|s, b, o| s.cie_from_offset(b, o)) {
                    let a = fde.initial_address();
                    if a != 0 {
                        out.push(a);
                    }
                }
            }
        }
    };
    let endian = if b.little_endian {
        gimli::RunTimeEndian::Little
    } else {
        gimli::RunTimeEndian::Big
    };
    let mut eh = gimli::EhFrame::new(bytes, endian);
    eh.set_address_size(b.bits / 8);
    run(eh);
    out.sort_unstable();
    out.dedup();
    out
}

fn elf_end(e: &elf::Elf) -> u64 {
    // Every field here is attacker-controlled: add without overflowing.
    let sh_end = e
        .header
        .e_shoff
        .saturating_add(e.header.e_shnum as u64 * e.header.e_shentsize as u64);
    let seg_end = e
        .program_headers
        .iter()
        .map(|p| p.p_offset.saturating_add(p.p_filesz))
        .max()
        .unwrap_or(0);
    let sec_end = e
        .section_headers
        .iter()
        .filter(|s| s.sh_type != elf::section_header::SHT_NOBITS)
        .map(|s| s.sh_offset.saturating_add(s.sh_size))
        .max()
        .unwrap_or(0);
    sh_end.max(seg_end).max(sec_end)
}

// ───────────────────────────── PE ─────────────────────────────

fn pe_arch(machine: u16) -> Arch {
    use pe::header::*;
    match machine {
        COFF_MACHINE_X86 => Arch::X86,
        COFF_MACHINE_X86_64 => Arch::X86_64,
        COFF_MACHINE_ARM | COFF_MACHINE_ARMNT => Arch::Arm,
        COFF_MACHINE_ARM64 => Arch::AArch64,
        m => Arch::Other(format!("machine {m:#x}")),
    }
}

fn from_pe(p: &pe::PE, data: &[u8]) -> Binary {
    use pe::section_table::*;
    let base = p.image_base;
    let sections: Vec<SectionInfo> = p
        .sections
        .iter()
        .map(|s| {
            let name = s
                .real_name
                .clone()
                .unwrap_or_else(|| s.name().unwrap_or("").to_string());
            let file_size = (s.size_of_raw_data as u64).min(data.len() as u64);
            SectionInfo {
                entropy: section_entropy(data, s.pointer_to_raw_data as u64, file_size),
                name,
                addr: base.wrapping_add(s.virtual_address as u64),
                size: s.virtual_size as u64,
                offset: s.pointer_to_raw_data as u64,
                file_size,
                perms: Perms {
                    r: s.characteristics & IMAGE_SCN_MEM_READ != 0,
                    w: s.characteristics & IMAGE_SCN_MEM_WRITE != 0,
                    x: s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0,
                },
            }
        })
        .collect();

    let imports = p
        .imports
        .iter()
        .map(|i| Import {
            library: Some(i.dll.to_string()),
            name: i.name.to_string(),
            slot: Some(base.wrapping_add(i.offset as u64)),
        })
        .collect();
    let exports: Vec<Symbol> = p
        .exports
        .iter()
        .filter_map(|e| {
            e.name.map(|n| {
                sym(
                    n,
                    base.wrapping_add(e.rva as u64),
                    e.size as u64,
                    SymKind::Func,
                )
            })
        })
        .collect();

    let ch = p.header.coff_header.characteristics;
    let file_type = if ch & pe::characteristic::IMAGE_FILE_DLL != 0 {
        "DLL".to_string()
    } else {
        let subsystem = p
            .header
            .optional_header
            .map(|o| o.windows_fields.subsystem)
            .unwrap_or(0);
        match subsystem {
            1 => "native / driver".into(),
            2 => "GUI executable".into(),
            3 => "console executable".into(),
            10..=13 => "EFI image".into(),
            _ => "executable".into(),
        }
    };

    let mut extras = Vec::new();
    let ts = p.header.coff_header.time_date_stamp;
    extras.push((
        "Timestamp".into(),
        format!("{ts} ({})", unix_to_utc(ts as i64)),
    ));
    if let Some(dbg) = &p.debug_data {
        if let Some(cv) = &dbg.codeview_pdb70_debug_info {
            let f = String::from_utf8_lossy(cv.filename)
                .trim_end_matches('\0')
                .to_string();
            extras.push(("PDB path".into(), f));
        }
    }
    if p.header.rich_header.is_some() {
        extras.push(("Rich header".into(), "present (MSVC toolchain)".into()));
    }
    if p.clr_data.is_some() {
        extras.push(("Runtime".into(), ".NET / CLR assembly".into()));
    }
    if let Some(name) = p.name {
        extras.push(("Export name".into(), name.to_string()));
    }

    // Overlay: data appended after the last section's raw data (installers, droppers, signatures).
    let last = p
        .sections
        .iter()
        .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
        .max()
        .unwrap_or(0);
    let cert_end = p
        .header
        .optional_header
        .and_then(|o| o.data_directories.get_certificate_table().copied())
        .filter(|d| d.virtual_address as u64 >= last && d.size > 0)
        .map(|d| d.virtual_address as u64 + d.size as u64);
    let overlay_offset = if last > 0 && (last as usize) < data.len() {
        // An Authenticode signature lives in the overlay; only report what lies beyond it.
        match cert_end {
            Some(end) if end as usize >= data.len() => None,
            Some(end) => Some(end),
            None => Some(last),
        }
    } else {
        None
    };

    let mut b = Binary {
        format: BinFormat::Pe,
        arch: pe_arch(p.header.coff_header.machine),
        bits: if p.is_64 { 64 } else { 32 },
        little_endian: true,
        file_type,
        entry: if p.entry > 0 {
            base.wrapping_add(p.entry as u64)
        } else {
            0
        },
        image_base: base,
        sections,
        imports,
        exports: exports.clone(),
        symbols: exports,
        libraries: p.libraries.iter().map(|s| s.to_string()).collect(),
        interpreter: None,
        stripped: true,
        mitigations: Vec::new(),
        extras,
        slice_offset: 0,
        overlay_offset,
        slice_size: data.len() as u64,
        function_starts: p
            .exception_data
            .as_ref()
            .map(|x| {
                x.functions()
                    .filter_map(|f| f.ok())
                    .filter(|f| f.begin_address != 0)
                    .map(|f| base.wrapping_add(f.begin_address as u64))
                    .collect()
            })
            .unwrap_or_default(),
        // PE base relocations keep the preferred-base pointer in the file, so reads are already right.
        relocated_ptrs: Vec::new(),
    };
    b.mitigations = crate::checksec::pe(p, &b);
    b
}

/// Format a unix timestamp as `YYYY-MM-DD HH:MM:SS UTC` without a date library.
pub fn unix_to_utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

// ───────────────────────────── Mach-O ─────────────────────────────

fn macho_arch(cputype: u32) -> Arch {
    use mach::constants::cputype::*;
    match cputype {
        CPU_TYPE_X86 => Arch::X86,
        CPU_TYPE_X86_64 => Arch::X86_64,
        CPU_TYPE_ARM => Arch::Arm,
        CPU_TYPE_ARM64 | CPU_TYPE_ARM64_32 => Arch::AArch64,
        CPU_TYPE_POWERPC => Arch::PowerPc,
        CPU_TYPE_POWERPC64 => Arch::PowerPc64,
        c => Arch::Other(format!("cputype {c:#x}")),
    }
}

/// More binds than any real program has; a crafted file asks for billions.
const MAX_MACHO_BINDS: u64 = 2_000_000;

/// Count the binds the dyld bind opcode streams would perform, without performing them.
///
/// goblin's bind interpreter expands `BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB` by pushing one
/// import per repetition, so a single opcode with a huge count exhausts memory (a fuzzed 16 KB file
/// did). Streams are finite, so summing the counts is cheap and bounds the real work.
fn macho_bind_count(m: &mach::MachO, data: &[u8], slice_offset: u64) -> u64 {
    use mach::load_command::CommandVariant;
    let Some(info) = m.load_commands.iter().find_map(|lc| match &lc.command {
        CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => Some(*c),
        _ => None,
    }) else {
        return 0;
    };
    let uleb = |d: &[u8], at: &mut usize| -> u64 {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let Some(&b) = d.get(*at) else { return v };
            *at += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                break;
            }
        }
        v
    };
    // Mirror goblin: only opcode *starts* are bounded by the stream; operands are read from the
    // whole slice, so a ULEB count that straddles the stream end is still read in full.
    let d = data.get(slice_offset as usize..).unwrap_or_default();
    let mut total = 0u64;
    for (off, size) in [
        (info.bind_off, info.bind_size),
        (info.weak_bind_off, info.weak_bind_size),
        (info.lazy_bind_off, info.lazy_bind_size),
    ] {
        let mut at = off as usize;
        let end = at.saturating_add(size as usize).min(d.len());
        while at < end {
            let op = d[at] & 0xf0;
            at += 1;
            match op {
                // ULEB or SLEB operand; skipping its bytes is the same either way.
                0x20 | 0x50 | 0x60 | 0x70 | 0x80 => {
                    uleb(d, &mut at);
                }
                0x40 => {
                    at += d[at.min(d.len())..]
                        .iter()
                        .position(|&b| b == 0)
                        .map_or(d.len(), |n| n + 1);
                }
                0x90 | 0xb0 => total += 1,
                0xa0 => {
                    uleb(d, &mut at);
                    total += 1;
                }
                0xc0 => {
                    total = total.saturating_add(uleb(d, &mut at));
                    uleb(d, &mut at);
                }
                _ => {}
            }
            if total > MAX_MACHO_BINDS {
                return total;
            }
        }
    }
    total
}

/// Exported symbols from the dyld export trie, as (name, offset from the `__TEXT` base).
///
/// goblin's own walker follows child edges without remembering where it has been, so a trie whose
/// nodes point back at each other makes it allocate until the process dies (an 18 KB file took
/// 3 GB). This reader visits each node once and caps the work.
fn macho_export_trie(m: &mach::MachO, data: &[u8], slice_offset: u64) -> Vec<(String, u64)> {
    use mach::load_command::CommandVariant;
    const MAX_NODES: usize = 200_000;
    const MAX_NAME: usize = 4096;
    let (off, size) = match m.load_commands.iter().find_map(|lc| match &lc.command {
        CommandVariant::DyldInfo(c) | CommandVariant::DyldInfoOnly(c) => {
            Some((c.export_off as u64, c.export_size as u64))
        }
        CommandVariant::DyldExportsTrie(c) => Some((c.dataoff as u64, c.datasize as u64)),
        _ => None,
    }) {
        Some(x) => x,
        None => return Vec::new(),
    };
    let start = slice_offset.saturating_add(off) as usize;
    let Some(trie) = data.get(start..start.saturating_add(size as usize).min(data.len())) else {
        return Vec::new();
    };
    fn uleb(t: &[u8], at: &mut usize) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = *t.get(*at)?;
            *at += 1;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }
    // Budget the whole walk, not just the node count: each node can queue up to 255 children,
    // so also cap the queued work and the bytes of name prefixes held at once.
    const MAX_PENDING: usize = 100_000;
    const MAX_PREFIX_BYTES: usize = 16 << 20;
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack: Vec<(usize, String)> = vec![(0, String::new())];
    let mut held = 0usize;
    while let Some((node, prefix)) = stack.pop() {
        held -= prefix.len();
        if seen.len() >= MAX_NODES || !seen.insert(node) {
            continue;
        }
        let mut at = node;
        let Some(terminal) = uleb(trie, &mut at) else {
            continue;
        };
        let children_at = at.saturating_add(terminal as usize);
        if terminal > 0 {
            let flags = uleb(trie, &mut at).unwrap_or(0);
            // Re-exports name another dylib's symbol and carry no address of their own.
            if flags & 0x08 == 0 {
                if let Some(addr) = uleb(trie, &mut at) {
                    out.push((prefix.clone(), addr));
                }
            }
        }
        let mut at = children_at;
        let Some(&count) = trie.get(at) else { continue };
        at += 1;
        for _ in 0..count {
            let Some(len) = trie.get(at..).and_then(|r| r.iter().position(|&b| b == 0)) else {
                break;
            };
            let edge = String::from_utf8_lossy(&trie[at..at + len]);
            at += len + 1;
            let Some(child) = uleb(trie, &mut at) else {
                break;
            };
            let child = child as usize;
            let name_len = prefix.len() + edge.len();
            if seen.contains(&child)
                || name_len > MAX_NAME
                || stack.len() >= MAX_PENDING
                || held + name_len > MAX_PREFIX_BYTES
            {
                continue;
            }
            held += name_len;
            stack.push((child, format!("{prefix}{edge}")));
        }
    }
    out.sort();
    out
}

fn from_macho(m: &mach::MachO, data: &[u8], slice_offset: u64, slice_size: u64) -> Binary {
    let mut sections = Vec::new();
    for seg in m.segments.iter() {
        let segname = seg.name().unwrap_or("?").to_string();
        let perms = Perms {
            r: seg.initprot & 1 != 0,
            w: seg.initprot & 2 != 0,
            x: seg.initprot & 4 != 0,
        };
        if let Ok(secs) = seg.sections() {
            for (s, _) in secs {
                let sname = s.name().unwrap_or("?");
                // S_ZEROFILL (1), S_GB_ZEROFILL (12), S_THREAD_LOCAL_ZEROFILL (18) have no file bytes.
                let zerofill = matches!(s.flags & 0xff, 1 | 12 | 18);
                let file_size = if zerofill || s.offset == 0 { 0 } else { s.size };
                // S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS: __TEXT holds
                // read-only data too (__cstring, __const), which is not code.
                let has_code = s.flags & 0x8000_0400 != 0;
                sections.push(SectionInfo {
                    entropy: section_entropy(data, s.offset as u64, file_size),
                    name: format!("{segname},{sname}"),
                    addr: s.addr,
                    size: s.size,
                    offset: s.offset as u64,
                    file_size,
                    perms: Perms {
                        x: perms.x && has_code,
                        ..perms
                    },
                });
            }
        }
    }

    let goblin_imports = if macho_bind_count(m, data, slice_offset) <= MAX_MACHO_BINDS {
        m.imports().unwrap_or_default()
    } else {
        Vec::new()
    };
    let imports: Vec<Import> = goblin_imports
        .into_iter()
        .map(|i| Import {
            library: Some(i.dylib.to_string()),
            name: i.name.trim_start_matches('_').to_string(),
            slot: Some(i.address),
        })
        .collect();

    let mut symbols = Vec::new();
    if let Some(syms) = &m.symbols {
        // nsyms comes from the file; stop at the first entry that cannot be read instead of
        // skipping billions of failing reads (a fuzzed 16 KB file took 25 s).
        for (name, nl) in syms.iter().take(data.len() / 12).map_while(|r| r.ok()) {
            if nl.is_stab()
                || nl.is_undefined()
                || nl.get_type() != mach::symbols::N_SECT
                || name.is_empty()
            {
                continue;
            }
            let kind = sections
                .get(nl.n_sect.saturating_sub(1))
                .map(|s: &SectionInfo| {
                    if s.perms.x {
                        SymKind::Func
                    } else {
                        SymKind::Object
                    }
                })
                .unwrap_or(SymKind::Other);
            symbols.push(sym(name, nl.n_value, 0, kind));
        }
    }
    symbols.sort_by_key(|s| s.addr);
    symbols.dedup_by(|a, b| a.addr == b.addr && a.name == b.name);
    // Mach-O symbols carry no size; infer from the next symbol in the same section.
    for i in 0..symbols.len() {
        if let Some(next) = symbols.get(i + 1).map(|s| s.addr) {
            let cur = symbols[i].addr;
            let same_sec = sections
                .iter()
                .any(|s| s.contains(cur) && s.contains(next.saturating_sub(1)));
            if same_sec && next > cur {
                symbols[i].size = next - cur;
            }
        }
    }
    let text_base = m
        .segments
        .iter()
        .find(|s| s.name().ok() == Some("__TEXT"))
        .map(|s| s.vmaddr)
        .unwrap_or(0);
    let exports: Vec<Symbol> = macho_export_trie(m, data, slice_offset)
        .into_iter()
        .map(|(name, off)| sym(&name, text_base.wrapping_add(off), 0, SymKind::Func))
        .collect();

    use mach::header::*;
    let file_type = match m.header.filetype {
        MH_EXECUTE => "executable",
        MH_DYLIB => "dynamic library",
        MH_BUNDLE => "bundle",
        MH_OBJECT => "object",
        MH_KEXT_BUNDLE => "kernel extension",
        MH_DYLINKER => "dynamic linker",
        _ => "unknown",
    }
    .to_string();

    let mut extras = Vec::new();
    for lc in &m.load_commands {
        if let mach::load_command::CommandVariant::Uuid(u) = &lc.command {
            extras.push(("UUID".into(), hash::hex(&u.uuid)));
        }
    }
    if !m.rpaths.is_empty() {
        extras.push(("RPATH".into(), m.rpaths.join(":")));
    }

    // goblin already maps LC_MAIN's file offset to a virtual address.
    let entry = m.entry;

    let mut b = Binary {
        format: BinFormat::MachO,
        arch: macho_arch(m.header.cputype),
        bits: if m.is_64 { 64 } else { 32 },
        little_endian: m.little_endian,
        file_type,
        entry,
        image_base: m
            .segments
            .iter()
            .find(|s| s.name().ok() == Some("__TEXT"))
            .map(|s| s.vmaddr)
            .unwrap_or(0),
        sections,
        imports,
        exports,
        stripped: symbols.is_empty(),
        symbols,
        libraries: m
            .libs
            .iter()
            .filter(|l| **l != "self")
            .map(|s| s.to_string())
            .collect(),
        interpreter: None,
        mitigations: Vec::new(),
        extras,
        slice_offset,
        overlay_offset: None,
        slice_size,
        function_starts: macho_function_starts(m, data),
        relocated_ptrs: Vec::new(),
    };
    b.mitigations = crate::checksec::macho(m, &b, data);
    b
}

/// Decode `LC_FUNCTION_STARTS`: ULEB128 deltas from the start of `__TEXT`.
fn macho_function_starts(m: &mach::MachO, data: &[u8]) -> Vec<u64> {
    let text = m
        .segments
        .iter()
        .find(|s| s.name().ok() == Some("__TEXT"))
        .map(|s| s.vmaddr)
        .unwrap_or(0);
    let mut out = Vec::new();
    for lc in &m.load_commands {
        if let mach::load_command::CommandVariant::FunctionStarts(fs) = &lc.command {
            let start = fs.dataoff as usize;
            let Some(bytes) = data.get(start..start.saturating_add(fs.datasize as usize)) else {
                continue;
            };
            let mut addr = text;
            let mut i = 0;
            while i < bytes.len() {
                let (mut delta, mut shift) = (0u64, 0u32);
                while i < bytes.len() {
                    let b = bytes[i];
                    i += 1;
                    if shift < 64 {
                        delta |= ((b & 0x7f) as u64) << shift;
                    }
                    shift += 7;
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                if delta == 0 {
                    break;
                }
                addr += delta;
                out.push(addr);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(unix_to_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(unix_to_utc(1_700_000_000), "2023-11-14 22:13:20 UTC");
    }

    #[test]
    fn demangles() {
        assert_eq!(demangle("_ZN3foo3barEv").as_deref(), Some("foo::bar()"));
        assert_eq!(
            demangle("_ZN3std2rt10lang_start17h0123456789abcdefE").as_deref(),
            Some("std::rt::lang_start")
        );
        assert_eq!(demangle("_Z3addii").as_deref(), Some("add(int, int)"));
        assert_eq!(demangle("__Z3addii").as_deref(), Some("add(int, int)"));
        assert_eq!(demangle("main"), None);
    }

    #[test]
    fn rejects_garbage() {
        assert!(Binary::parse(b"not a binary at all").is_err());
        assert!(Binary::parse(b"\x7fELF\x02\x01\x01").is_err());
    }
}
