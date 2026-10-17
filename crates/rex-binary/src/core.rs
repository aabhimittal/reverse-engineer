//! Linux ELF core dumps (`ET_CORE`).
//!
//! A core has no sections and no code to recover: it is the crashed process's memory (one
//! `PT_LOAD` per mapping, often with no file bytes for pages the kernel skipped) plus a
//! `PT_NOTE` segment the kernel fills with the crash context:
//!
//! * `NT_PRSTATUS`, one per thread, the crashing thread first: pid and the general registers.
//! * `NT_SIGINFO`: the signal, its `si_code` and the faulting address.
//! * `NT_PRPSINFO`: the command name and its arguments.
//! * `NT_AUXV`: what the kernel told the program at exec (entry point, executable path, …).
//! * `NT_FILE`: which file backs each mapping, so addresses resolve to `module+offset`.
//!
//! Every read is bounds-checked; all counts and sizes come from the file.

use goblin::elf;
use serde::Serialize;

const MAX_THREADS: usize = 4096;
const MAX_MAPPINGS: usize = 65536;
const MAX_NOTES: usize = 1 << 20;

const NT_PRSTATUS: u32 = 1;
const NT_PRPSINFO: u32 = 3;
const NT_AUXV: u32 = 6;
const NT_SIGINFO: u32 = 0x5349_4749;
const NT_FILE: u32 = 0x4649_4c45;

const X86_64_REGS: &[&str] = &[
    "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi",
    "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs",
    "gs",
];
const AARCH64_REGS: &[&str] = &[
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10", "x11", "x12", "x13", "x14",
    "x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24", "x25", "x26", "x27",
    "x28", "x29", "x30", "sp", "pc", "pstate",
];

/// What the core says about the crash.
#[derive(Debug, Clone, Default, Serialize)]
pub struct CoreInfo {
    /// Signal that killed the process (0 if the notes don't say).
    pub signal: u32,
    /// `SIGSEGV`, `SIGABRT`, …
    pub signal_name: String,
    /// `si_code` (why the signal was sent), from `NT_SIGINFO`.
    pub si_code: Option<i32>,
    /// Faulting address, for SIGSEGV/SIGBUS/SIGILL/SIGFPE.
    pub fault_addr: Option<u64>,
    /// Process id.
    pub pid: Option<u32>,
    /// Threads, crashing thread first (kernel order).
    pub threads: Vec<Thread>,
    /// File-backed mappings from `NT_FILE`.
    pub mappings: Vec<FileMapping>,
    /// Memory segments (`PT_LOAD`).
    pub segments: Vec<Segment>,
    /// Command name (`pr_fname`).
    pub command: Option<String>,
    /// Command line (`pr_psargs`, truncated by the kernel to 80 bytes).
    pub args: Option<String>,
    /// Auxiliary vector entries.
    pub auxv: Auxv,
}

/// One thread's registers (`NT_PRSTATUS`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Thread {
    /// Thread id.
    pub tid: u32,
    /// Signal pending on this thread (`pr_cursig`).
    pub signal: u32,
    /// Program counter (x86-64 and AArch64 only).
    pub pc: Option<u64>,
    /// Stack pointer (x86-64 and AArch64 only).
    pub sp: Option<u64>,
    /// General registers in kernel order.
    pub regs: Vec<(&'static str, u64)>,
}

/// A file mapped into the process (`NT_FILE`).
#[derive(Debug, Clone, Serialize)]
pub struct FileMapping {
    /// Start address.
    pub start: u64,
    /// End address (exclusive).
    pub end: u64,
    /// Offset of `start` in the file.
    pub file_offset: u64,
    /// Path of the file.
    pub path: String,
}

/// A memory segment of the dump.
#[derive(Debug, Clone, Serialize)]
pub struct Segment {
    /// Virtual address.
    pub vaddr: u64,
    /// Size in memory.
    pub memsz: u64,
    /// File offset of the dumped bytes.
    pub offset: u64,
    /// Bytes present in the file (0 when the kernel skipped the pages).
    pub filesz: u64,
    /// `PF_X`.
    pub exec: bool,
    /// `PF_W`.
    pub write: bool,
}

/// Selected auxiliary vector entries (`NT_AUXV`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Auxv {
    /// `AT_ENTRY`: program entry point.
    pub entry: Option<u64>,
    /// `AT_PHDR`: program headers in memory.
    pub phdr: Option<u64>,
    /// `AT_EXECFN`: address of the executable path string.
    pub execfn_addr: Option<u64>,
    /// `AT_EXECFN` resolved from the dumped memory.
    pub execfn: Option<String>,
    /// `AT_HWCAP`: CPU feature bits.
    pub hwcap: Option<u64>,
    /// `AT_PAGESZ`.
    pub page_size: Option<u64>,
}

impl CoreInfo {
    /// The thread that received the signal (the first with `pr_cursig` set, else the first).
    pub fn crashing_thread(&self) -> Option<&Thread> {
        self.threads
            .iter()
            .find(|t| t.signal != 0 && t.signal == self.signal)
            .or_else(|| self.threads.first())
    }

    /// `len` dumped bytes at `addr`, if the file holds them.
    pub fn read<'a>(&self, data: &'a [u8], addr: u64, len: usize) -> Option<&'a [u8]> {
        let s = self.segments.iter().find(|s| {
            addr >= s.vaddr
                && addr - s.vaddr < s.filesz
                && s.filesz - (addr - s.vaddr) >= len as u64
        })?;
        let start = usize::try_from(s.offset.checked_add(addr - s.vaddr)?).ok()?;
        data.get(start..start.checked_add(len)?)
    }

    /// Is `addr` inside an executable segment?
    pub fn is_exec(&self, addr: u64) -> bool {
        self.segments
            .iter()
            .any(|s| s.exec && addr >= s.vaddr && addr - s.vaddr < s.memsz)
    }

    /// The file mapping holding `addr`.
    pub fn mapping(&self, addr: u64) -> Option<&FileMapping> {
        self.mappings
            .iter()
            .find(|m| addr >= m.start && addr < m.end)
    }

    /// `module+0xoff` (offset into the file) for an address in a file mapping.
    pub fn symbolize(&self, addr: u64) -> Option<String> {
        let m = self.mapping(addr)?;
        let base = m.path.rsplit('/').next().unwrap_or(&m.path);
        Some(format!(
            "{base}+{:#x}",
            (addr - m.start).wrapping_add(m.file_offset)
        ))
    }

    /// Executable path: `AT_EXECFN`, else the first word of the command line, else `pr_fname`.
    pub fn executable(&self) -> Option<&str> {
        self.auxv
            .execfn
            .as_deref()
            .or_else(|| {
                self.args
                    .as_deref()
                    .and_then(|a| a.split_whitespace().next())
            })
            .or(self.command.as_deref())
    }
}

/// Little/big-endian reads that return `None` past the end.
#[derive(Clone, Copy)]
struct Rd<'a> {
    d: &'a [u8],
    le: bool,
}

impl Rd<'_> {
    fn u16(&self, at: usize) -> Option<u16> {
        let b: [u8; 2] = self.d.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(if self.le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }
    fn u32(&self, at: usize) -> Option<u32> {
        let b: [u8; 4] = self.d.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(if self.le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }
    fn u64(&self, at: usize) -> Option<u64> {
        let b: [u8; 8] = self.d.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if self.le {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }
    /// A pointer-sized word.
    fn word(&self, at: usize, is64: bool) -> Option<u64> {
        if is64 {
            self.u64(at)
        } else {
            self.u32(at).map(u64::from)
        }
    }
}

/// NUL-terminated string, lossily decoded.
fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Read one pointer-sized word from the dump.
pub fn read_word(core: &CoreInfo, data: &[u8], addr: u64, is64: bool, le: bool) -> Option<u64> {
    let n = if is64 { 8 } else { 4 };
    Rd {
        d: core.read(data, addr, n)?,
        le,
    }
    .word(0, is64)
}

/// Iterate the notes of one `PT_NOTE` segment: (owner, type, desc).
fn notes(seg: &[u8], le: bool) -> impl Iterator<Item = (&[u8], u32, &[u8])> {
    let r = Rd { d: seg, le };
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let namesz = r.u32(at)? as usize;
        let descsz = r.u32(at + 4)? as usize;
        let ty = r.u32(at + 8)?;
        let name_at = at.checked_add(12)?;
        let desc_at = name_at.checked_add(namesz.checked_add(3)? & !3)?;
        let name = seg.get(name_at..name_at.checked_add(namesz)?)?;
        let desc = seg.get(desc_at..desc_at.checked_add(descsz)?)?;
        at = desc_at.checked_add(descsz.checked_add(3)? & !3)?;
        let owner = name.split(|&c| c == 0).next().unwrap_or(name);
        Some((owner, ty, desc))
    })
    .take(MAX_NOTES)
}

/// Parse the crash context of an `ET_CORE` file.
pub fn parse(e: &elf::Elf, data: &[u8]) -> CoreInfo {
    use elf::program_header::{PF_W, PF_X, PT_LOAD, PT_NOTE};

    let le = e.little_endian;
    let is64 = e.is_64;
    let machine = e.header.e_machine;
    let mut c = CoreInfo {
        segments: e
            .program_headers
            .iter()
            .filter(|p| p.p_type == PT_LOAD)
            .map(|p| Segment {
                vaddr: p.p_vaddr,
                memsz: p.p_memsz,
                offset: p.p_offset,
                // Never trust a segment to hold more bytes than the file does.
                filesz: p
                    .p_filesz
                    .min((data.len() as u64).saturating_sub(p.p_offset)),
                exec: p.p_flags & PF_X != 0,
                write: p.p_flags & PF_W != 0,
            })
            .collect(),
        ..Default::default()
    };

    for ph in e.program_headers.iter().filter(|p| p.p_type == PT_NOTE) {
        let Some(seg) = usize::try_from(ph.p_offset)
            .ok()
            .and_then(|o| data.get(o..o.saturating_add(ph.p_filesz as usize).min(data.len())))
        else {
            continue;
        };
        for (owner, ty, desc) in notes(seg, le) {
            if owner != b"CORE" {
                continue;
            }
            let r = Rd { d: desc, le };
            match ty {
                NT_PRSTATUS if c.threads.len() < MAX_THREADS => {
                    // elf_prstatus: pr_info (3 ints), pr_cursig, sigpend/sighold (2 longs), pid…
                    let pid_at = if is64 { 32 } else { 24 };
                    let mut t = Thread {
                        tid: r.u32(pid_at).unwrap_or(0),
                        signal: r.u16(12).map(u32::from).unwrap_or(0),
                        ..Default::default()
                    };
                    if c.pid.is_none() {
                        c.pid = Some(t.tid);
                    }
                    if c.signal == 0 {
                        c.signal = t.signal;
                    }
                    // pr_reg follows the four timevals at 112 (64-bit only).
                    let names = match machine {
                        elf::header::EM_X86_64 if is64 => X86_64_REGS,
                        elf::header::EM_AARCH64 if is64 => AARCH64_REGS,
                        _ => &[],
                    };
                    for (i, n) in names.iter().enumerate() {
                        match r.u64(112 + 8 * i) {
                            Some(v) => t.regs.push((*n, v)),
                            None => break,
                        }
                    }
                    let reg = |n: &str| t.regs.iter().find(|(k, _)| *k == n).map(|(_, v)| *v);
                    (t.pc, t.sp) = match machine {
                        elf::header::EM_X86_64 => (reg("rip"), reg("rsp")),
                        elf::header::EM_AARCH64 => (reg("pc"), reg("sp")),
                        _ => (None, None),
                    };
                    c.threads.push(t);
                }
                NT_SIGINFO => {
                    // siginfo_t: si_signo, si_errno, si_code, then (after padding to a word on
                    // 64-bit) the union whose first member is si_addr for fault signals.
                    if let Some(s) = r.u32(0).filter(|&s| s != 0) {
                        c.signal = s;
                    }
                    c.si_code = r.u32(8).map(|v| v as i32);
                    if matches!(c.signal, 4 | 7 | 8 | 11) {
                        c.fault_addr = r.word(if is64 { 16 } else { 12 }, is64);
                    }
                }
                NT_PRPSINFO if is64 => {
                    c.command = desc.get(40..56).map(cstr).filter(|s| !s.is_empty());
                    c.args = desc
                        .get(56..136)
                        .map(|b| cstr(b).trim_end().to_string())
                        .filter(|s| !s.is_empty());
                }
                NT_AUXV if is64 => {
                    for i in 0..desc.len() / 16 {
                        let (Some(k), Some(v)) = (r.u64(16 * i), r.u64(16 * i + 8)) else {
                            break;
                        };
                        match k {
                            0 => break,
                            3 => c.auxv.phdr = Some(v),
                            6 => c.auxv.page_size = Some(v),
                            9 => c.auxv.entry = Some(v),
                            16 => c.auxv.hwcap = Some(v),
                            31 => c.auxv.execfn_addr = Some(v),
                            _ => {}
                        }
                    }
                }
                NT_FILE if is64 => c.mappings = nt_file(r),
                _ => {}
            }
        }
    }
    if let Some(addr) = c.auxv.execfn_addr {
        c.auxv.execfn = execfn(&c, data, addr);
    }
    c.signal_name = signal_name(c.signal).to_string();
    c
}

/// `NT_FILE`: count, page size, `count` × (start, end, page offset), then `count` paths.
fn nt_file(r: Rd) -> Vec<FileMapping> {
    let (Some(count), Some(page)) = (r.u64(0), r.u64(8)) else {
        return Vec::new();
    };
    let count = (count as usize)
        .min(MAX_MAPPINGS)
        .min(r.d.len().saturating_sub(16) / 24);
    let mut paths =
        r.d.get(16 + 24 * count..)
            .unwrap_or_default()
            .split(|&b| b == 0);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let at = 16 + 24 * i;
        let (Some(start), Some(end), Some(pgoff)) = (r.u64(at), r.u64(at + 8), r.u64(at + 16))
        else {
            break;
        };
        out.push(FileMapping {
            start,
            end,
            file_offset: pgoff.wrapping_mul(page),
            path: paths
                .next()
                .map(|p| String::from_utf8_lossy(p).into_owned())
                .unwrap_or_default(),
        });
    }
    out
}

/// The `AT_EXECFN` string, when its page was dumped.
fn execfn(c: &CoreInfo, data: &[u8], addr: u64) -> Option<String> {
    let s = c
        .segments
        .iter()
        .find(|s| addr >= s.vaddr && addr - s.vaddr < s.filesz)?;
    let start = usize::try_from(s.offset.checked_add(addr - s.vaddr)?).ok()?;
    let avail = usize::try_from(s.filesz - (addr - s.vaddr)).ok()?.min(4096);
    let b = data.get(start..start.checked_add(avail)?)?;
    b.contains(&0).then(|| cstr(b)).filter(|s| !s.is_empty())
}

/// Linux signal name (generic numbering, as on x86 and ARM).
pub fn signal_name(sig: u32) -> &'static str {
    const NAMES: [&str; 32] = [
        "",
        "SIGHUP",
        "SIGINT",
        "SIGQUIT",
        "SIGILL",
        "SIGTRAP",
        "SIGABRT",
        "SIGBUS",
        "SIGFPE",
        "SIGKILL",
        "SIGUSR1",
        "SIGSEGV",
        "SIGUSR2",
        "SIGPIPE",
        "SIGALRM",
        "SIGTERM",
        "SIGSTKFLT",
        "SIGCHLD",
        "SIGCONT",
        "SIGSTOP",
        "SIGTSTP",
        "SIGTTIN",
        "SIGTTOU",
        "SIGURG",
        "SIGXCPU",
        "SIGXFSZ",
        "SIGVTALRM",
        "SIGPROF",
        "SIGWINCH",
        "SIGIO",
        "SIGPWR",
        "SIGSYS",
    ];
    NAMES.get(sig as usize).copied().unwrap_or("")
}

/// What a signal means for a crash.
pub fn signal_meaning(sig: u32) -> &'static str {
    match sig {
        3 => "quit requested (core on demand)",
        4 => "illegal instruction",
        5 => "trace/breakpoint trap",
        6 => "abort (abort(), failed assertion or detected heap corruption)",
        7 => "bus error (misaligned or nonexistent physical address)",
        8 => "arithmetic exception (e.g. division by zero)",
        11 => "invalid memory reference",
        24 => "CPU time limit exceeded",
        25 => "file size limit exceeded",
        31 => "bad system call (seccomp filter or invalid syscall)",
        _ => "",
    }
}

/// What `si_code` means for a given signal.
pub fn si_code_meaning(sig: u32, code: i32) -> &'static str {
    match (sig, code) {
        (_, 0) => "SI_USER: sent by kill()",
        (_, -6) => "SI_TKILL: sent by tkill()/raise()",
        (_, 0x80) => "SI_KERNEL: sent by the kernel",
        (11, 1) => "SEGV_MAPERR: address not mapped",
        (11, 2) => "SEGV_ACCERR: invalid permissions for mapped object",
        (11, 3) => "SEGV_BNDERR: failed address bound checks",
        (11, 4) => "SEGV_PKUERR: protection key violation",
        (11, 10) => "SEGV_CPERR: control protection fault (shadow stack / IBT)",
        (7, 1) => "BUS_ADRALN: invalid address alignment",
        (7, 2) => "BUS_ADRERR: nonexistent physical address",
        (7, 3) => "BUS_OBJERR: object-specific hardware error",
        (4, 1) => "ILL_ILLOPC: illegal opcode",
        (4, 2) => "ILL_ILLOPN: illegal operand",
        (4, 5) => "ILL_PRVOPC: privileged opcode",
        (8, 1) => "FPE_INTDIV: integer divide by zero",
        (8, 2) => "FPE_INTOVF: integer overflow",
        _ => "",
    }
}
