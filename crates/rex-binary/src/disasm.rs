//! Instruction decoding.
//!
//! x86 / x86-64 decoding is built in (pure Rust, via `iced-x86`). Other
//! architectures use Capstone when the `multiarch` feature is enabled.
//!
//! Analogy: a disassembler is a *phrasebook*. The CPU speaks in bytes;
//! decoding turns `48 89 e5` into `mov rbp, rsp`. What it cannot tell you on
//! its own is *which* bytes are code: that is the job of
//! [`crate::functions`], which follows control flow like a reader following
//! "turn to page 42" instructions in a choose-your-own-adventure book.

use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, IntelFormatter, OpKind, Register,
    SymbolResolver, SymbolResult,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;

/// Where control goes after an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum Flow {
    /// Falls through to the next instruction.
    Next,
    /// Unconditional direct jump.
    Jump(u64),
    /// Conditional direct jump (falls through when not taken).
    CondJump(u64),
    /// Direct call.
    Call(u64),
    /// Indirect jump; `Some(slot)` when it reads a known memory slot (IAT/GOT).
    IndirectJump(Option<u64>),
    /// Indirect call; `Some(slot)` when it reads a known memory slot (IAT/GOT).
    IndirectCall(Option<u64>),
    /// Return.
    Return,
    /// Stops execution (`hlt`, `ud2`, `int3`).
    Halt,
}

impl Flow {
    /// Does this instruction end a basic block?
    pub fn ends_block(self) -> bool {
        !matches!(self, Flow::Next | Flow::Call(_) | Flow::IndirectCall(_))
    }
}

/// A decoded instruction.
#[derive(Debug, Clone, Serialize)]
pub struct Insn {
    /// Address.
    pub addr: u64,
    /// Raw bytes.
    #[serde(serialize_with = "ser_hex")]
    pub bytes: Vec<u8>,
    /// Mnemonic (lower case).
    pub mnemonic: String,
    /// Full Intel-syntax text.
    pub text: String,
    /// Control flow.
    pub flow: Flow,
    /// Data address referenced (RIP-relative or absolute memory operand, or address-like immediate).
    pub data_ref: Option<u64>,
}

fn ser_hex<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&rex_core::hash::hex(b))
}

impl Insn {
    /// Length in bytes.
    pub fn len(&self) -> u64 {
        self.bytes.len() as u64
    }
    /// Never empty for decoded instructions.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// Address of the next instruction.
    pub fn next(&self) -> u64 {
        self.addr + self.len()
    }
}

/// Address → name table shared with the formatter.
#[derive(Debug, Clone, Default)]
pub struct Names(pub Arc<HashMap<u64, String>>);

struct Resolver(Arc<HashMap<u64, String>>);

impl SymbolResolver for Resolver {
    fn symbol(
        &mut self,
        _instruction: &Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<SymbolResult<'_>> {
        self.0
            .get(&address)
            .map(|n| SymbolResult::with_str(address, n.as_str()))
    }
}

/// A decoder that function discovery can drive, whatever the CPU.
///
/// Discovery needs three things: decode one instruction at an address, sweep a short stretch
/// linearly (PLT stubs, `_start`), and forget per-path state when it starts following a new path.
pub trait CodeDecoder {
    /// Decode a single instruction at `addr` from `bytes` (which start at `addr`).
    fn decode_one(&mut self, bytes: &[u8], addr: u64) -> Option<Insn>;
    /// Linear sweep of up to `max` instructions.
    fn linear(&mut self, bytes: &[u8], addr: u64, max: usize) -> Vec<Insn>;
    /// Longest instruction in bytes (how much to hand `decode_one`).
    fn max_insn_len(&self) -> usize;
    /// Drop per-path register state before following a new path.
    fn reset(&mut self) {}
    /// Turn a code pointer (a symbol value, a pointer read from memory) into an instruction
    /// address. On 32-bit ARM bit 0 of a code pointer selects Thumb: the decoder notes the mode
    /// and returns the address with the bit cleared.
    fn code_addr(&mut self, ptr: u64) -> u64 {
        ptr
    }
    /// Whether the code at `addr` is Thumb (32-bit ARM only).
    fn is_thumb(&self, addr: u64) -> bool {
        let _ = addr;
        false
    }
}

impl CodeDecoder for X86 {
    fn decode_one(&mut self, bytes: &[u8], addr: u64) -> Option<Insn> {
        X86::decode_one(self, bytes, addr)
    }
    fn linear(&mut self, bytes: &[u8], addr: u64, max: usize) -> Vec<Insn> {
        X86::linear(self, bytes, addr, max)
    }
    fn max_insn_len(&self) -> usize {
        16
    }
}

/// Pick the decoder for a binary, or `None` when its CPU has only linear disassembly.
///
/// x86 is built in. AArch64 and 32-bit ARM (ARM and Thumb) need the `multiarch` feature. `data`
/// is the file; 32-bit ARM keeps a copy of its code sections to read literal pools.
pub fn decoder_for(
    bin: &crate::model::Binary,
    data: &[u8],
    names: &Names,
) -> Option<Box<dyn CodeDecoder>> {
    use crate::model::Arch;
    let _ = data;
    match &bin.arch {
        Arch::X86 | Arch::X86_64 => Some(Box::new(X86::new(bin.bits, names))),
        #[cfg(feature = "multiarch")]
        Arch::AArch64 if bin.little_endian => Cs::new(true).map(|d| Box::new(d) as _),
        #[cfg(feature = "multiarch")]
        Arch::Arm if bin.little_endian => Cs::arm32(bin, data).map(|d| Box::new(d) as _),
        _ => None,
    }
}

/// Capstone-backed decoder for ARM encodings, with flow recovered by [`crate::arm`].
#[cfg(feature = "multiarch")]
pub struct Cs {
    cs: capstone::Capstone,
    a64: bool,
    tracker: crate::arm::Tracker,
    /// 32-bit ARM only: the Thumb decoder, and the instruction set by address.
    thumb: Option<ArmState>,
}

/// What a 32-bit ARM decoder knows beyond one instruction.
#[cfg(feature = "multiarch")]
struct ArmState {
    cs: capstone::Capstone,
    /// From each address on: ARM (`'a'`), Thumb (`'t'`) or data (`'d'`).
    modes: std::collections::BTreeMap<u64, char>,
    /// The map came from mapping symbols, which cover every byte; don't add guesses to it.
    complete: bool,
    mem: ArmMem,
}

/// Code bytes (for literal pools) and the data ranges of a 32-bit ARM image.
#[cfg(feature = "multiarch")]
struct ArmMem {
    code: Vec<(u64, Vec<u8>)>,
    data: Vec<(u64, u64)>,
}

#[cfg(feature = "multiarch")]
impl crate::arm::Mem for ArmMem {
    fn word(&self, addr: u64) -> Option<u32> {
        let (start, bytes) = self
            .code
            .iter()
            .find(|(s, b)| addr >= *s && addr < s.saturating_add(b.len() as u64))?;
        let off = (addr - start) as usize;
        let w = bytes.get(off..off.checked_add(4)?)?;
        Some(u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
    }
    fn is_data(&self, addr: u64) -> bool {
        self.data.iter().any(|&(s, e)| addr >= s && addr < e)
    }
}

/// Literal pools of more code than this are not read (flow recovery still works).
#[cfg(feature = "multiarch")]
const MAX_ARM_CODE_COPY: usize = 256 << 20;

#[cfg(feature = "multiarch")]
impl Cs {
    /// `a64 = true` for AArch64, `false` for 32-bit ARM in ARM mode only (little endian).
    pub fn new(a64: bool) -> Option<Self> {
        Some(Self {
            cs: Self::build(if a64 { 'x' } else { 'a' })?,
            a64,
            tracker: Default::default(),
            thumb: None,
        })
    }

    /// A 32-bit ARM decoder that follows the binary's ARM/Thumb map and reads literal pools.
    pub fn arm32(bin: &crate::model::Binary, data: &[u8]) -> Option<Self> {
        let mut code = Vec::new();
        let mut copied = 0usize;
        for s in bin.code_sections() {
            let bytes = bin.section_bytes(data, s);
            copied = copied.saturating_add(bytes.len());
            if copied > MAX_ARM_CODE_COPY {
                code.clear();
                break;
            }
            code.push((s.addr, bytes.to_vec()));
        }
        let data_ranges = bin
            .sections
            .iter()
            .filter(|s| s.perms.r && !s.perms.x && s.addr != 0)
            .map(|s| (s.addr, s.addr.saturating_add(s.size)))
            .collect();
        Some(Self {
            cs: Self::build('a')?,
            a64: false,
            tracker: Default::default(),
            thumb: Some(ArmState {
                cs: Self::build('t')?,
                modes: bin.arm_map.iter().copied().collect(),
                complete: !bin.stripped && bin.arm_map.iter().any(|m| m.1 == 'd'),
                mem: ArmMem {
                    code,
                    data: data_ranges,
                },
            }),
        })
    }

    fn build(mode: char) -> Option<capstone::Capstone> {
        use capstone::prelude::*;
        match mode {
            'x' => Capstone::new()
                .arm64()
                .mode(arch::arm64::ArchMode::Arm)
                .build(),
            't' => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Thumb)
                .endian(capstone::Endian::Little)
                .build(),
            _ => Capstone::new()
                .arm()
                .mode(arch::arm::ArchMode::Arm)
                .endian(capstone::Endian::Little)
                .build(),
        }
        .ok()
    }

    /// The instruction set at `addr` (`'a'` when nothing says otherwise).
    fn mode_at(&self, addr: u64) -> char {
        self.thumb
            .as_ref()
            .and_then(|t| t.modes.range(..=addr).next_back().map(|m| *m.1))
            .unwrap_or('a')
    }

    /// Record that code at `addr` is in `mode`, unless mapping symbols already say.
    fn learn(&mut self, addr: u64, mode: char) {
        if let Some(t) = self.thumb.as_mut() {
            if !t.complete {
                t.modes.entry(addr).or_insert(mode);
            }
        }
    }
}

#[cfg(feature = "multiarch")]
impl CodeDecoder for Cs {
    fn decode_one(&mut self, bytes: &[u8], addr: u64) -> Option<Insn> {
        let mode = if self.a64 { 'x' } else { self.mode_at(addr) };
        let cs = match (mode, &self.thumb) {
            ('d', _) => return None,
            ('t', Some(t)) => &t.cs,
            ('t', None) => return None,
            _ => &self.cs,
        };
        let window = bytes.get(..bytes.len().min(4))?;
        if window.len() < if mode == 't' { 2 } else { 4 } {
            return None;
        }
        let insns = cs.disasm_count(window, addr, 1).ok()?;
        let i = insns.iter().next()?;
        let mnemonic = i.mnemonic().unwrap_or("").to_string();
        let ops = i.op_str().unwrap_or("").to_string();
        let raw = i.bytes().to_vec();
        drop(insns);
        let (flow, data_ref) = match &self.thumb {
            None if self.a64 => self.tracker.a64(&mnemonic, &ops, addr),
            None => self.tracker.arm32(&mnemonic, &ops, addr, false, &()),
            Some(t) => self
                .tracker
                .arm32(&mnemonic, &ops, addr, mode == 't', &t.mem),
        };
        if !self.a64 {
            // `blx #imm` always switches instruction set; other direct branches keep it.
            if let Flow::Call(t) | Flow::Jump(t) | Flow::CondJump(t) = flow {
                let switch = mnemonic == "blx";
                let target_mode = match (mode, switch) {
                    ('t', true) => 'a',
                    ('a', true) => 't',
                    (m, _) => m,
                };
                self.learn(t, target_mode);
            }
        }
        // Straight-line register state does not survive a control transfer.
        if flow != Flow::Next {
            self.tracker.after_branch();
        }
        Some(Insn {
            addr,
            bytes: raw,
            text: if ops.is_empty() {
                mnemonic.clone()
            } else {
                format!("{mnemonic} {ops}")
            },
            mnemonic,
            flow,
            data_ref,
        })
    }
    fn linear(&mut self, bytes: &[u8], addr: u64, max: usize) -> Vec<Insn> {
        self.tracker.reset();
        let mut out = Vec::new();
        let mut a = addr;
        while out.len() < max {
            let off = (a - addr) as usize;
            let Some(rest) = bytes.get(off..) else { break };
            match self.decode_one(rest, a) {
                Some(i) => {
                    a += i.len();
                    out.push(i);
                }
                None if !self.a64 && self.mode_at(a) == 't' => {
                    // Undecodable halfword in Thumb code.
                    let Some(w) = rest.get(..2) else { break };
                    out.push(Insn {
                        addr: a,
                        bytes: w.to_vec(),
                        mnemonic: ".short".into(),
                        text: format!(".short 0x{:04x}", u16::from_le_bytes([w[0], w[1]])),
                        flow: Flow::Next,
                        data_ref: None,
                    });
                    a += 2;
                }
                None => {
                    // Undecodable word (or a literal pool): emit it as data and stay aligned.
                    let Some(w) = rest.get(..4) else { break };
                    out.push(Insn {
                        addr: a,
                        bytes: w.to_vec(),
                        mnemonic: ".word".into(),
                        text: format!(
                            ".word 0x{:08x}",
                            u32::from_le_bytes([w[0], w[1], w[2], w[3]])
                        ),
                        flow: Flow::Next,
                        data_ref: None,
                    });
                    a += 4;
                }
            }
        }
        out
    }
    fn max_insn_len(&self) -> usize {
        4
    }
    fn reset(&mut self) {
        self.tracker.reset();
    }
    fn is_thumb(&self, addr: u64) -> bool {
        !self.a64 && self.mode_at(addr) == 't'
    }
    fn code_addr(&mut self, ptr: u64) -> u64 {
        if self.thumb.is_some() && ptr & 1 == 1 {
            self.learn(ptr & !1, 't');
            return ptr & !1;
        }
        ptr
    }
}

/// Stateful x86 decoder + formatter.
pub struct X86 {
    bitness: u32,
    fmt: IntelFormatter,
    text: String,
}

impl X86 {
    /// New decoder for 16/32/64-bit code with an optional symbol table.
    pub fn new(bits: u8, names: &Names) -> Self {
        let mut fmt = IntelFormatter::with_options(Some(Box::new(Resolver(names.0.clone()))), None);
        let o = fmt.options_mut();
        o.set_hex_prefix("0x");
        o.set_hex_suffix("");
        o.set_uppercase_hex(false);
        o.set_space_after_operand_separator(true);
        o.set_branch_leading_zeros(false);
        o.set_show_branch_size(false);
        o.set_rip_relative_addresses(false);
        Self {
            bitness: if bits == 64 {
                64
            } else if bits == 16 {
                16
            } else {
                32
            },
            fmt,
            text: String::new(),
        }
    }

    /// Decode a single instruction at `addr` from `bytes` (which start at `addr`).
    pub fn decode_one(&mut self, bytes: &[u8], addr: u64) -> Option<Insn> {
        let mut d = Decoder::with_ip(self.bitness, bytes, addr, DecoderOptions::NONE);
        if !d.can_decode() {
            return None;
        }
        let ins = d.decode();
        if ins.is_invalid() {
            return None;
        }
        Some(self.convert(&ins, bytes))
    }

    /// Linear sweep: decode up to `max` instructions (skipping undecodable bytes).
    pub fn linear(&mut self, bytes: &[u8], addr: u64, max: usize) -> Vec<Insn> {
        let mut out = Vec::new();
        let mut d = Decoder::with_ip(self.bitness, bytes, addr, DecoderOptions::NONE);
        let mut ins = Instruction::default();
        while d.can_decode() && out.len() < max {
            let pos = d.position();
            d.decode_out(&mut ins);
            if ins.is_invalid() {
                // Emit a `db` pseudo-instruction and resync one byte later.
                let b = bytes[pos];
                out.push(Insn {
                    addr: addr + pos as u64,
                    bytes: vec![b],
                    mnemonic: "db".into(),
                    text: format!("db 0x{b:02x}"),
                    flow: Flow::Next,
                    data_ref: None,
                });
                let _ = d.set_position(pos + 1);
                d.set_ip(addr + pos as u64 + 1);
                continue;
            }
            out.push(self.convert(&ins, &bytes[pos..]));
        }
        out
    }

    fn convert(&mut self, ins: &Instruction, bytes: &[u8]) -> Insn {
        self.text.clear();
        self.fmt.format(ins, &mut self.text);
        let len = ins.len();
        let mem_slot = if ins.is_ip_rel_memory_operand() {
            Some(ins.ip_rel_memory_address())
        } else if has_memory_operand(ins)
            && ins.memory_base() == Register::None
            && ins.memory_index() == Register::None
        {
            Some(ins.memory_displacement64())
        } else {
            None
        };
        let flow = match ins.flow_control() {
            FlowControl::Next | FlowControl::XbeginXabortXend => Flow::Next,
            FlowControl::UnconditionalBranch => Flow::Jump(ins.near_branch_target()),
            FlowControl::ConditionalBranch => Flow::CondJump(ins.near_branch_target()),
            FlowControl::Call => Flow::Call(ins.near_branch_target()),
            FlowControl::IndirectBranch => Flow::IndirectJump(mem_slot),
            FlowControl::IndirectCall => Flow::IndirectCall(mem_slot),
            FlowControl::Return => Flow::Return,
            FlowControl::Interrupt => {
                if ins.mnemonic() == iced_x86::Mnemonic::Int3 {
                    Flow::Halt
                } else {
                    Flow::Next
                }
            }
            FlowControl::Exception => Flow::Halt,
        };
        let flow = if ins.mnemonic() == iced_x86::Mnemonic::Hlt {
            Flow::Halt
        } else {
            flow
        };
        let mut data_ref = mem_slot;
        if data_ref.is_none() {
            for i in 0..ins.op_count() {
                if matches!(
                    ins.op_kind(i),
                    OpKind::Immediate32 | OpKind::Immediate32to64 | OpKind::Immediate64
                ) {
                    let v = ins.immediate(i);
                    if v > 0x1000 {
                        data_ref = Some(v);
                    }
                }
            }
        }
        let mnemonic = self
            .text
            .split_whitespace()
            .find(|w| {
                !matches!(
                    *w,
                    "lock" | "rep" | "repe" | "repne" | "bnd" | "notrack" | "xacquire" | "xrelease"
                )
            })
            .unwrap_or("")
            .to_string();
        Insn {
            addr: ins.ip(),
            bytes: bytes[..len.min(bytes.len())].to_vec(),
            mnemonic,
            text: self.text.clone(),
            flow,
            data_ref,
        }
    }
}

fn has_memory_operand(ins: &Instruction) -> bool {
    (0..ins.op_count()).any(|i| ins.op_kind(i) == OpKind::Memory)
}

/// Linear disassembly for non-x86 architectures (Capstone).
#[cfg(feature = "multiarch")]
pub fn linear_capstone(
    arch: &crate::model::Arch,
    little_endian: bool,
    bytes: &[u8],
    addr: u64,
    max: usize,
) -> Result<Vec<Insn>, String> {
    use crate::model::Arch;
    use capstone::prelude::*;
    let endian = if little_endian {
        capstone::Endian::Little
    } else {
        capstone::Endian::Big
    };
    let cs = match arch {
        Arch::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .endian(endian)
            .build(),
        Arch::AArch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build(),
        Arch::Mips => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips32)
            .endian(endian)
            .build(),
        Arch::Mips64 => Capstone::new()
            .mips()
            .mode(arch::mips::ArchMode::Mips64)
            .endian(endian)
            .build(),
        Arch::PowerPc => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode32)
            .endian(endian)
            .build(),
        Arch::PowerPc64 => Capstone::new()
            .ppc()
            .mode(arch::ppc::ArchMode::Mode64)
            .endian(endian)
            .build(),
        Arch::RiscV => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .build(),
        other => return Err(format!("no capstone mode for {}", other.name())),
    }
    .map_err(|e| e.to_string())?;
    let insns = cs
        .disasm_count(bytes, addr, max)
        .map_err(|e| e.to_string())?;
    Ok(insns
        .iter()
        .map(|i| {
            let m = i.mnemonic().unwrap_or("").to_string();
            let ops = i.op_str().unwrap_or("");
            Insn {
                addr: i.address(),
                bytes: i.bytes().to_vec(),
                text: if ops.is_empty() {
                    m.clone()
                } else {
                    format!("{m} {ops}")
                },
                flow: if matches!(m.as_str(), "ret" | "retaa" | "retab") {
                    Flow::Return
                } else {
                    Flow::Next
                },
                mnemonic: m,
                data_ref: None,
            }
        })
        .collect())
}

/// Render instructions as a listing.
pub fn listing(insns: &[Insn], comments: &HashMap<u64, String>) -> String {
    use std::fmt::Write;
    let mut o = String::new();
    for i in insns {
        let hex: String = i
            .bytes
            .iter()
            .take(10)
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ");
        let _ = write!(o, "{:>12x}  {:<30} {}", i.addr, hex, i.text);
        if let Some(c) = comments.get(&i.addr) {
            let pad = 40usize.saturating_sub(i.text.len());
            let _ = write!(o, "{}; {}", " ".repeat(pad), c);
        }
        o.push('\n');
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_flow() {
        let names = Names(Arc::new(HashMap::from([(0x1010u64, "target".to_string())])));
        let mut x = X86::new(64, &names);
        // push rbp; mov rbp,rsp; call 0x1010; jne 0x1010; ret
        let code = [
            0x55, 0x48, 0x89, 0xe5, 0xe8, 0x07, 0x00, 0x00, 0x00, 0x75, 0x05, 0xc3,
        ];
        let v = x.linear(&code, 0x1000, 100);
        assert_eq!(v[0].mnemonic, "push");
        assert_eq!(v[1].text, "mov rbp, rsp");
        assert_eq!(v[2].flow, Flow::Call(0x1010));
        assert!(v[2].text.contains("target"), "{}", v[2].text);
        assert_eq!(v[3].flow, Flow::CondJump(0x1010));
        assert_eq!(v[4].flow, Flow::Return);
    }

    #[test]
    fn rip_relative_slot() {
        let mut x = X86::new(64, &Names::default());
        // call qword ptr [rip+0x10]
        let i = x.decode_one(&[0xff, 0x15, 0x10, 0, 0, 0], 0x2000).unwrap();
        assert_eq!(i.flow, Flow::IndirectCall(Some(0x2016)));
        // lea rdi, [rip+0x100]
        let i = x
            .decode_one(&[0x48, 0x8d, 0x3d, 0x00, 0x01, 0, 0], 0x3000)
            .unwrap();
        assert_eq!(i.data_ref, Some(0x3107));
    }

    #[test]
    fn invalid_bytes_become_db() {
        let mut x = X86::new(64, &Names::default());
        let v = x.linear(&[0x06, 0x90], 0, 10); // 0x06 is invalid in 64-bit mode
        assert_eq!(v[0].mnemonic, "db");
        assert_eq!(v[1].mnemonic, "nop");
    }
}
