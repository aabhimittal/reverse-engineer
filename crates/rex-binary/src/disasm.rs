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
