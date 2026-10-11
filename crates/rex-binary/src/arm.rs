//! Control-flow classification for ARM (ARM mode) and AArch64.
//!
//! x86 decoders hand us control flow directly; Capstone gives text. This module turns that text
//! into the same [`Flow`] values the rest of the pipeline uses, and tracks just enough register
//! state to resolve the two idioms that matter for reversing:
//!
//! * **Address materialisation.** AArch64 cannot load a 64-bit address in one instruction, so it
//!   builds one in two: `adrp x0, #page` then `add x0, x0, #off` (or `ldr x0, [x0, #off]` to read it
//!   from the GOT). Following the pair is how strings, globals and PLT slots get resolved.
//! * **PLT stubs.** `adrp x16, ...; ldr x17, [x16, #off]; br x17` is "jump to whatever the GOT says",
//!   which is how `strcpy` gets called. Resolving the slot names the import.
//!
//! The classifier is pure (strings in, [`Flow`] out) so it is tested without Capstone.

use crate::disasm::Flow;
use std::collections::HashMap;

/// Tracks `adrp`/`add`/`ldr` register state within straight-line code.
#[derive(Debug, Default)]
pub struct Tracker {
    /// Registers holding a known address.
    regs: HashMap<String, u64>,
    /// Registers that were loaded from a known memory slot.
    loaded: HashMap<String, u64>,
}

fn reg(s: &str) -> String {
    let s = s.trim().trim_end_matches('!');
    match s.strip_prefix('w') {
        Some(n) if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() => format!("x{n}"),
        _ => s.to_string(),
    }
}

fn imm(s: &str) -> Option<i64> {
    let s = s.trim().trim_start_matches('#');
    let (neg, s) = match s.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, s),
    };
    let v = match s.strip_prefix("0x") {
        Some(h) => i64::from_str_radix(h, 16).ok()?,
        None => s.parse::<i64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

/// The operand after the last comma, as an address (`#0x400100`).
fn last_target(ops: &str) -> Option<u64> {
    imm(ops.rsplit(',').next()?).map(|v| v as u64)
}

/// `[xN, #off]` / `[xN]` / `[xN, #off]!` → (base register, offset).
fn mem_operand(ops: &str) -> Option<(String, i64)> {
    let inner = ops.split('[').nth(1)?.split(']').next()?;
    let mut parts = inner.split(',');
    let base = reg(parts.next()?);
    let off = match parts.next() {
        Some(o) => imm(o)?,
        None => 0,
    };
    Some((base, off))
}

const COND: [&str; 17] = [
    "eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs", "vc", "hi", "ls", "ge", "lt", "gt", "le",
    "al",
];

impl Tracker {
    /// Forget everything (call at the start of each new path).
    pub fn reset(&mut self) {
        self.regs.clear();
        self.loaded.clear();
    }

    fn forget(&mut self, ops: &str) {
        if let Some(first) = ops.split(',').next() {
            let r = reg(first);
            self.regs.remove(&r);
            self.loaded.remove(&r);
        }
    }

    /// Classify one AArch64 instruction. Returns its flow and any data address it references.
    pub fn a64(&mut self, mnemonic: &str, ops: &str, addr: u64) -> (Flow, Option<u64>) {
        let m = mnemonic;
        match m {
            "adrp" | "adr" => {
                let rd = reg(ops.split(',').next().unwrap_or(""));
                let v = last_target(ops);
                self.loaded.remove(&rd);
                match v {
                    Some(v) => {
                        self.regs.insert(rd, v);
                        (Flow::Next, Some(v))
                    }
                    None => {
                        self.regs.remove(&rd);
                        (Flow::Next, None)
                    }
                }
            }
            "add" => {
                let mut p = ops.split(',');
                let (rd, rn) = (reg(p.next().unwrap_or("")), reg(p.next().unwrap_or("")));
                let off = p.next().and_then(imm);
                self.loaded.remove(&rd);
                match (self.regs.get(&rn).copied(), off) {
                    (Some(base), Some(o)) => {
                        let v = base.wrapping_add(o as u64);
                        self.regs.insert(rd, v);
                        (Flow::Next, Some(v))
                    }
                    _ => {
                        self.regs.remove(&rd);
                        (Flow::Next, None)
                    }
                }
            }
            "ldr" | "ldur" | "ldrsw" => {
                let rd = reg(ops.split(',').next().unwrap_or(""));
                // Read the base before clobbering the destination (`ldr x8, [x8, #16]`).
                let slot = mem_operand(ops).and_then(|(base, off)| {
                    self.regs.get(&base).map(|b| b.wrapping_add(off as u64))
                });
                self.regs.remove(&rd);
                self.loaded.remove(&rd);
                if let Some(slot) = slot {
                    self.loaded.insert(rd, slot);
                    return (Flow::Next, Some(slot));
                }
                if mem_operand(ops).is_none() {
                    if let Some(t) = last_target(ops) {
                        // `ldr x0, #literal`
                        return (Flow::Next, Some(t));
                    }
                }
                (Flow::Next, None)
            }
            "b" => (
                last_target(ops).map_or(Flow::IndirectJump(None), Flow::Jump),
                None,
            ),
            "bl" => (
                last_target(ops).map_or(Flow::IndirectCall(None), Flow::Call),
                None,
            ),
            "cbz" | "cbnz" | "tbz" | "tbnz" => {
                (last_target(ops).map_or(Flow::Next, Flow::CondJump), None)
            }
            _ if m.starts_with("b.") || m.starts_with("bc.") => {
                (last_target(ops).map_or(Flow::Next, Flow::CondJump), None)
            }
            "br" | "braa" | "brab" | "braaz" | "brabz" => {
                let r = reg(ops.split(',').next().unwrap_or(""));
                (Flow::IndirectJump(self.loaded.get(&r).copied()), None)
            }
            "blr" | "blraa" | "blrab" | "blraaz" | "blrabz" => {
                let r = reg(ops.split(',').next().unwrap_or(""));
                (Flow::IndirectCall(self.loaded.get(&r).copied()), None)
            }
            "ret" | "retaa" | "retab" | "eret" | "eretaa" | "eretab" | "drps" => {
                (Flow::Return, None)
            }
            "brk" | "hlt" | "udf" => (Flow::Halt, None),
            _ => {
                let _ = addr;
                self.forget(ops);
                (Flow::Next, None)
            }
        }
    }

    /// Classify one 32-bit ARM (ARM mode) instruction.
    pub fn arm32(&mut self, mnemonic: &str, ops: &str, addr: u64) -> (Flow, Option<u64>) {
        // Split a trailing condition code: `bne` -> ("b", Some("ne")).
        let split = |base: &str| -> Option<Option<&str>> {
            let rest = mnemonic.strip_prefix(base)?;
            if rest.is_empty() {
                Some(None)
            } else if COND.contains(&rest) {
                Some(Some(rest))
            } else {
                None
            }
        };
        let direct = ops.trim_start().starts_with('#');
        let target = last_target(ops);
        if let Some(c) = split("b") {
            return match (direct, target, c) {
                (true, Some(t), None) | (true, Some(t), Some("al")) => (Flow::Jump(t), None),
                (true, Some(t), Some(_)) => (Flow::CondJump(t), None),
                _ => (Flow::IndirectJump(None), None),
            };
        }
        if let Some(_c) = split("bl") {
            return match (direct, target) {
                (true, Some(t)) => (Flow::Call(t), None),
                _ => (Flow::IndirectCall(None), None),
            };
        }
        if split("blx").is_some() {
            return match (direct, target) {
                (true, Some(t)) => (Flow::Call(t), None),
                _ => (Flow::IndirectCall(None), None),
            };
        }
        if let Some(c) = split("bx") {
            let lr = reg(ops) == "lr";
            return match (lr, c) {
                (true, None) | (true, Some("al")) => (Flow::Return, None),
                (true, Some(_)) => (Flow::Next, None),
                _ => (Flow::IndirectJump(None), None),
            };
        }
        let writes_pc = |ops: &str| ops.split(',').next().map(reg).as_deref() == Some("pc");
        let uncond = |base: &str| split(base).is_some_and(|c| matches!(c, None | Some("al")));
        if (uncond("pop") || uncond("ldm") || uncond("ldmia") || uncond("ldmfd"))
            && ops.contains("pc")
        {
            return (Flow::Return, None);
        }
        if uncond("ldr") && writes_pc(ops) {
            return (Flow::IndirectJump(None), None);
        }
        if uncond("mov") && writes_pc(ops) {
            return if reg(ops.split(',').nth(1).unwrap_or("")) == "lr" {
                (Flow::Return, None)
            } else {
                (Flow::IndirectJump(None), None)
            };
        }
        if matches!(mnemonic, "udf" | "bkpt") {
            return (Flow::Halt, None);
        }
        // `ldr rX, [pc, #off]` literal load: the operand is addr + 8 + off.
        if mnemonic == "ldr" {
            if let Some((base, off)) = mem_operand(ops) {
                if base == "pc" {
                    return (
                        Flow::Next,
                        Some(addr.wrapping_add(8).wrapping_add(off as u64)),
                    );
                }
            }
        }
        (Flow::Next, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a64_direct_branches() {
        let mut t = Tracker::default();
        assert_eq!(t.a64("b", "#0x400100", 0).0, Flow::Jump(0x400100));
        assert_eq!(t.a64("bl", "#0x400200", 0).0, Flow::Call(0x400200));
        assert_eq!(t.a64("b.eq", "#0x400300", 0).0, Flow::CondJump(0x400300));
        assert_eq!(t.a64("b.ne", "#0x400300", 0).0, Flow::CondJump(0x400300));
        assert_eq!(t.a64("cbz", "x0, #0x400400", 0).0, Flow::CondJump(0x400400));
        assert_eq!(
            t.a64("tbnz", "w1, #3, #0x400500", 0).0,
            Flow::CondJump(0x400500)
        );
        assert_eq!(t.a64("ret", "", 0).0, Flow::Return);
        assert_eq!(t.a64("retaa", "", 0).0, Flow::Return);
        assert_eq!(t.a64("brk", "#0x1", 0).0, Flow::Halt);
        assert_eq!(t.a64("mov", "x0, x1", 0).0, Flow::Next);
    }

    #[test]
    fn a64_plt_stub_resolves_the_got_slot() {
        let mut t = Tracker::default();
        assert_eq!(t.a64("adrp", "x16, #0x420000", 0x1000).1, Some(0x420000));
        assert_eq!(
            t.a64("ldr", "x17, [x16, #0x18]", 0x1004),
            (Flow::Next, Some(0x420018))
        );
        t.a64("add", "x16, x16, #0x18", 0x1008);
        assert_eq!(
            t.a64("br", "x17", 0x100c).0,
            Flow::IndirectJump(Some(0x420018))
        );
    }

    #[test]
    fn a64_string_address_materialisation_and_reset() {
        let mut t = Tracker::default();
        t.a64("adrp", "x0, #0x10000", 0);
        assert_eq!(
            t.a64("add", "x0, x0, #0x7b0", 4),
            (Flow::Next, Some(0x107b0))
        );
        // Overwriting the register forgets the address.
        t.a64("mov", "x0, #5", 8);
        assert_eq!(t.a64("add", "x0, x0, #1", 12).1, None);
        // blr through a register that was never loaded from a slot has no slot.
        assert_eq!(t.a64("blr", "x8", 16).0, Flow::IndirectCall(None));
        t.a64("adrp", "x8, #0x30000", 20);
        t.a64("ldr", "x8, [x8, #0x10]", 24);
        assert_eq!(t.a64("blr", "x8", 28).0, Flow::IndirectCall(Some(0x30010)));
        t.reset();
        t.a64("ldr", "x8, [x8, #0x10]", 32);
        assert_eq!(t.a64("blr", "x8", 36).0, Flow::IndirectCall(None));
    }

    #[test]
    fn a64_handles_w_registers_and_garbage() {
        let mut t = Tracker::default();
        assert_eq!(t.a64("b", "", 0).0, Flow::IndirectJump(None));
        assert_eq!(t.a64("cbz", "garbage", 0).0, Flow::Next);
        assert_eq!(t.a64("ldr", "", 0).1, None);
        assert_eq!(t.a64("add", "", 0).1, None);
        t.a64("adrp", "x1, #0x2000", 0);
        assert_eq!(t.a64("add", "w1, w1, #4", 4).1, Some(0x2004));
    }

    #[test]
    fn arm32_control_flow() {
        let mut t = Tracker::default();
        assert_eq!(t.arm32("b", "#0x8100", 0).0, Flow::Jump(0x8100));
        assert_eq!(t.arm32("bne", "#0x8100", 0).0, Flow::CondJump(0x8100));
        assert_eq!(t.arm32("bl", "#0x8200", 0).0, Flow::Call(0x8200));
        assert_eq!(t.arm32("blx", "r3", 0).0, Flow::IndirectCall(None));
        assert_eq!(t.arm32("bx", "lr", 0).0, Flow::Return);
        assert_eq!(t.arm32("bx", "r2", 0).0, Flow::IndirectJump(None));
        assert_eq!(t.arm32("pop", "{r4, r5, pc}", 0).0, Flow::Return);
        assert_eq!(t.arm32("popne", "{r4, pc}", 0).0, Flow::Next);
        assert_eq!(
            t.arm32("ldr", "pc, [ip, #4]!", 0).0,
            Flow::IndirectJump(None)
        );
        assert_eq!(t.arm32("mov", "pc, lr", 0).0, Flow::Return);
        assert_eq!(
            t.arm32("bic", "r0, r0, #1", 0).0,
            Flow::Next,
            "bic is not a branch"
        );
        assert_eq!(
            t.arm32("bfc", "r0, #1, #2", 0).0,
            Flow::Next,
            "bfc is not a branch"
        );
        assert_eq!(t.arm32("bkpt", "#0", 0).0, Flow::Halt);
        assert_eq!(
            t.arm32("ldr", "r0, [pc, #0x10]", 0x100),
            (Flow::Next, Some(0x118))
        );
    }
}
