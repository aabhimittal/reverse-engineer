//! Control-flow classification for 32-bit ARM (ARM and Thumb) and AArch64.
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
    /// Instructions left in the current Thumb `it` block.
    it_left: u8,
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
        self.after_branch();
        self.it_left = 0;
    }

    /// Forget register state after a control transfer. An `it` block survives a conditional
    /// branch inside it, so its count is kept.
    pub fn after_branch(&mut self) {
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

    /// Classify one 32-bit ARM instruction, in ARM (`thumb = false`) or Thumb mode.
    ///
    /// `mem` reads literal-pool words, so `ldr r0, [pc, #off]; add r0, pc` (Thumb PIC) and
    /// `movw`/`movt` pairs resolve to the address they build.
    pub fn arm32(
        &mut self,
        mnemonic: &str,
        ops: &str,
        addr: u64,
        thumb: bool,
        mem: &dyn Mem,
    ) -> (Flow, Option<u64>) {
        // Thumb-2 width suffixes say nothing about flow: `b.w` is `b`.
        let m = mnemonic
            .strip_suffix(".w")
            .or_else(|| mnemonic.strip_suffix(".n"))
            .unwrap_or(mnemonic);
        // `it`, `itte`, …: the next one to four instructions are conditional. Capstone decodes
        // one instruction at a time and does not carry this state, so `bx lr` in `it eq; bxeq lr`
        // reads as an unconditional return unless we count.
        if m.len() <= 5 && m.starts_with("it") && m[2..].chars().all(|c| c == 't' || c == 'e') {
            self.it_left = (m.len() - 1) as u8;
            return (Flow::Next, None);
        }
        if self.it_left > 0 {
            self.it_left -= 1;
            let (flow, r) = self.arm32_insn(m, ops, addr, thumb, mem);
            // A conditional write leaves the register unknown on one path.
            self.forget(ops);
            let flow = match flow {
                Flow::Jump(t) => Flow::CondJump(t),
                Flow::Return | Flow::Halt | Flow::IndirectJump(_) => Flow::Next,
                f => f,
            };
            return (flow, r);
        }
        self.arm32_insn(m, ops, addr, thumb, mem)
    }

    fn arm32_insn(
        &mut self,
        mnemonic: &str,
        ops: &str,
        addr: u64,
        thumb: bool,
        mem: &dyn Mem,
    ) -> (Flow, Option<u64>) {
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
        // What an instruction reads as `pc`, and the base of a literal load.
        let pc = addr.wrapping_add(if thumb { 4 } else { 8 }) & 0xffff_ffff;
        let lit_base = if thumb { pc & !3 } else { pc };
        let direct = ops.trim_start().starts_with('#');
        let target = last_target(ops);
        let first = reg(ops.split(',').next().unwrap_or(""));
        if let Some(c) = split("b") {
            return match (direct, target, c) {
                (true, Some(t), None) | (true, Some(t), Some("al")) => (Flow::Jump(t), None),
                (true, Some(t), Some(_)) => (Flow::CondJump(t), None),
                _ => (Flow::IndirectJump(None), None),
            };
        }
        if split("bl").is_some() || split("blx").is_some() {
            return match (direct, target) {
                (true, Some(t)) => (Flow::Call(t), None),
                _ => (Flow::IndirectCall(self.loaded.get(&first).copied()), None),
            };
        }
        if let Some(c) = split("bx") {
            return match (first == "lr", c) {
                (true, None) | (true, Some("al")) => (Flow::Return, None),
                (true, Some(_)) => (Flow::Next, None),
                _ => (Flow::IndirectJump(self.loaded.get(&first).copied()), None),
            };
        }
        if matches!(mnemonic, "cbz" | "cbnz") {
            return (target.map_or(Flow::Next, Flow::CondJump), None);
        }
        // Jump tables; the table follows the instruction.
        if matches!(mnemonic, "tbb" | "tbh") {
            return (Flow::IndirectJump(None), None);
        }
        let uncond = |base: &str| split(base).is_some_and(|c| matches!(c, None | Some("al")));
        if (uncond("pop") || uncond("ldm") || uncond("ldmia") || uncond("ldmfd"))
            && ops.contains("pc")
        {
            return (Flow::Return, None);
        }
        if uncond("ldr") && first == "pc" {
            // `ldr pc, [ip, #off]!` ends an ARM PLT entry: jump through the GOT slot.
            let slot = arm_mem(ops).and_then(|(base, off, idx)| {
                let b = self.value(&base, pc)?;
                let i = match idx {
                    Some(r) => self.value(&r, pc)?,
                    None => 0,
                };
                Some(b.wrapping_add(i).wrapping_add(off as u64) & 0xffff_ffff)
            });
            return (Flow::IndirectJump(slot), None);
        }
        if uncond("mov") && first == "pc" {
            return if reg(ops.split(',').nth(1).unwrap_or("")) == "lr" {
                (Flow::Return, None)
            } else {
                (Flow::IndirectJump(None), None)
            };
        }
        if matches!(mnemonic, "udf" | "bkpt") {
            return (Flow::Halt, None);
        }
        (
            Flow::Next,
            self.arm32_data(mnemonic, ops, pc, lit_base, mem),
        )
    }

    /// A tracked register's value; `pc` reads as the instruction's pc.
    fn value(&self, r: &str, pc: u64) -> Option<u64> {
        if r == "pc" {
            Some(pc)
        } else {
            self.regs.get(r).copied()
        }
    }

    /// Register tracking for straight-line ARM32 code. Returns the data address referenced.
    fn arm32_data(
        &mut self,
        m: &str,
        ops: &str,
        pc: u64,
        lit_base: u64,
        mem: &dyn Mem,
    ) -> Option<u64> {
        const MASK: u64 = 0xffff_ffff;
        let parts: Vec<&str> = ops.split(',').map(str::trim).collect();
        let rd = reg(parts.first().copied().unwrap_or(""));
        let set = |t: &mut Self, v: Option<u64>| {
            t.loaded.remove(&rd);
            match v {
                Some(v) => t.regs.insert(rd.clone(), v & MASK),
                None => t.regs.remove(&rd),
            };
        };
        match m {
            "ldr" => {
                let (base, off, idx) = arm_mem(ops)?;
                let b = if base == "pc" {
                    lit_base
                } else {
                    self.value(&base, pc)?
                };
                let i = match &idx {
                    Some(r) => self.value(r, pc),
                    None => Some(0),
                };
                let Some(i) = i else {
                    set(self, None);
                    return None;
                };
                let slot = b.wrapping_add(i).wrapping_add(off as u64) & MASK;
                let v = mem.word(slot).map(u64::from);
                set(self, v);
                self.loaded.insert(rd, slot);
                // A pool word holding a data address (non-PIC code) references that address.
                Some(v.filter(|&v| mem.is_data(v)).unwrap_or(slot))
            }
            "adr" => {
                let v = lit_base.wrapping_add(imm(parts.get(1)?)? as u64);
                set(self, Some(v));
                Some(v & MASK)
            }
            "add" | "sub" => {
                // `add rd, rn, op2`, or Thumb's two-operand `add rd, rm` (rd += rm).
                let (rn, op2) = match parts.len() {
                    2 => (rd.as_str(), parts[1]),
                    _ => (parts.get(1).copied().unwrap_or(""), parts[2]),
                };
                let base = self.value(&reg(rn), pc);
                let operand = if op2.starts_with('#') {
                    // ARM modified immediates may print as `#imm, #rot`.
                    let v = imm(op2)? as u64 & MASK;
                    match parts.get(3).and_then(|r| imm(r)) {
                        Some(rot) => Some(u64::from((v as u32).rotate_right(rot as u32))),
                        None => Some(v),
                    }
                } else {
                    self.value(&reg(op2), pc)
                };
                let v = match (base, operand) {
                    (Some(b), Some(o)) if m == "add" => Some(b.wrapping_add(o) & MASK),
                    (Some(b), Some(o)) => Some(b.wrapping_sub(o) & MASK),
                    _ => None,
                };
                set(self, v);
                // Only an address built from pc is a reference; register sums are arithmetic.
                v.filter(|_| rn == "pc" || op2 == "pc")
            }
            "movw" => {
                set(self, imm(parts.get(1)?).map(|v| v as u64));
                None
            }
            "movt" => {
                let hi = imm(parts.get(1)?)? as u64;
                let v = self.regs.get(&rd).map(|lo| (lo & 0xffff) | (hi << 16));
                set(self, v);
                v
            }
            "mov" if parts.len() == 2 && !parts[1].starts_with('#') => {
                let v = self.value(&reg(parts[1]), pc);
                set(self, v);
                None
            }
            _ => {
                self.forget(ops);
                None
            }
        }
    }
}

/// Memory the ARM32 tracker may read: literal-pool words in code, and which addresses are data.
pub trait Mem {
    /// The little-endian word at `addr`, if it is in a code section.
    fn word(&self, addr: u64) -> Option<u32>;
    /// Whether `addr` is in a mapped, non-executable section (strings, globals).
    fn is_data(&self, addr: u64) -> bool;
}

/// No memory: the tracker still classifies flow.
impl Mem for () {
    fn word(&self, _: u64) -> Option<u32> {
        None
    }
    fn is_data(&self, _: u64) -> bool {
        false
    }
}

/// `[rn]`, `[rn, #off]`, `[rn, #off]!`, `[rn, rm]` → (base, offset, index register).
fn arm_mem(ops: &str) -> Option<(String, i64, Option<String>)> {
    let inner = ops.split('[').nth(1)?.split(']').next()?;
    let mut parts = inner.split(',').map(str::trim);
    let base = reg(parts.next()?);
    match parts.next() {
        None => Some((base, 0, None)),
        Some(p) if p.starts_with('#') => Some((base, imm(p)?, None)),
        // `[rn, rm, lsl #2]` scales the index; leave those unresolved.
        Some(p) if parts.next().is_none() && !p.starts_with('-') => Some((base, 0, Some(reg(p)))),
        _ => None,
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
        assert_eq!(t.arm32("b", "#0x8100", 0, false, &()).0, Flow::Jump(0x8100));
        assert_eq!(
            t.arm32("bne", "#0x8100", 0, false, &()).0,
            Flow::CondJump(0x8100)
        );
        assert_eq!(
            t.arm32("bl", "#0x8200", 0, false, &()).0,
            Flow::Call(0x8200)
        );
        assert_eq!(
            t.arm32("blx", "r3", 0, false, &()).0,
            Flow::IndirectCall(None)
        );
        assert_eq!(t.arm32("bx", "lr", 0, false, &()).0, Flow::Return);
        assert_eq!(
            t.arm32("bx", "r2", 0, false, &()).0,
            Flow::IndirectJump(None)
        );
        assert_eq!(
            t.arm32("pop", "{r4, r5, pc}", 0, false, &()).0,
            Flow::Return
        );
        assert_eq!(t.arm32("popne", "{r4, pc}", 0, false, &()).0, Flow::Next);
        assert_eq!(
            t.arm32("ldr", "pc, [ip, #4]!", 0, false, &()).0,
            Flow::IndirectJump(None)
        );
        assert_eq!(t.arm32("mov", "pc, lr", 0, false, &()).0, Flow::Return);
        assert_eq!(
            t.arm32("bic", "r0, r0, #1", 0, false, &()).0,
            Flow::Next,
            "bic is not a branch"
        );
        assert_eq!(
            t.arm32("bfc", "r0, #1, #2", 0, false, &()).0,
            Flow::Next,
            "bfc is not a branch"
        );
        assert_eq!(t.arm32("bkpt", "#0", 0, false, &()).0, Flow::Halt);
        assert_eq!(
            t.arm32("ldr", "r0, [pc, #0x10]", 0x100, false, &()),
            (Flow::Next, Some(0x118))
        );
    }

    /// Literal pools for the Thumb tests: a pool word at 0x1034 and a string area.
    struct Pool;
    impl Mem for Pool {
        fn word(&self, a: u64) -> Option<u32> {
            match a {
                0x1034 => Some(0xffff_f2a3), // PIC offset: 0x1014 + this = 0x2b7
                0x1040 => Some(0x0000_3000), // absolute address of a string
                _ => None,
            }
        }
        fn is_data(&self, a: u64) -> bool {
            (0x2000..0x4000).contains(&a)
        }
    }

    #[test]
    fn thumb_flow_and_width_suffixes() {
        let mut t = Tracker::default();
        let m = &();
        assert_eq!(
            t.arm32("cbz", "r1, #0x1026", 0, true, m).0,
            Flow::CondJump(0x1026)
        );
        assert_eq!(
            t.arm32("cbnz", "r0, #0x1080", 0, true, m).0,
            Flow::CondJump(0x1080)
        );
        assert_eq!(t.arm32("b.w", "#0x1038", 0, true, m).0, Flow::Jump(0x1038));
        assert_eq!(
            t.arm32("bne.w", "#0x1038", 0, true, m).0,
            Flow::CondJump(0x1038)
        );
        assert_eq!(t.arm32("blx", "#0x13d0", 0, true, m).0, Flow::Call(0x13d0));
        assert_eq!(
            t.arm32("pop.w", "{r4, r5, r7, pc}", 0, true, m).0,
            Flow::Return
        );
        assert_eq!(
            t.arm32("tbb", "[pc, r0]", 0, true, m).0,
            Flow::IndirectJump(None)
        );
    }

    #[test]
    fn thumb_it_blocks_make_branches_conditional() {
        let mut t = Tracker::default();
        let m = &();
        assert_eq!(t.arm32("it", "eq", 0x1000, true, m).0, Flow::Next);
        // Capstone prints the conditional return as a plain `bx lr`.
        assert_eq!(t.arm32("bx", "lr", 0x1002, true, m).0, Flow::Next);
        assert_eq!(t.arm32("bx", "lr", 0x1004, true, m).0, Flow::Return);
        t.arm32("ite", "ne", 0x1006, true, m);
        assert_eq!(
            t.arm32("b", "#0x2000", 0x1008, true, m).0,
            Flow::CondJump(0x2000)
        );
        // The `else` slot survives the conditional branch in the `then` slot.
        t.after_branch();
        assert_eq!(t.arm32("pop", "{r4, pc}", 0x100a, true, m).0, Flow::Next);
        assert_eq!(t.arm32("pop", "{r4, pc}", 0x100c, true, m).0, Flow::Return);
        t.arm32("itt", "eq", 0x100e, true, m);
        t.reset();
        assert_eq!(
            t.arm32("bx", "lr", 0x1010, true, m).0,
            Flow::Return,
            "reset ends the block"
        );
    }

    #[test]
    fn thumb_pic_literal_and_movw_movt_resolve_addresses() {
        let mut t = Tracker::default();
        // ldr r2, [pc, #0x24] at 0x100e: Align(0x1012, 4) + 0x24 = 0x1034 (the pool slot).
        assert_eq!(
            t.arm32("ldr", "r2, [pc, #0x24]", 0x100e, true, &Pool).1,
            Some(0x1034)
        );
        // add r2, pc at 0x1010: r2 = 0xfffff2a3 + 0x1014 (mod 2^32).
        assert_eq!(t.arm32("add", "r2, pc", 0x1010, true, &Pool).1, Some(0x2b7));
        // Non-PIC: the pool word is the string's address, and that is what is referenced.
        assert_eq!(
            t.arm32("ldr", "r0, [pc, #0x30]", 0x100e, true, &Pool).1,
            Some(0x3000)
        );
        t.arm32("movw", "r1, #0x3456", 0, true, &Pool);
        assert_eq!(
            t.arm32("movt", "r1, #0x12", 4, true, &Pool).1,
            Some(0x123456)
        );
        // A different write forgets the value.
        t.arm32("movs", "r1, #0", 8, true, &Pool);
        assert_eq!(t.arm32("movt", "r1, #0x12", 12, true, &Pool).1, None);
    }

    #[test]
    fn arm32_plt_entry_resolves_the_got_slot() {
        // lld's ARM PLT entry: ip = pc + rotated immediates; ldr pc, [ip, #off]!.
        let mut t = Tracker::default();
        t.arm32("add", "ip, pc, #0, #12", 0x103c0, false, &());
        t.arm32("add", "ip, ip, #32, #20", 0x103c4, false, &());
        assert_eq!(
            t.arm32("ldr", "pc, [ip, #0xc8]!", 0x103c8, false, &()).0,
            Flow::IndirectJump(Some(0x30490))
        );
    }

    #[test]
    fn arm32_glibc_start_loads_main_from_its_got_slot() {
        // ldr sl, .Lgot; adr r3, .Lgot (add r3, pc, #); add sl, sl, r3; ldr ip, .Lgot+4;
        // ldr r0, [sl, ip] → the slot holding main.
        struct Got;
        impl Mem for Got {
            fn word(&self, a: u64) -> Option<u32> {
                match a {
                    0x10304 => Some(0x1017c), // _GLOBAL_OFFSET_TABLE_ - .Lgot
                    0x10308 => Some(0),       // main's GOT offset
                    _ => None,
                }
            }
            fn is_data(&self, _: u64) -> bool {
                false
            }
        }
        let mut t = Tracker::default();
        t.arm32("ldr", "sl, [pc, #0x1c]", 0x102e0, false, &Got);
        t.arm32("add", "r3, pc, #0x18", 0x102e4, false, &Got);
        t.arm32("add", "sl, sl, r3", 0x102e8, false, &Got);
        t.arm32("ldr", "ip, [pc, #0x14]", 0x102ec, false, &Got);
        assert_eq!(
            t.arm32("ldr", "r0, [sl, ip]", 0x102f0, false, &Got).1,
            Some(0x20480)
        );
    }
}
