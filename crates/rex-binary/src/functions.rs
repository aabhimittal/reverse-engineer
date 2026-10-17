//! Function discovery, control-flow graphs, call graphs and cross-references.
//!
//! The approach is *recursive descent*: start from places we know are code
//! (the entry point, symbols, exports), decode instruction by instruction,
//! and follow every branch and call to discover more code. Analogy: exploring
//! a cave system with a ball of string. You only ever walk passages you can
//! reach from where you've already been, so you never mistake a painting on
//! the wall (data) for a tunnel (code), which is the classic failure of a
//! naive linear sweep.

use crate::disasm::{CodeDecoder, Flow, Insn, Names, decoder_for};
use crate::model::{BinFormat, Binary};
use crate::strings;
use rex_core::AnalysisOptions;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt::Write;
use std::sync::Arc;

/// Why an edge exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// Sequential fall-through into the next block.
    Fallthrough,
    /// Unconditional jump.
    Jump,
    /// Conditional branch taken.
    True,
    /// Conditional branch not taken.
    False,
}

/// A basic block: straight-line code with one entry and one exit.
#[derive(Debug, Clone, Serialize)]
pub struct Block {
    /// First instruction address.
    pub start: u64,
    /// One past the last byte.
    pub end: u64,
    /// Instructions.
    pub insns: Vec<Insn>,
    /// Successor blocks.
    pub succs: Vec<(u64, EdgeKind)>,
}

/// A recovered function.
#[derive(Debug, Clone, Serialize)]
pub struct Function {
    /// Entry address.
    pub addr: u64,
    /// Name (symbol, inferred, or `sub_<addr>`).
    pub name: String,
    /// Bytes of code belonging to the function (sum of instruction lengths).
    pub size: u64,
    /// Basic blocks, sorted by address.
    pub blocks: Vec<Block>,
    /// Direct call targets (addresses).
    pub calls: Vec<u64>,
    /// Imported functions called (directly, via stub or via IAT slot).
    pub imports_called: Vec<String>,
    /// Strings referenced by the code.
    pub strings: Vec<String>,
    /// Is this a thunk / stub that just jumps to an import?
    pub thunk_to: Option<String>,
}

impl Function {
    /// Number of instructions.
    pub fn insn_count(&self) -> usize {
        self.blocks.iter().map(|b| b.insns.len()).sum()
    }
    /// McCabe cyclomatic complexity: E − N + 2.
    pub fn cyclomatic(&self) -> usize {
        let e: usize = self.blocks.iter().map(|b| b.succs.len()).sum();
        (e + 2).saturating_sub(self.blocks.len()).max(1)
    }
    /// All instructions in address order.
    pub fn insns(&self) -> impl Iterator<Item = &Insn> {
        self.blocks.iter().flat_map(|b| b.insns.iter())
    }
    /// Mnemonic-only fingerprint used for diffing (position independent).
    pub fn mnemonic_hash(&self) -> String {
        let s: String = self
            .insns()
            .map(|i| i.mnemonic.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        rex_core::hash::md5_hex(s.as_bytes())
    }
}

/// The whole-program view.
#[derive(Debug, Default, Serialize)]
pub struct Program {
    /// Functions by address.
    pub functions: BTreeMap<u64, Function>,
    /// Address → name (functions, stubs, IAT/GOT slots).
    #[serde(skip)]
    pub names: HashMap<u64, String>,
    /// Import stubs (PLT / __stubs) address → import name.
    pub stubs: BTreeMap<u64, String>,
    /// Strings located in non-executable sections, by virtual address.
    #[serde(skip)]
    pub strings_at: HashMap<u64, String>,
    /// Address of `main` if inferred from the entry stub.
    pub main: Option<u64>,
    /// True if the architecture isn't supported by the built-in decoder.
    pub unsupported_arch: bool,
}

impl Program {
    /// Find a function by name or hex address.
    pub fn find(&self, query: &str) -> Option<&Function> {
        let q = query.trim();
        let as_addr = q
            .strip_prefix("0x")
            .and_then(|h| u64::from_str_radix(h, 16).ok())
            .or_else(|| {
                q.strip_prefix("sub_")
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
            });
        if let Some(a) = as_addr {
            if let Some(f) = self.functions.get(&a) {
                return Some(f);
            }
            return self
                .functions
                .values()
                .find(|f| f.blocks.iter().any(|b| a >= b.start && a < b.end));
        }
        self.functions.values().find(|f| f.name == q).or_else(|| {
            self.functions
                .values()
                .find(|f| f.name.trim_start_matches('_') == q)
        })
    }

    /// Callers of each function: callee → callers.
    pub fn callers(&self) -> HashMap<u64, Vec<u64>> {
        let mut m: HashMap<u64, Vec<u64>> = HashMap::new();
        for f in self.functions.values() {
            for &c in &f.calls {
                m.entry(c).or_default().push(f.addr);
            }
        }
        for v in m.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        m
    }

    /// Name for an address, if known.
    pub fn name_of(&self, addr: u64) -> String {
        self.names
            .get(&addr)
            .cloned()
            .unwrap_or_else(|| format!("sub_{addr:x}"))
    }
}

/// Functions that never return; calls to them end a basic block.
fn is_noreturn(name: &str) -> bool {
    let n = name
        .trim_start_matches("__imp_")
        .trim_end_matches("@plt")
        .trim_end_matches("@stub")
        .trim_start_matches('_');
    matches!(
        n,
        "exit"
            | "Exit"
            | "abort"
            | "stack_chk_fail"
            | "assert_fail"
            | "err"
            | "errx"
            | "verr"
            | "verrx"
            | "ExitProcess"
            | "ExitThread"
            | "FatalExit"
            | "RaiseFailFastException"
            | "cxa_throw"
            | "cxa_rethrow"
            | "longjmp"
            | "siglongjmp"
            | "pthread_exit"
            | "quick_exit"
            | "fortify_fail"
            | "chk_fail"
            | "libc_fatal"
            | "Unwind_Resume"
            | "terminate"
            | "CxxThrowException"
    ) || n.starts_with("core::panicking::")
        || n.starts_with("std::panicking::begin_panic")
        || n.starts_with("std::process::exit")
        || n.starts_with("runtime.gopanic")
        || n == "runtime.throw"
}

fn stub_section(name: &str) -> bool {
    matches!(
        name,
        ".plt"
            | ".plt.sec"
            | ".plt.got"
            | ".iplt"
            | "__TEXT,__stubs"
            | "__TEXT,__auth_stubs"
            | "__TEXT,__symbol_stub"
    )
}

/// Recover functions, CFGs and the call graph.
pub fn analyze(bin: &Binary, data: &[u8], opts: &AnalysisOptions) -> Program {
    let mut prog = Program::default();
    let Some(mut x) = decoder_for(bin, &Names::default()) else {
        prog.unsupported_arch = true;
        for s in &bin.symbols {
            prog.names.insert(s.addr, s.display().to_string());
        }
        return prog;
    };

    // 1. Names from symbols and import slots.
    let mut names: HashMap<u64, String> = HashMap::new();
    let mut slot_imports: HashMap<u64, String> = HashMap::new();
    for imp in &bin.imports {
        if let Some(slot) = imp.slot {
            slot_imports.insert(slot, imp.name.clone());
            names.insert(slot, format!("__imp_{}", imp.name));
        }
    }
    for s in bin.symbols.iter().chain(bin.exports.iter()) {
        names
            .entry(s.addr)
            .or_insert_with(|| s.display().to_string());
    }

    // 2. Resolve PLT / stub entries: each ends in an indirect jump through a slot (`jmp [slot]` on
    //    x86, `adrp; ldr; br` on AArch64), so map stub → import name.
    let suffix = if bin.format == BinFormat::MachO {
        "@stub"
    } else {
        "@plt"
    };
    for sec in bin.code_sections().filter(|s| stub_section(&s.name)) {
        let bytes = bin.section_bytes(data, sec);
        let insns = x.linear(bytes, sec.addr, 1 << 16);
        let mut block_start: Option<u64> = None;
        for i in &insns {
            if block_start.is_none()
                && !i.mnemonic.starts_with("nop")
                && i.mnemonic != "endbr64"
                && i.mnemonic != "endbr32"
            {
                block_start = Some(i.addr);
            }
            if i.mnemonic == "endbr64" || i.mnemonic == "endbr32" {
                block_start = Some(i.addr);
            }
            match i.flow {
                Flow::IndirectJump(Some(slot)) => {
                    if let (Some(start), Some(name)) = (block_start, slot_imports.get(&slot)) {
                        prog.stubs.insert(start, name.clone());
                        names.insert(start, format!("{name}{suffix}"));
                    }
                    block_start = None;
                }
                Flow::Jump(_) | Flow::Return | Flow::Halt => block_start = None,
                _ => {}
            }
        }
    }

    // 3. Strings by virtual address, for annotating references.
    let mut string_at: HashMap<u64, String> = HashMap::new();
    for s in strings::extract(data, 4) {
        if let Some(va) = bin.offset_to_va(s.offset) {
            if !bin.section_for(va).map(|x| x.perms.x).unwrap_or(false) {
                string_at.insert(va, s.text);
            }
        }
    }

    // 4. Seeds.
    let in_code = |a: u64| bin.code_sections().any(|s| s.contains(a));
    let mut seeds: BTreeSet<u64> = BTreeSet::new();
    if bin.entry != 0 && in_code(bin.entry) {
        seeds.insert(bin.entry);
        names.entry(bin.entry).or_insert_with(|| "entry".into());
    }
    for s in bin.symbols.iter().chain(bin.exports.iter()) {
        if s.kind == crate::model::SymKind::Func
            && in_code(s.addr)
            && !prog.stubs.contains_key(&s.addr)
        {
            seeds.insert(s.addr);
        }
    }
    // Unwind / metadata tables list every function, even ones nothing calls.
    for &a in &bin.function_starts {
        if in_code(a) && !prog.stubs.contains_key(&a) {
            seeds.insert(a);
        }
    }

    // 5. Infer `main` in stripped binaries: `_start` passes it to __libc_start_main.
    if bin.entry != 0 && bin.format == BinFormat::Elf {
        if let Some(bytes) = bin.bytes_at(data, bin.entry) {
            let insns = x.linear(&bytes[..bytes.len().min(256)], bin.entry, 64);
            let mut candidate = None;
            for i in &insns {
                let first_op = i.text.split_whitespace().nth(1).unwrap_or("");
                let target_reg = if bin.bits == 64 { "rdi," } else { "" };
                if bin.bits == 64
                    && (i.mnemonic == "lea" || i.mnemonic == "mov")
                    && first_op == target_reg
                {
                    candidate = i.data_ref;
                }
                if bin.bits == 32 && i.mnemonic == "push" {
                    if let Some(r) = i.data_ref {
                        candidate = Some(r);
                    }
                }
                let is_libc_start = match i.flow {
                    Flow::Call(t) => names
                        .get(&t)
                        .is_some_and(|n| n.contains("__libc_start_main")),
                    Flow::IndirectCall(Some(s)) => slot_imports
                        .get(&s)
                        .is_some_and(|n| n.contains("__libc_start_main")),
                    _ => false,
                };
                if is_libc_start {
                    if let Some(m) = candidate.filter(|&m| in_code(m)) {
                        prog.main = Some(m);
                        seeds.insert(m);
                        names.entry(m).or_insert_with(|| "main".into());
                    }
                    break;
                }
            }
        }
    }

    // 5b. The same inference on AArch64: `_start` builds `main` in x0 (`adrp x0; add x0, x0, #off` (or a single `adr` after linker relaxation),
    //     or `ldr x0, [x0, #off]` from the GOT in PIE binaries) and calls __libc_start_main.
    if prog.main.is_none()
        && bin.arch == crate::model::Arch::AArch64
        && bin.entry != 0
        && bin.format == BinFormat::Elf
    {
        if let Some(bytes) = bin.bytes_at(data, bin.entry) {
            let insns = x.linear(&bytes[..bytes.len().min(256)], bin.entry, 64);
            let mut candidate = None;
            for i in &insns {
                if matches!(i.mnemonic.as_str(), "add" | "ldr" | "adr") && i.text.contains(" x0, ")
                {
                    candidate = i.data_ref;
                }
                let is_libc_start = match i.flow {
                    Flow::Call(t) => names
                        .get(&t)
                        .is_some_and(|n| n.contains("__libc_start_main")),
                    _ => false,
                };
                if is_libc_start {
                    // PIE: the candidate is a GOT slot holding main; non-PIE: main itself.
                    let main = candidate.filter(|&c| in_code(c)).or_else(|| {
                        candidate
                            .and_then(|c| read_ptr(bin, data, c))
                            .filter(|&m| in_code(m))
                    });
                    if let Some(m) = main {
                        prog.main = Some(m);
                        seeds.insert(m);
                        names.entry(m).or_insert_with(|| "main".into());
                    }
                    break;
                }
            }
        }
    }

    let names_arc = Names(Arc::new(names.clone()));
    let mut x = decoder_for(bin, &names_arc).expect("decoder was available above");

    // 6. Explore.
    let mut queue: Vec<u64> = seeds.iter().rev().copied().collect();
    let mut done: HashSet<u64> = HashSet::new();
    let known_starts: HashSet<u64> = seeds.clone().into_iter().collect();
    while let Some(start) = queue.pop() {
        if prog.functions.len() >= opts.max_functions {
            break;
        }
        if !done.insert(start) || prog.stubs.contains_key(&start) {
            continue;
        }
        let f = explore(
            bin,
            data,
            x.as_mut(),
            start,
            &names,
            &known_starts,
            &prog.stubs,
            opts.max_insns_per_function,
        );
        for &c in f.calls.iter().rev() {
            if in_code(c) && !done.contains(&c) && !prog.stubs.contains_key(&c) {
                queue.push(c);
            }
        }
        prog.functions.insert(start, f);
    }

    // 7. Post-pass: names, imports called, strings referenced, thunks.
    for (&a, f) in prog.functions.iter_mut() {
        f.name = names
            .get(&a)
            .cloned()
            .unwrap_or_else(|| format!("sub_{a:x}"));
        let mut imps = BTreeSet::new();
        let mut strs = Vec::new();
        for i in f.blocks.iter().flat_map(|b| &b.insns) {
            match i.flow {
                Flow::Call(t) | Flow::Jump(t) => {
                    if let Some(n) = prog.stubs.get(&t) {
                        imps.insert(n.clone());
                    }
                }
                Flow::IndirectCall(Some(s)) | Flow::IndirectJump(Some(s)) => {
                    if let Some(n) = slot_imports.get(&s) {
                        imps.insert(n.clone());
                    }
                }
                _ => {}
            }
            if let Some(r) = i.data_ref {
                // Direct reference, or one pointer hop (`mov rcx, [config]` where config → "string").
                let target = string_at.get(&r).or_else(|| {
                    let ptr = read_ptr(bin, data, r)?;
                    string_at.get(&ptr)
                });
                if let Some(s) = target {
                    if !strs.contains(s) {
                        strs.push(s.clone());
                    }
                }
            }
        }
        f.imports_called = imps.into_iter().collect();
        f.strings = strs;
        if f.insn_count() <= 3 {
            if let Some(Flow::IndirectJump(Some(s))) = f.insns().last().map(|i| i.flow) {
                f.thunk_to = slot_imports.get(&s).cloned();
            }
        }
    }
    for f in prog.functions.values() {
        if let Some(t) = &f.thunk_to {
            if f.name.starts_with("sub_") {
                names.insert(f.addr, format!("j_{t}"));
            }
        }
    }
    let thunk_names: Vec<(u64, String)> = prog
        .functions
        .values()
        .filter_map(|f| f.thunk_to.as_ref().map(|t| (f.addr, t.clone())))
        .collect();
    for f in prog.functions.values_mut() {
        if let Some(n) = names.get(&f.addr) {
            f.name = n.clone();
        }
        for (ta, tn) in &thunk_names {
            if f.calls.contains(ta) && !f.imports_called.contains(tn) {
                f.imports_called.push(tn.clone());
            }
        }
    }
    prog.names = names;
    prog.strings_at = string_at;
    prog
}

/// Read a pointer-sized little/big-endian value at a virtual address.
fn read_ptr(bin: &Binary, data: &[u8], va: u64) -> Option<u64> {
    if let Ok(i) = bin.relocated_ptrs.binary_search_by_key(&va, |p| p.0) {
        return Some(bin.relocated_ptrs[i].1);
    }
    let width = (bin.bits / 8) as usize;
    let b = bin.bytes_at(data, va)?.get(..width)?;
    let mut buf = [0u8; 8];
    if bin.little_endian {
        buf[..width].copy_from_slice(b);
        Some(u64::from_le_bytes(buf))
    } else {
        buf[8 - width..].copy_from_slice(b);
        Some(u64::from_be_bytes(buf))
    }
}

#[allow(clippy::too_many_arguments)]
fn explore(
    bin: &Binary,
    data: &[u8],
    x: &mut dyn CodeDecoder,
    start: u64,
    names: &HashMap<u64, String>,
    known_starts: &HashSet<u64>,
    stubs: &BTreeMap<u64, String>,
    max_insns: usize,
) -> Function {
    let mut insns: BTreeMap<u64, Insn> = BTreeMap::new();
    let mut leaders: BTreeSet<u64> = BTreeSet::from([start]);
    let mut work = vec![start];
    let mut calls: Vec<u64> = Vec::new();
    let in_code = |a: u64| bin.code_sections().any(|s| s.contains(a));

    'outer: while let Some(mut a) = work.pop() {
        x.reset();
        loop {
            if insns.contains_key(&a) || insns.len() >= max_insns || !in_code(a) {
                continue 'outer;
            }
            let Some(bytes) = bin.bytes_at(data, a) else {
                continue 'outer;
            };
            let Some(i) = x.decode_one(&bytes[..bytes.len().min(x.max_insn_len())], a) else {
                continue 'outer;
            };
            let next = i.next();
            let flow = i.flow;
            insns.insert(a, i);
            // Running off the end of a function (it ended in a call to something that never
            // returns) must not swallow the next function or the PLT stubs behind it.
            let falls_into_other = |n: u64| known_starts.contains(&n) || stubs.contains_key(&n);
            match flow {
                Flow::Next if falls_into_other(next) => continue 'outer,
                Flow::Call(_) | Flow::IndirectCall(_) if falls_into_other(next) => {
                    if let Flow::Call(t) = flow {
                        calls.push(t);
                    }
                    continue 'outer;
                }
                Flow::Next => a = next,
                Flow::Call(t) => {
                    calls.push(t);
                    let callee = names
                        .get(&t)
                        .map(String::as_str)
                        .or(stubs.get(&t).map(String::as_str));
                    if callee.is_some_and(is_noreturn) {
                        continue 'outer;
                    }
                    a = next;
                }
                Flow::IndirectCall(slot) => {
                    let callee = slot.and_then(|s| names.get(&s));
                    if callee.is_some_and(|n| is_noreturn(n)) {
                        continue 'outer;
                    }
                    a = next;
                }
                Flow::Jump(t) => {
                    // A jump to another function's entry or to a stub is a tail call.
                    if (t != start && known_starts.contains(&t))
                        || stubs.contains_key(&t)
                        || !in_code(t)
                    {
                        if !stubs.contains_key(&t) && in_code(t) {
                            calls.push(t);
                        }
                        continue 'outer;
                    }
                    leaders.insert(t);
                    work.push(t);
                    continue 'outer;
                }
                Flow::CondJump(t) => {
                    leaders.insert(t);
                    leaders.insert(next);
                    work.push(next);
                    work.push(t);
                    continue 'outer;
                }
                Flow::IndirectJump(_) | Flow::Return | Flow::Halt => continue 'outer,
            }
        }
    }

    // Form basic blocks.
    let mut blocks: Vec<Block> = Vec::new();
    let mut cur: Option<Block> = None;
    let mut prev_end: Option<u64> = None;
    for (&a, i) in &insns {
        let starts_new = leaders.contains(&a) || prev_end != Some(a) || cur.is_none();
        if starts_new {
            if let Some(mut b) = cur.take() {
                if let Some(last) = b.insns.last() {
                    if !last.flow.ends_block() && insns.contains_key(&b.end) {
                        b.succs.push((b.end, EdgeKind::Fallthrough));
                    }
                }
                blocks.push(b);
            }
            cur = Some(Block {
                start: a,
                end: a,
                insns: Vec::new(),
                succs: Vec::new(),
            });
        }
        let b = cur.as_mut().expect("block");
        b.end = i.next();
        b.insns.push(i.clone());
        prev_end = Some(i.next());
        if i.flow.ends_block()
            || matches!(i.flow, Flow::Call(t) if names.get(&t).or(stubs.get(&t)).is_some_and(|n| is_noreturn(n)))
        {
            let mut b = cur.take().expect("block");
            match i.flow {
                Flow::Jump(t) if insns.contains_key(&t) => b.succs.push((t, EdgeKind::Jump)),
                Flow::CondJump(t) => {
                    if insns.contains_key(&t) {
                        b.succs.push((t, EdgeKind::True));
                    }
                    if insns.contains_key(&i.next()) {
                        b.succs.push((i.next(), EdgeKind::False));
                    }
                }
                _ => {}
            }
            blocks.push(b);
            prev_end = None;
        }
    }
    if let Some(mut b) = cur.take() {
        if let Some(last) = b.insns.last() {
            if !last.flow.ends_block() && insns.contains_key(&b.end) {
                b.succs.push((b.end, EdgeKind::Fallthrough));
            }
        }
        blocks.push(b);
    }

    // Bytes actually covered by code (robust to hot/cold splitting, where a
    // function's cold path lives far away in `.text.unlikely`).
    let covered: u64 = insns.values().map(|i| i.len()).sum();
    calls.sort_unstable();
    calls.dedup();
    Function {
        addr: start,
        name: String::new(),
        size: covered,
        blocks,
        calls,
        imports_called: Vec::new(),
        strings: Vec::new(),
        thunk_to: None,
    }
}

// ───────────────────────── rendering ─────────────────────────

fn short(i: &Insn) -> String {
    i.text.replace('"', "'")
}

/// Graphviz DOT for one function's CFG.
pub fn cfg_dot(f: &Function) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "digraph \"{}\" {{", f.name.replace('"', "'"));
    let _ = writeln!(
        o,
        "  node [shape=box, fontname=\"monospace\", fontsize=10];"
    );
    let _ = writeln!(
        o,
        "  labelloc=t; label=\"{} @ {:#x}\";",
        f.name.replace('"', "'"),
        f.addr
    );
    for b in &f.blocks {
        let mut label = format!("{:#x}:\\l", b.start);
        for i in &b.insns {
            let _ = write!(label, "{}\\l", short(i).replace('\\', "\\\\"));
        }
        let _ = writeln!(o, "  \"{:x}\" [label=\"{}\"];", b.start, label);
    }
    for b in &f.blocks {
        for (t, k) in &b.succs {
            let color = match k {
                EdgeKind::True => "green",
                EdgeKind::False => "red",
                EdgeKind::Jump => "blue",
                EdgeKind::Fallthrough => "black",
            };
            let _ = writeln!(o, "  \"{:x}\" -> \"{:x}\" [color={color}];", b.start, t);
        }
    }
    o.push_str("}\n");
    o
}

fn mermaid_escape(s: &str) -> String {
    s.replace('"', "#quot;")
        .replace('<', "#lt;")
        .replace('>', "#gt;")
}

/// Mermaid flowchart for one function's CFG (instructions truncated per block).
pub fn cfg_mermaid(f: &Function, max_insns_per_block: usize) -> String {
    let mut o = String::from("flowchart TD\n");
    for b in &f.blocks {
        let mut lines: Vec<String> = vec![format!("{:#x}", b.start)];
        for i in b.insns.iter().take(max_insns_per_block) {
            lines.push(mermaid_escape(&i.text));
        }
        if b.insns.len() > max_insns_per_block {
            lines.push(format!("… +{}", b.insns.len() - max_insns_per_block));
        }
        let _ = writeln!(o, "  b{:x}[\"{}\"]", b.start, lines.join("<br/>"));
    }
    for b in &f.blocks {
        for (t, k) in &b.succs {
            let arrow = match k {
                EdgeKind::True => "-- T -->",
                EdgeKind::False => "-- F -->",
                EdgeKind::Jump => "==>",
                EdgeKind::Fallthrough => "-->",
            };
            let _ = writeln!(o, "  b{:x} {arrow} b{:x}", b.start, t);
        }
    }
    o
}

/// Mermaid call graph rooted at `root`, breadth-first up to `max_nodes`.
pub fn callgraph_mermaid(prog: &Program, root: u64, max_nodes: usize) -> String {
    let mut o = String::from("flowchart LR\n");
    let mut seen = BTreeSet::from([root]);
    let mut q = std::collections::VecDeque::from([root]);
    let mut edges = Vec::new();
    let mut import_nodes = BTreeSet::new();
    while let Some(a) = q.pop_front() {
        let Some(f) = prog.functions.get(&a) else {
            continue;
        };
        for &c in &f.calls {
            if prog.functions.contains_key(&c) {
                edges.push(format!("  f{a:x} --> f{c:x}"));
                if seen.len() < max_nodes && seen.insert(c) {
                    q.push_back(c);
                }
            }
        }
        for imp in f.imports_called.iter().take(8) {
            let id = format!(
                "i_{}",
                imp.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect::<String>()
            );
            edges.push(format!("  f{a:x} -.-> {id}"));
            import_nodes.insert((id, imp.clone()));
        }
    }
    for a in &seen {
        if let Some(f) = prog.functions.get(a) {
            let _ = writeln!(o, "  f{a:x}[\"{}\"]", mermaid_escape(&f.name));
        }
    }
    for (id, name) in &import_nodes {
        let _ = writeln!(o, "  {id}([\"{}\"])", mermaid_escape(name));
    }
    edges.retain(|e| {
        let to = e.rsplit(' ').next().unwrap_or("");
        let from = e.split_whitespace().next().unwrap_or("");
        let ok = |n: &str| {
            n.starts_with("i_")
                || n.strip_prefix('f')
                    .and_then(|h| u64::from_str_radix(h, 16).ok())
                    .is_some_and(|a| seen.contains(&a))
        };
        ok(from) && ok(to)
    });
    edges.sort();
    edges.dedup();
    for e in edges {
        o.push_str(&e);
        o.push('\n');
    }
    o
}

/// Annotated listing of a function (blocks labelled, strings commented).
pub fn function_listing(prog: &Program, f: &Function) -> String {
    let mut o = String::new();
    let _ = writeln!(
        o,
        "; ── {} @ {:#x}  ({} bytes, {} blocks, cyclomatic {})",
        f.name,
        f.addr,
        f.size,
        f.blocks.len(),
        f.cyclomatic()
    );
    let callers = prog.callers();
    if let Some(cs) = callers.get(&f.addr) {
        let _ = writeln!(
            o,
            "; called from: {}",
            cs.iter()
                .take(8)
                .map(|c| prog.name_of(*c))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    for b in &f.blocks {
        if b.start != f.addr {
            let _ = writeln!(o, "loc_{:x}:", b.start);
        }
        for i in &b.insns {
            let hex: String = i
                .bytes
                .iter()
                .take(8)
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(" ");
            let _ = write!(o, "  {:>10x}  {:<24} {}", i.addr, hex, i.text);
            if let Some(s) = i.data_ref.and_then(|r| prog.strings_at.get(&r)) {
                let shown: String = s.chars().take(60).collect();
                let _ = write!(
                    o,
                    "{}; \"{}\"",
                    " ".repeat(36usize.saturating_sub(i.text.len())),
                    shown.escape_debug()
                );
            }
            o.push('\n');
        }
        let succ: Vec<String> = b
            .succs
            .iter()
            .map(|(t, k)| format!("{:?}→{:x}", k, t).to_lowercase())
            .collect();
        if !succ.is_empty() {
            let _ = writeln!(o, "  {:>10}  ; {}", "", succ.join("  "));
        }
    }
    o
}
