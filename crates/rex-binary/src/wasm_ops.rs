//! WebAssembly instruction decoder: turns a function body into a WAT-like listing.
//!
//! WASM is a structured stack machine: there are no addresses to jump to, only nested
//! `block`/`loop`/`if` labels and relative `br` depths. A reader's job is to recover which label
//! each `br N` targets, which is why the listing indents by nesting and annotates every branch.
//!
//! The decoder is total: every read is bounds-checked, an unknown opcode stops that one function
//! (reported as incomplete), and the operation count is capped.

use crate::wasm::{Module, R, valtype};
use rex_core::{Error, Result};
use serde::Serialize;

const MAX_OPS: usize = 250_000;

/// One decoded instruction.
#[derive(Debug, Clone, Serialize)]
pub struct Op {
    /// File offset of the opcode.
    pub offset: usize,
    /// Structured nesting depth (for indentation).
    pub depth: usize,
    /// Instruction text, with branch targets and callee names resolved.
    pub text: String,
    /// Callee function index for `call` / `return_call`.
    pub call: Option<u32>,
    /// True for `call_indirect` / `return_call_indirect` (target unknowable statically).
    pub indirect: bool,
}

/// A disassembled function.
#[derive(Debug, Clone, Serialize)]
pub struct Listing {
    /// Function index (imports first).
    pub index: u32,
    /// Display name.
    pub name: String,
    /// `(params) -> (results)` when the type section was readable.
    pub signature: Option<String>,
    /// Declared locals, e.g. `2 x i32`.
    pub locals: Vec<String>,
    /// Instructions.
    pub ops: Vec<Op>,
    /// False when decoding stopped early (unknown opcode, truncated body or op cap).
    pub complete: bool,
}

impl Listing {
    /// Render as text.
    pub fn render(&self) -> String {
        use std::fmt::Write;
        let mut o = String::new();
        let _ = write!(o, ";; func {} ${}", self.index, self.name);
        if let Some(sig) = &self.signature {
            let _ = write!(o, " {sig}");
        }
        o.push('\n');
        if !self.locals.is_empty() {
            let _ = writeln!(o, ";; locals: {}", self.locals.join(", "));
        }
        for op in &self.ops {
            let _ = writeln!(o, "{:08x}  {}{}", op.offset, "  ".repeat(op.depth), op.text);
        }
        if !self.complete {
            o.push_str(";; (decoding stopped early: unknown opcode or truncated body)\n");
        }
        o
    }

    /// Distinct direct callees, in first-call order.
    pub fn callees(&self) -> Vec<u32> {
        let mut seen = Vec::new();
        for c in self.ops.iter().filter_map(|o| o.call) {
            if !seen.contains(&c) {
                seen.push(c);
            }
        }
        seen
    }
}

const NUMERIC: [&str; 128] = [
    "i32.eqz",
    "i32.eq",
    "i32.ne",
    "i32.lt_s",
    "i32.lt_u",
    "i32.gt_s",
    "i32.gt_u",
    "i32.le_s",
    "i32.le_u",
    "i32.ge_s",
    "i32.ge_u",
    "i64.eqz",
    "i64.eq",
    "i64.ne",
    "i64.lt_s",
    "i64.lt_u",
    "i64.gt_s",
    "i64.gt_u",
    "i64.le_s",
    "i64.le_u",
    "i64.ge_s",
    "i64.ge_u",
    "f32.eq",
    "f32.ne",
    "f32.lt",
    "f32.gt",
    "f32.le",
    "f32.ge",
    "f64.eq",
    "f64.ne",
    "f64.lt",
    "f64.gt",
    "f64.le",
    "f64.ge",
    "i32.clz",
    "i32.ctz",
    "i32.popcnt",
    "i32.add",
    "i32.sub",
    "i32.mul",
    "i32.div_s",
    "i32.div_u",
    "i32.rem_s",
    "i32.rem_u",
    "i32.and",
    "i32.or",
    "i32.xor",
    "i32.shl",
    "i32.shr_s",
    "i32.shr_u",
    "i32.rotl",
    "i32.rotr",
    "i64.clz",
    "i64.ctz",
    "i64.popcnt",
    "i64.add",
    "i64.sub",
    "i64.mul",
    "i64.div_s",
    "i64.div_u",
    "i64.rem_s",
    "i64.rem_u",
    "i64.and",
    "i64.or",
    "i64.xor",
    "i64.shl",
    "i64.shr_s",
    "i64.shr_u",
    "i64.rotl",
    "i64.rotr",
    "f32.abs",
    "f32.neg",
    "f32.ceil",
    "f32.floor",
    "f32.trunc",
    "f32.nearest",
    "f32.sqrt",
    "f32.add",
    "f32.sub",
    "f32.mul",
    "f32.div",
    "f32.min",
    "f32.max",
    "f32.copysign",
    "f64.abs",
    "f64.neg",
    "f64.ceil",
    "f64.floor",
    "f64.trunc",
    "f64.nearest",
    "f64.sqrt",
    "f64.add",
    "f64.sub",
    "f64.mul",
    "f64.div",
    "f64.min",
    "f64.max",
    "f64.copysign",
    "i32.wrap_i64",
    "i32.trunc_f32_s",
    "i32.trunc_f32_u",
    "i32.trunc_f64_s",
    "i32.trunc_f64_u",
    "i64.extend_i32_s",
    "i64.extend_i32_u",
    "i64.trunc_f32_s",
    "i64.trunc_f32_u",
    "i64.trunc_f64_s",
    "i64.trunc_f64_u",
    "f32.convert_i32_s",
    "f32.convert_i32_u",
    "f32.convert_i64_s",
    "f32.convert_i64_u",
    "f32.demote_f64",
    "f64.convert_i32_s",
    "f64.convert_i32_u",
    "f64.convert_i64_s",
    "f64.convert_i64_u",
    "f64.promote_f32",
    "i32.reinterpret_f32",
    "i64.reinterpret_f64",
    "f32.reinterpret_i32",
    "f64.reinterpret_i64",
    "i32.extend8_s",
    "i32.extend16_s",
    "i64.extend8_s",
    "i64.extend16_s",
    "i64.extend32_s",
];

const MEMORY: [&str; 23] = [
    "i32.load",
    "i64.load",
    "f32.load",
    "f64.load",
    "i32.load8_s",
    "i32.load8_u",
    "i32.load16_s",
    "i32.load16_u",
    "i64.load8_s",
    "i64.load8_u",
    "i64.load16_s",
    "i64.load16_u",
    "i64.load32_s",
    "i64.load32_u",
    "i32.store",
    "i64.store",
    "f32.store",
    "f64.store",
    "i32.store8",
    "i32.store16",
    "i64.store8",
    "i64.store16",
    "i64.store32",
];

const SAT: [&str; 8] = [
    "i32.trunc_sat_f32_s",
    "i32.trunc_sat_f32_u",
    "i32.trunc_sat_f64_s",
    "i32.trunc_sat_f64_u",
    "i64.trunc_sat_f32_s",
    "i64.trunc_sat_f32_u",
    "i64.trunc_sat_f64_s",
    "i64.trunc_sat_f64_u",
];

fn block_type(r: &mut R, m: &Module) -> Result<String> {
    let v = r.sleb()?;
    Ok(if v == -64 {
        String::new()
    } else if v < 0 {
        format!(" (result {})", valtype((v & 0x7f) as u8))
    } else {
        match m.types.get(v as usize) {
            Some(t) if t.params.is_empty() && t.results.len() == 1 => {
                format!(" (result {})", valtype(t.results[0]))
            }
            _ => format!(" (type {v})"),
        }
    })
}

fn memarg(r: &mut R) -> Result<String> {
    let align = r.u32()?;
    let mem = if align & 0x40 != 0 {
        Some(r.u32()?)
    } else {
        None
    };
    let offset = r.u32()?;
    let mut s = String::new();
    if let Some(m) = mem {
        s.push_str(&format!(" mem={m}"));
    }
    if offset != 0 {
        s.push_str(&format!(" offset={offset}"));
    }
    s.push_str(&format!(" align={}", 1u64 << (align & 0x3f).min(63)));
    Ok(s)
}

/// Disassemble one function by index (imports are not disassemblable).
pub fn disassemble(m: &Module, data: &[u8], index: u32) -> Result<Listing> {
    let def = (index as usize)
        .checked_sub(m.imported_functions)
        .ok_or_else(|| Error::Other(format!("function {index} is an import and has no body")))?;
    let body = m
        .bodies
        .get(def)
        .ok_or_else(|| Error::Other(format!("no function with index {index}")))?;
    let bytes = data
        .get(body.offset..body.offset.saturating_add(body.size))
        .ok_or_else(|| Error::parse("WASM", "function body past end of file"))?;
    let mut r = R::new(bytes, 0);

    let mut locals = Vec::new();
    for _ in 0..r.count()? {
        let n = r.u32()?;
        let t = r.u8()?;
        locals.push(format!("{n} x {}", valtype(t)));
    }

    let mut ops = Vec::new();
    // (kind, offset) of enclosing labels; index 0 is the function itself.
    let mut labels: Vec<(&'static str, usize)> = vec![("func", body.offset)];
    let mut complete = false;

    while !r.eof() && ops.len() < MAX_OPS {
        let at = body.offset + r.p;
        let opc = r.u8()?;
        let mut depth = labels.len() - 1;
        let mut call = None;
        let mut indirect = false;
        let res: Result<String> = (|| {
            Ok(match opc {
                0x00 => "unreachable".into(),
                0x01 => "nop".into(),
                0x02 | 0x03 | 0x04 | 0x06 => {
                    let kind = match opc {
                        0x02 => "block",
                        0x03 => "loop",
                        0x04 => "if",
                        _ => "try",
                    };
                    let t = block_type(&mut r, m)?;
                    labels.push((kind, at));
                    format!("{kind}{t}")
                }
                0x05 | 0x19 => {
                    depth = depth.saturating_sub(1);
                    if opc == 0x05 { "else" } else { "catch_all" }.into()
                }
                0x07 => {
                    depth = depth.saturating_sub(1);
                    format!("catch tag={}", r.u32()?)
                }
                0x08 => format!("throw tag={}", r.u32()?),
                0x09 => format!("rethrow {}", r.u32()?),
                0x0b => {
                    if labels.len() == 1 {
                        complete = true;
                        depth = 0;
                    } else {
                        labels.pop();
                        depth = labels.len() - 1;
                    }
                    "end".into()
                }
                0x0c | 0x0d | 0x18 => {
                    let n = r.u32()?;
                    let name = match opc {
                        0x0c => "br",
                        0x0d => "br_if",
                        _ => "delegate",
                    };
                    format!("{name} {n}{}", label_note(&labels, n))
                }
                0x0e => {
                    let count = r.count()?;
                    let mut targets = Vec::with_capacity(count);
                    for _ in 0..count {
                        targets.push(r.u32()?);
                    }
                    let default = r.u32()?;
                    format!(
                        "br_table {} default={default}",
                        targets
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(" ")
                    )
                }
                0x0f => "return".into(),
                0x10 | 0x12 => {
                    let f = r.u32()?;
                    call = Some(f);
                    let name = if opc == 0x10 { "call" } else { "return_call" };
                    format!("{name} ${}  ;; func {f}", m.label(f))
                }
                0x11 | 0x13 => {
                    let (ty, table) = (r.u32()?, r.u32()?);
                    indirect = true;
                    let name = if opc == 0x11 {
                        "call_indirect"
                    } else {
                        "return_call_indirect"
                    };
                    format!("{name} (type {ty}) table={table}")
                }
                0x1a => "drop".into(),
                0x1b => "select".into(),
                0x1c => {
                    let n = r.count()?;
                    let mut ts = Vec::new();
                    for _ in 0..n {
                        ts.push(valtype(r.u8()?));
                    }
                    format!("select (result {})", ts.join(" "))
                }
                0x20 => format!("local.get {}", r.u32()?),
                0x21 => format!("local.set {}", r.u32()?),
                0x22 => format!("local.tee {}", r.u32()?),
                0x23 => format!("global.get {}", r.u32()?),
                0x24 => format!("global.set {}", r.u32()?),
                0x25 => format!("table.get {}", r.u32()?),
                0x26 => format!("table.set {}", r.u32()?),
                0x28..=0x3e => format!("{}{}", MEMORY[(opc - 0x28) as usize], memarg(&mut r)?),
                0x3f => {
                    r.u32()?;
                    "memory.size".into()
                }
                0x40 => {
                    r.u32()?;
                    "memory.grow".into()
                }
                0x41 => format!("i32.const {}", r.sleb()? as i32),
                0x42 => format!("i64.const {}", r.sleb()?),
                0x43 => {
                    let b = r.bytes(4)?;
                    format!("f32.const {}", f32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                }
                0x44 => {
                    let b = r.bytes(8)?;
                    format!(
                        "f64.const {}",
                        f64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                    )
                }
                0x45..=0xc4 => NUMERIC[(opc - 0x45) as usize].into(),
                0xd0 => format!("ref.null {}", valtype(r.u8()?)),
                0xd1 => "ref.is_null".into(),
                0xd2 => {
                    let f = r.u32()?;
                    format!("ref.func ${}  ;; func {f}", m.label(f))
                }
                0xfc => prefixed_fc(&mut r)?,
                0xfd => prefixed_simd(&mut r)?,
                0xfe => prefixed_atomic(&mut r)?,
                other => {
                    return Err(Error::parse(
                        "WASM",
                        format!("unknown opcode {other:#04x} at {at:#x}"),
                    ));
                }
            })
        })();
        match res {
            Ok(text) => ops.push(Op {
                offset: at,
                depth,
                text,
                call,
                indirect,
            }),
            Err(_) => break,
        }
        if complete {
            break;
        }
    }

    Ok(Listing {
        index,
        name: m.label(index),
        signature: m.signature(index),
        locals,
        ops,
        complete,
    })
}

fn label_note(labels: &[(&'static str, usize)], n: u32) -> String {
    match labels
        .len()
        .checked_sub(1 + n as usize)
        .and_then(|i| labels.get(i))
    {
        Some(("func", _)) => "  ;; -> function exit".into(),
        Some(("loop", off)) => format!("  ;; -> loop @{off:#x} (repeat)"),
        Some((kind, off)) => format!("  ;; -> end of {kind} @{off:#x}"),
        None => "  ;; -> ? (out of range)".into(),
    }
}

fn prefixed_fc(r: &mut R) -> Result<String> {
    let sub = r.u32()?;
    Ok(match sub {
        0..=7 => SAT[sub as usize].into(),
        8 => {
            let (d, m) = (r.u32()?, r.u32()?);
            format!("memory.init data={d} mem={m}")
        }
        9 => format!("data.drop {}", r.u32()?),
        10 => {
            let (a, b) = (r.u32()?, r.u32()?);
            format!("memory.copy {a} {b}")
        }
        11 => format!("memory.fill {}", r.u32()?),
        12 => {
            let (e, t) = (r.u32()?, r.u32()?);
            format!("table.init elem={e} table={t}")
        }
        13 => format!("elem.drop {}", r.u32()?),
        14 => {
            let (a, b) = (r.u32()?, r.u32()?);
            format!("table.copy {a} {b}")
        }
        15 => format!("table.grow {}", r.u32()?),
        16 => format!("table.size {}", r.u32()?),
        17 => format!("table.fill {}", r.u32()?),
        n => return Err(Error::parse("WASM", format!("unknown 0xfc op {n}"))),
    })
}

/// SIMD: decode immediates exactly (so the stream stays in sync) but only name the common ops.
fn prefixed_simd(r: &mut R) -> Result<String> {
    let sub = r.u32()?;
    Ok(match sub {
        0 => format!("v128.load{}", memarg(r)?),
        1..=10 => format!("simd.mem_{sub:#x}{}", memarg(r)?),
        11 => format!("v128.store{}", memarg(r)?),
        12 => {
            let b = r.bytes(16)?;
            format!("v128.const {}", rex_core::hash::hex(b))
        }
        13 => {
            let b = r.bytes(16)?;
            format!(
                "i8x16.shuffle {}",
                b.iter().map(u8::to_string).collect::<Vec<_>>().join(" ")
            )
        }
        21..=34 => format!("simd.lane_{sub:#x} {}", r.u8()?),
        84..=91 => {
            let m = memarg(r)?;
            format!("simd.mem_lane_{sub:#x}{m} lane={}", r.u8()?)
        }
        92 | 93 => format!("simd.mem_{sub:#x}{}", memarg(r)?),
        n => format!("simd.{n:#x}"),
    })
}

fn prefixed_atomic(r: &mut R) -> Result<String> {
    let sub = r.u32()?;
    Ok(if sub == 3 {
        r.u8()?;
        "atomic.fence".into()
    } else {
        format!("atomic.{sub:#x}{}", memarg(r)?)
    })
}

/// Direct call edges `(caller, callee)` for every defined function, in index order.
pub fn call_edges(m: &Module, data: &[u8]) -> Vec<(u32, u32)> {
    let mut edges = Vec::new();
    for i in 0..m.defined_functions {
        let idx = (m.imported_functions + i) as u32;
        if let Ok(l) = disassemble(m, data, idx) {
            edges.extend(l.callees().into_iter().map(|c| (idx, c)));
        }
    }
    edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wasm::{parse, tests::sample};

    #[test]
    fn disassembles_run_with_resolved_callees() {
        let d = sample();
        let m = parse(&d).unwrap();
        let l = disassemble(&m, &d, 3).unwrap();
        assert!(l.complete);
        let text = l.render();
        assert!(
            text.contains("call $wasi_snapshot_preview1.path_open  ;; func 0"),
            "{text}"
        );
        assert!(
            text.contains("call $wasi_snapshot_preview1.sock_connect"),
            "{text}"
        );
        assert!(text.contains("call $env.log"), "{text}");
        assert!(text.contains("i32.const 42"), "{text}");
        assert!(text.contains("call $decrypt_config  ;; func 4"), "{text}");
        assert_eq!(l.callees(), vec![0, 1, 2, 4]);
    }

    #[test]
    fn loop_branches_are_annotated_and_indented() {
        let d = sample();
        let m = parse(&d).unwrap();
        let l = disassemble(&m, &d, 4).unwrap();
        assert!(l.complete);
        assert_eq!(l.locals, vec!["1 x i32"]);
        assert_eq!(l.signature.as_deref(), Some("(i32) -> (i32)"));
        let text = l.render();
        assert!(text.contains("br_if 0  ;; -> loop @"), "{text}");
        let inner = l
            .ops
            .iter()
            .find(|o| o.text.starts_with("i32.add"))
            .unwrap();
        assert_eq!(inner.depth, 1, "loop body is indented one level");
        assert_eq!(l.ops.last().unwrap().text, "end");
        assert_eq!(l.ops.last().unwrap().depth, 0);
    }

    #[test]
    fn decoded_length_covers_the_whole_body() {
        let d = sample();
        let m = parse(&d).unwrap();
        for (i, b) in m.bodies.iter().enumerate() {
            let l = disassemble(&m, &d, (m.imported_functions + i) as u32).unwrap();
            assert!(l.complete, "func {i}");
            let last = l.ops.last().unwrap();
            assert_eq!(
                last.offset + 1,
                b.offset + b.size,
                "`end` is the final byte of func {i}"
            );
        }
    }

    #[test]
    fn imports_have_no_body_and_bad_indices_error() {
        let d = sample();
        let m = parse(&d).unwrap();
        assert!(disassemble(&m, &d, 0).is_err());
        assert!(disassemble(&m, &d, 99).is_err());
    }

    #[test]
    fn call_edges_cover_the_module() {
        let d = sample();
        let m = parse(&d).unwrap();
        let e = call_edges(&m, &d);
        assert!(e.contains(&(3, 0)) && e.contains(&(3, 4)));
        assert!(
            !e.iter().any(|(c, _)| *c == 4),
            "decrypt_config calls nothing"
        );
    }

    #[test]
    fn mutated_modules_never_panic() {
        let good = sample();
        let mut seed = 0x9e3779b9u32;
        for _ in 0..3000 {
            let mut d = good.clone();
            for _ in 0..3 {
                seed = seed.wrapping_mul(1664525).wrapping_add(1013904223);
                let i = (seed >> 8) as usize % d.len();
                d[i] ^= (seed & 0xff) as u8;
            }
            if let Ok(m) = parse(&d) {
                for i in 0..(m.imported_functions + m.defined_functions + 2) {
                    let _ = disassemble(&m, &d, i as u32).map(|l| l.render());
                }
            }
        }
    }

    #[test]
    fn prefixed_and_memory_ops_decode() {
        let mut m = Module {
            defined_functions: 1,
            ..Default::default()
        };
        // locals: none; i32.const 5; i32.load align=4 offset=16; memory.copy 0 0; i32.trunc_sat_f32_s; end
        let body: Vec<u8> = vec![
            0x00, 0x41, 0x05, 0x28, 0x02, 0x10, 0xfc, 0x0a, 0x00, 0x00, 0xfc, 0x00, 0x0b,
        ];
        m.bodies.push(crate::wasm::Body {
            offset: 0,
            size: body.len(),
        });
        let l = disassemble(&m, &body, 0).unwrap();
        let text = l.render();
        assert!(text.contains("i32.load offset=16 align=4"), "{text}");
        assert!(text.contains("memory.copy 0 0"), "{text}");
        assert!(text.contains("i32.trunc_sat_f32_s"), "{text}");
        assert!(l.complete);
    }
}
