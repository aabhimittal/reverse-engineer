//! WebAssembly module inspection.
//!
//! A `.wasm` file is a tiny, regular container: an 8-byte header followed by *sections*, each
//! `(id, length, payload)`. Analogy: a shipping container with a manifest of exactly what it
//! may take from the outside world (**imports**) and what it offers back (**exports**).
//! That makes triage unusually effective: a module can only touch the network or the
//! filesystem through the imports it declares, so reading the import list tells you its
//! reach before you read a single instruction.

use rex_core::{Error, Result};
use serde::Serialize;

const MAX_ITEMS: usize = 1_000_000;

/// Kind of an import/export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ExternKind {
    /// Function.
    Func,
    /// Table.
    Table,
    /// Linear memory.
    Memory,
    /// Global.
    Global,
    /// Exception tag.
    Tag,
}

impl ExternKind {
    /// Lower-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Func => "func",
            Self::Table => "table",
            Self::Memory => "memory",
            Self::Global => "global",
            Self::Tag => "tag",
        }
    }

    fn from(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Func,
            1 => Self::Table,
            2 => Self::Memory,
            3 => Self::Global,
            4 => Self::Tag,
            _ => return None,
        })
    }
}

/// An import.
#[derive(Debug, Clone, Serialize)]
pub struct Import {
    /// Module namespace (`env`, `wasi_snapshot_preview1`, ...).
    pub module: String,
    /// Field name.
    pub name: String,
    /// Kind.
    pub kind: ExternKind,
}

/// An export.
#[derive(Debug, Clone, Serialize)]
pub struct Export {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: ExternKind,
    /// Index in its index space.
    pub index: u32,
}

/// A section as laid out in the file.
#[derive(Debug, Clone, Serialize)]
pub struct Section {
    /// Section id (0 = custom).
    pub id: u8,
    /// Human name (for custom sections, the custom name).
    pub name: String,
    /// File offset of the payload.
    pub offset: usize,
    /// Payload size.
    pub size: usize,
}

/// A linear memory's limits.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Memory {
    /// Minimum pages (64 KiB each).
    pub min: u64,
    /// Maximum pages, if declared.
    pub max: Option<u64>,
    /// Shared (threads).
    pub shared: bool,
}

/// Location of one function body in the file.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Body {
    /// File offset of the first byte of the body (the local-declarations vector).
    pub offset: usize,
    /// Size in bytes.
    pub size: usize,
}

/// A function signature: parameter and result value-type bytes.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FuncType {
    /// Parameter types.
    pub params: Vec<u8>,
    /// Result types.
    pub results: Vec<u8>,
}

/// A parsed module.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Module {
    /// Binary format version (1).
    pub version: u32,
    /// Sections in file order.
    pub sections: Vec<Section>,
    /// Imports.
    pub imports: Vec<Import>,
    /// Exports.
    pub exports: Vec<Export>,
    /// Memories (imported ones excluded).
    pub memories: Vec<Memory>,
    /// Number of defined (non-imported) functions.
    pub defined_functions: usize,
    /// Number of imported functions.
    pub imported_functions: usize,
    /// Function index of the start function, if any.
    pub start: Option<u32>,
    /// Byte size of each function body, in definition order.
    pub body_sizes: Vec<usize>,
    /// Where each function body starts, in definition order.
    pub bodies: Vec<Body>,
    /// Function signatures from the type section.
    pub types: Vec<FuncType>,
    /// Type index of every function, imports first (the function index space).
    pub func_types: Vec<u32>,
    /// Active/passive data segments.
    pub data_segments: usize,
    /// Function names from the `name` custom section: index → name.
    pub names: Vec<(u32, String)>,
    /// Toolchain entries from the `producers` custom section: (field, name, version).
    pub producers: Vec<(String, String, String)>,
    /// Names of custom sections (debug info shows up here: `.debug_info`, `external_debug_info`).
    pub custom: Vec<String>,
}

pub(crate) struct R<'a> {
    pub(crate) d: &'a [u8],
    pub(crate) p: usize,
}

impl<'a> R<'a> {
    pub(crate) fn new(d: &'a [u8], p: usize) -> Self {
        Self { d, p }
    }
    pub(crate) fn eof(&self) -> bool {
        self.p >= self.d.len()
    }
    pub(crate) fn u8(&mut self) -> Result<u8> {
        let b = *self
            .d
            .get(self.p)
            .ok_or_else(|| Error::parse("WASM", "unexpected end of data"))?;
        self.p += 1;
        Ok(b)
    }
    pub(crate) fn leb(&mut self) -> Result<u64> {
        let (mut v, mut shift) = (0u64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            if shift > 70 {
                return Err(Error::parse("WASM", "LEB128 too long"));
            }
        }
    }
    /// Signed LEB128 (up to 64 bits).
    pub(crate) fn sleb(&mut self) -> Result<i64> {
        let (mut v, mut shift) = (0i64, 0u32);
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Ok(v);
            }
            if shift > 70 {
                return Err(Error::parse("WASM", "LEB128 too long"));
            }
        }
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        u32::try_from(self.leb()?).map_err(|_| Error::parse("WASM", "u32 out of range"))
    }
    pub(crate) fn count(&mut self) -> Result<usize> {
        let n = self.u32()? as usize;
        if n > MAX_ITEMS || n > self.d.len() {
            return Err(Error::parse("WASM", format!("implausible item count {n}")));
        }
        Ok(n)
    }
    pub(crate) fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .p
            .checked_add(n)
            .filter(|&e| e <= self.d.len())
            .ok_or_else(|| Error::parse("WASM", "length past end of data"))?;
        let s = &self.d[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn name(&mut self) -> Result<String> {
        let n = self.u32()? as usize;
        Ok(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }
}

fn section_name(id: u8) -> &'static str {
    match id {
        1 => "type",
        2 => "import",
        3 => "function",
        4 => "table",
        5 => "memory",
        6 => "global",
        7 => "export",
        8 => "start",
        9 => "element",
        10 => "code",
        11 => "data",
        12 => "datacount",
        13 => "tag",
        _ => "unknown",
    }
}

fn limits(r: &mut R) -> Result<(u64, Option<u64>, bool)> {
    let flag = r.u8()?;
    let min = r.leb()?;
    let max = if flag & 1 != 0 { Some(r.leb()?) } else { None };
    Ok((min, max, flag & 2 != 0))
}

/// Parse a module. Never panics; malformed input returns an error.
pub fn parse(data: &[u8]) -> Result<Module> {
    if data.len() < 8 || &data[..4] != b"\0asm" {
        return Err(Error::parse("WASM", "missing \\0asm header"));
    }
    let mut m = Module {
        version: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
        ..Default::default()
    };
    let mut r = R::new(data, 8);
    while !r.eof() {
        let id = r.u8()?;
        let size = r.u32()? as usize;
        let offset = r.p;
        let payload = r.bytes(size)?;
        let mut s = R::new(payload, 0);
        let mut name = section_name(id).to_string();
        match id {
            0 => {
                let n = s.name()?;
                name = n.clone();
                m.custom.push(n.clone());
                // Custom sections are advisory: a malformed one must not hide the rest.
                let _ = custom_section(&mut m, &n, &mut s);
            }
            1 => {
                // Unknown type forms (GC proposal) end the list; later sections stay readable.
                let _ = type_section(&mut m, &mut s);
            }
            2 => {
                for _ in 0..s.count()? {
                    let (module, field) = (s.name()?, s.name()?);
                    let kind = ExternKind::from(s.u8()?)
                        .ok_or_else(|| Error::parse("WASM", "bad import kind"))?;
                    match kind {
                        ExternKind::Func => {
                            m.func_types.push(s.u32()?);
                            m.imported_functions += 1;
                        }
                        ExternKind::Table => {
                            s.u8()?;
                            limits(&mut s)?;
                        }
                        ExternKind::Memory => {
                            limits(&mut s)?;
                        }
                        ExternKind::Global => {
                            s.u8()?;
                            s.u8()?;
                        }
                        ExternKind::Tag => {
                            s.u8()?;
                            s.u32()?;
                        }
                    }
                    m.imports.push(Import {
                        module,
                        name: field,
                        kind,
                    });
                }
            }
            3 => {
                m.defined_functions = s.count()?;
                for _ in 0..m.defined_functions {
                    m.func_types.push(s.u32()?);
                }
            }
            5 => {
                for _ in 0..s.count()? {
                    let (min, max, shared) = limits(&mut s)?;
                    m.memories.push(Memory { min, max, shared });
                }
            }
            7 => {
                for _ in 0..s.count()? {
                    let name = s.name()?;
                    let kind = ExternKind::from(s.u8()?)
                        .ok_or_else(|| Error::parse("WASM", "bad export kind"))?;
                    m.exports.push(Export {
                        name,
                        kind,
                        index: s.u32()?,
                    });
                }
            }
            8 => m.start = Some(s.u32()?),
            10 => {
                for _ in 0..s.count()? {
                    let n = s.u32()? as usize;
                    m.bodies.push(Body {
                        offset: offset + s.p,
                        size: n,
                    });
                    s.bytes(n)?;
                    m.body_sizes.push(n);
                }
            }
            11 => m.data_segments = s.count()?,
            _ => {}
        }
        m.sections.push(Section {
            id,
            name,
            offset,
            size,
        });
    }
    Ok(m)
}

fn type_section(m: &mut Module, s: &mut R) -> Result<()> {
    for _ in 0..s.count()? {
        if s.u8()? != 0x60 {
            return Err(Error::parse("WASM", "unsupported type form"));
        }
        let mut t = FuncType::default();
        for _ in 0..s.count()? {
            t.params.push(s.u8()?);
        }
        for _ in 0..s.count()? {
            t.results.push(s.u8()?);
        }
        m.types.push(t);
    }
    Ok(())
}

fn custom_section(m: &mut Module, name: &str, s: &mut R) -> Result<()> {
    match name {
        "name" => {
            while !s.eof() {
                let sub = s.u8()?;
                let len = s.u32()? as usize;
                let body = s.bytes(len)?;
                if sub == 1 {
                    let mut b = R::new(body, 0);
                    for _ in 0..b.count()? {
                        let idx = b.u32()?;
                        let n = b.name()?;
                        m.names.push((idx, n));
                    }
                }
            }
        }
        "producers" => {
            for _ in 0..s.count()? {
                let field = s.name()?;
                for _ in 0..s.count()? {
                    let (n, v) = (s.name()?, s.name()?);
                    m.producers.push((field.clone(), n, v));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

impl Module {
    /// Function index → name (names section), falling back to export names and `func_<n>`.
    pub fn func_name(&self, idx: u32) -> String {
        self.names
            .iter()
            .find(|(i, _)| *i == idx)
            .map(|(_, n)| n.clone())
            .or_else(|| {
                self.exports
                    .iter()
                    .find(|e| e.kind == ExternKind::Func && e.index == idx)
                    .map(|e| e.name.clone())
            })
            .unwrap_or_else(|| format!("func_{idx}"))
    }

    /// Display label for a function index: `module.name` for imports, otherwise [`Self::func_name`].
    pub fn label(&self, idx: u32) -> String {
        if (idx as usize) < self.imported_functions {
            if let Some(i) = self
                .imports
                .iter()
                .filter(|i| i.kind == ExternKind::Func)
                .nth(idx as usize)
            {
                return format!("{}.{}", i.module, i.name);
            }
        }
        self.func_name(idx)
    }

    /// Human signature such as `(i32, i32) -> i32` for a function index.
    pub fn signature(&self, idx: u32) -> Option<String> {
        let t = self
            .types
            .get(*self.func_types.get(idx as usize)? as usize)?;
        let list = |v: &[u8]| v.iter().map(|b| valtype(*b)).collect::<Vec<_>>().join(", ");
        Some(format!("({}) -> ({})", list(&t.params), list(&t.results)))
    }

    /// Does the module carry debug information?
    pub fn has_debug_info(&self) -> bool {
        self.custom.iter().any(|c| {
            c.starts_with(".debug_") || c == "external_debug_info" || c == "sourceMappingURL"
        })
    }
}

/// Name of a value-type byte.
pub fn valtype(b: u8) -> &'static str {
    match b {
        0x7f => "i32",
        0x7e => "i64",
        0x7d => "f32",
        0x7c => "f64",
        0x7b => "v128",
        0x70 => "funcref",
        0x6f => "externref",
        _ => "?",
    }
}

/// WASI imports that grant reach outside the sandbox: (function, what it grants, severity label).
pub const WASI_REACH: &[(&str, &str)] = &[
    ("path_open", "open files and directories"),
    ("path_unlink_file", "delete files"),
    ("path_remove_directory", "delete directories"),
    ("path_create_directory", "create directories"),
    ("path_rename", "rename files"),
    ("sock_accept", "accept network connections"),
    ("sock_send", "send on network sockets"),
    ("sock_recv", "receive from network sockets"),
    ("sock_connect", "open outbound connections"),
    ("proc_exec", "spawn processes"),
    ("environ_get", "read environment variables"),
    ("args_get", "read command-line arguments"),
    ("random_get", "obtain randomness"),
];

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn leb(mut v: u32, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                return;
            }
            out.push(b | 0x80);
        }
    }
    fn name(s: &str, out: &mut Vec<u8>) {
        leb(s.len() as u32, out);
        out.extend(s.as_bytes());
    }
    fn section(id: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.push(id);
        leb(payload.len() as u32, out);
        out.extend(payload);
    }

    /// A small but realistic module: WASI + env imports, memory without a maximum, exports,
    /// a start function, two function bodies, a data segment, names and producers sections.
    pub fn sample() -> Vec<u8> {
        let mut w = b"\0asm\x01\0\0\0".to_vec();
        section(1, &[2, 0x60, 0, 0, 0x60, 1, 0x7f, 1, 0x7f], &mut w); // types: () -> (), (i32) -> i32
        let mut imp = Vec::new();
        leb(3, &mut imp);
        for (m, f) in [
            ("wasi_snapshot_preview1", "path_open"),
            ("wasi_snapshot_preview1", "sock_connect"),
            ("env", "log"),
        ] {
            name(m, &mut imp);
            name(f, &mut imp);
            imp.extend([0, 0]); // func, type 0
        }
        section(2, &imp, &mut w);
        section(3, &[2, 0, 1], &mut w); // two defined functions: run () and decrypt_config (i32) -> i32
        section(5, &[1, 0, 1], &mut w); // memory: min 1, no max
        let mut exp = Vec::new();
        leb(2, &mut exp);
        name("memory", &mut exp);
        exp.extend([2, 0]);
        name("run", &mut exp);
        exp.extend([0, 3]); // func index 3 (after 3 imports)
        section(7, &exp, &mut w);
        section(8, &[3], &mut w); // start = func 3
        // run: three imported calls, then decrypt_config(42); decrypt_config: a counting loop with br_if.
        section(
            10,
            &[
                2, 0x0d, 0, 0x10, 0, 0x10, 1, 0x10, 2, 0x41, 0x2a, 0x10, 4, 0x1a, 0x0b, 0x15, 1, 1,
                0x7f, 3, 0x40, 0x20, 1, 0x41, 1, 0x6a, 0x22, 1, 0x20, 0, 0x49, 0x0d, 0, 0x0b, 0x20,
                1, 0x0b,
            ],
            &mut w,
        );
        let mut data = vec![1, 0, 0x41, 0, 0x0b];
        leb(5, &mut data);
        data.extend(b"hello");
        section(11, &data, &mut w);
        let mut names = Vec::new();
        names.push(1u8);
        let mut sub = Vec::new();
        leb(1, &mut sub);
        leb(4, &mut sub);
        name("decrypt_config", &mut sub);
        leb(sub.len() as u32, &mut names);
        names.extend(sub);
        let mut custom = Vec::new();
        name("name", &mut custom);
        custom.extend(names);
        section(0, &custom, &mut w);
        let mut prod = Vec::new();
        name("producers", &mut prod);
        leb(1, &mut prod);
        name("processed-by", &mut prod);
        leb(1, &mut prod);
        name("rustc", &mut prod);
        name("1.80.0", &mut prod);
        section(0, &prod, &mut w);
        w
    }

    #[test]
    fn parses_sample() {
        let d = sample();
        assert_eq!(
            rex_core::detect_bytes(&d, None),
            rex_core::ArtifactKind::Wasm
        );
        let m = parse(&d).unwrap();
        assert_eq!(m.version, 1);
        assert_eq!(m.imports.len(), 3);
        assert_eq!(m.imported_functions, 3);
        assert_eq!(m.defined_functions, 2);
        assert_eq!(m.body_sizes, vec![13, 21]);
        assert_eq!(m.start, Some(3));
        assert_eq!(m.data_segments, 1);
        assert!(m.memories[0].max.is_none() && m.memories[0].min == 1);
        assert_eq!(m.func_name(4), "decrypt_config");
        assert_eq!(m.func_name(3), "run", "falls back to the export name");
        assert_eq!(m.func_name(9), "func_9");
        assert_eq!(
            m.producers,
            vec![("processed-by".into(), "rustc".into(), "1.80.0".into())]
        );
        assert!(m.sections.iter().any(|s| s.name == "name"));
        assert!(!m.has_debug_info());
    }

    #[test]
    fn malformed_input_is_an_error_not_a_panic() {
        let d = sample();
        assert!(parse(b"nope").is_err());
        for cut in 0..d.len() {
            let _ = parse(&d[..cut]);
        }
        let mut huge = b"\0asm\x01\0\0\0".to_vec();
        huge.extend([2, 0x05, 0xff, 0xff, 0xff, 0xff, 0x0f]); // import section claiming 4 billion entries
        assert!(parse(&huge).is_err());
        let mut deep = b"\0asm\x01\0\0\0".to_vec();
        deep.extend([
            0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]);
        assert!(parse(&deep).is_err());
        for i in 8..d.len() {
            let mut x = d.clone();
            x[i] ^= 0xa5;
            let _ = parse(&x);
        }
    }

    #[test]
    fn committed_lab_matches_the_unit_test_module() {
        let lab =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../labs/wasm/sample.wasm");
        assert_eq!(
            std::fs::read(&lab).unwrap(),
            sample(),
            "labs/wasm/make_wasm.py and wasm::tests::sample() have drifted apart"
        );
    }
}
