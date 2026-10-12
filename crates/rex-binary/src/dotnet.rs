//! .NET assemblies: CLI metadata (ECMA-335 partition II).
//!
//! A .NET executable is a PE file whose real program is CIL bytecode described by metadata
//! tables. Those tables name every type and method, every referenced assembly, and every native
//! function the code calls through P/Invoke. That last list is the .NET equivalent of a PE import
//! table: `kernel32!VirtualAllocEx` reached through `[DllImport]` never appears in the PE imports.
//!
//! ```text
//! CLR header (data directory 14) ─► metadata root "BSJB": version string, stream headers
//!   #~ (or #-)  table stream: row counts, then each present table back to back
//!   #Strings    NUL-terminated UTF-8 names         #US    user strings (UTF-16, length-prefixed)
//!   #Blob       signatures and constants           #GUID  16-byte GUIDs
//! ```
//!
//! Row sizes depend on heap sizes and on how many rows other tables have (index columns are 2 or
//! 4 bytes), so every table's layout is computed from the schema below before any row is read.
//! All offsets come from the file and every read is bounds-checked.

use serde::Serialize;

/// What the metadata says about an assembly.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DotNet {
    /// Runtime the metadata targets, e.g. `v4.0.30319`.
    pub runtime: String,
    /// Assembly name and version, if this is an assembly (not a bare module).
    pub assembly: Option<(String, String)>,
    /// Referenced assemblies: name, version.
    pub assembly_refs: Vec<(String, String)>,
    /// Native modules named by P/Invoke (`ModuleRef`).
    pub module_refs: Vec<String>,
    /// P/Invoke imports: native module, imported name, managed method name.
    pub pinvokes: Vec<(String, String, String)>,
    /// Type names (`Namespace.Name`), capped.
    pub types: Vec<String>,
    /// Number of TypeDef rows.
    pub type_count: usize,
    /// Number of MethodDef rows.
    pub method_count: usize,
    /// Strings from `#US` (string literals in the code), capped.
    pub user_strings: Vec<String>,
    /// CLR header flags: IL only, 32-bit required, strong-name signed.
    pub il_only: bool,
    /// Strong-name signed.
    pub strong_named: bool,
}

const MAX_LIST: usize = 5000;

/// Column kinds.
#[derive(Clone, Copy)]
enum C {
    U16,
    U32,
    Str,
    Guid,
    Blob,
    /// Index into one table.
    T(u8),
    /// Coded index: tag bits and the tables it can point into (`0xff` = unused tag value).
    Coded(u8, &'static [u8]),
}

const TYPE_DEF_OR_REF: C = C::Coded(2, &[0x02, 0x01, 0x1b]);
const HAS_CONSTANT: C = C::Coded(2, &[0x04, 0x08, 0x17]);
const HAS_CUSTOM_ATTRIBUTE: C = C::Coded(
    5,
    &[
        0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0a, 0x00, 0x0e, 0x17, 0x14, 0x11, 0x1a, 0x1b, 0x20,
        0x23, 0x26, 0x27, 0x28, 0x2a, 0x2c, 0x2b,
    ],
);
const HAS_FIELD_MARSHAL: C = C::Coded(1, &[0x04, 0x08]);
const HAS_DECL_SECURITY: C = C::Coded(2, &[0x02, 0x06, 0x20]);
const MEMBER_REF_PARENT: C = C::Coded(3, &[0x02, 0x01, 0x1a, 0x06, 0x1b]);
const HAS_SEMANTICS: C = C::Coded(1, &[0x14, 0x17]);
const METHOD_DEF_OR_REF: C = C::Coded(1, &[0x06, 0x0a]);
const MEMBER_FORWARDED: C = C::Coded(1, &[0x04, 0x06]);
const IMPLEMENTATION: C = C::Coded(2, &[0x26, 0x23, 0x27]);
const CUSTOM_ATTRIBUTE_TYPE: C = C::Coded(3, &[0xff, 0xff, 0x06, 0x0a, 0xff]);
const RESOLUTION_SCOPE: C = C::Coded(2, &[0x00, 0x1a, 0x23, 0x01]);
const TYPE_OR_METHOD_DEF: C = C::Coded(1, &[0x02, 0x06]);

/// Column layout of every table, by table number (ECMA-335 II.22).
fn schema(t: usize) -> &'static [C] {
    use C::*;
    match t {
        0x00 => &[U16, Str, Guid, Guid, Guid],
        0x01 => &[RESOLUTION_SCOPE, Str, Str],
        0x02 => &[U32, Str, Str, TYPE_DEF_OR_REF, T(0x04), T(0x06)],
        0x03 => &[T(0x04)],
        0x04 => &[U16, Str, Blob],
        0x05 => &[T(0x06)],
        0x06 => &[U32, U16, U16, Str, Blob, T(0x08)],
        0x07 => &[T(0x08)],
        0x08 => &[U16, U16, Str],
        0x09 => &[T(0x02), TYPE_DEF_OR_REF],
        0x0a => &[MEMBER_REF_PARENT, Str, Blob],
        0x0b => &[U16, HAS_CONSTANT, Blob],
        0x0c => &[HAS_CUSTOM_ATTRIBUTE, CUSTOM_ATTRIBUTE_TYPE, Blob],
        0x0d => &[HAS_FIELD_MARSHAL, Blob],
        0x0e => &[U16, HAS_DECL_SECURITY, Blob],
        0x0f => &[U16, U32, T(0x02)],
        0x10 => &[U32, T(0x04)],
        0x11 => &[Blob],
        0x12 => &[T(0x02), T(0x14)],
        0x13 => &[T(0x14)],
        0x14 => &[U16, Str, TYPE_DEF_OR_REF],
        0x15 => &[T(0x02), T(0x17)],
        0x16 => &[T(0x17)],
        0x17 => &[U16, Str, Blob],
        0x18 => &[U16, T(0x06), HAS_SEMANTICS],
        0x19 => &[T(0x02), METHOD_DEF_OR_REF, METHOD_DEF_OR_REF],
        0x1a => &[Str],
        0x1b => &[Blob],
        0x1c => &[U16, MEMBER_FORWARDED, Str, T(0x1a)],
        0x1d => &[U32, T(0x04)],
        0x1e => &[U32, U32],
        0x1f => &[U32],
        0x20 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        0x21 => &[U32],
        0x22 => &[U32, U32, U32],
        0x23 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        0x24 => &[U32, T(0x23)],
        0x25 => &[U32, U32, U32, T(0x23)],
        0x26 => &[U32, Str, Blob],
        0x27 => &[U32, U32, Str, Str, IMPLEMENTATION],
        0x28 => &[U32, U32, Str, IMPLEMENTATION],
        0x29 => &[T(0x02), T(0x02)],
        0x2a => &[U16, U16, TYPE_OR_METHOD_DEF, Str],
        0x2b => &[METHOD_DEF_OR_REF, Blob],
        0x2c => &[T(0x2a), TYPE_DEF_OR_REF],
        _ => &[],
    }
}

fn u16_at(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(o..o.checked_add(2)?)?.try_into().ok()?,
    ))
}
fn u32_at(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(o..o.checked_add(4)?)?.try_into().ok()?,
    ))
}

struct Tables<'d> {
    data: &'d [u8],
    rows: [u32; 64],
    /// Byte offset of each table's first row, and its row size.
    start: [usize; 64],
    row_size: [usize; 64],
    widths: [Vec<usize>; 64],
    strings: &'d [u8],
    blob: &'d [u8],
}

impl Tables<'_> {
    fn col(&self, t: usize, row: u32, col: usize) -> Option<u32> {
        if row == 0 || row > self.rows[t] {
            return None;
        }
        let w = &self.widths[t];
        let off = self.start[t]
            .checked_add((row as usize - 1).checked_mul(self.row_size[t])?)?
            .checked_add(w[..col].iter().sum::<usize>())?;
        match w[col] {
            2 => u16_at(self.data, off).map(u32::from),
            _ => u32_at(self.data, off),
        }
    }
    fn string(&self, idx: u32) -> String {
        let s = self.strings.get(idx as usize..).unwrap_or_default();
        let end = s.iter().take(1024).position(|&b| b == 0).unwrap_or(0);
        String::from_utf8_lossy(&s[..end]).into_owned()
    }
    fn version(&self, t: usize, row: u32) -> String {
        let p: Vec<u32> = (0..4).filter_map(|c| self.col(t, row, c)).collect();
        p.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
    }
}

/// Parse the metadata root at `meta` (a slice starting at "BSJB").
pub fn parse(meta: &[u8], cor_flags: u32) -> Option<DotNet> {
    if meta.get(..4)? != b"BSJB" {
        return None;
    }
    let vlen = u32_at(meta, 12)? as usize;
    if vlen > 255 {
        return None;
    }
    let runtime = String::from_utf8_lossy(meta.get(16..16 + vlen)?)
        .trim_end_matches('\0')
        .to_string();
    let mut p = 16 + vlen + 2; // flags u16
    let nstreams = u16_at(meta, p)? as usize;
    p += 2;
    let mut streams = std::collections::HashMap::new();
    for _ in 0..nstreams.min(16) {
        let off = u32_at(meta, p)? as usize;
        let size = u32_at(meta, p + 4)? as usize;
        let name_at = p + 8;
        let name_len = meta.get(name_at..)?.iter().take(32).position(|&b| b == 0)?;
        let name = String::from_utf8_lossy(&meta[name_at..name_at + name_len]).into_owned();
        // Name is NUL-terminated and padded to a multiple of 4.
        p = name_at + ((name_len + 4) & !3);
        let body = meta.get(off..off.checked_add(size)?.min(meta.len()))?;
        streams.insert(name, body);
    }
    let tilde = streams.get("#~").or_else(|| streams.get("#-"))?;
    let mut dn = DotNet {
        runtime,
        il_only: cor_flags & 1 != 0,
        strong_named: cor_flags & 8 != 0,
        ..Default::default()
    };

    // Table stream header: reserved u32, major, minor, heap sizes, reserved, valid u64, sorted u64.
    let heap = *tilde.get(6)?;
    let valid = u64::from_le_bytes(tilde.get(8..16)?.try_into().ok()?);
    let mut rows = [0u32; 64];
    let mut at = 24;
    for (t, r) in rows.iter_mut().enumerate() {
        if valid >> t & 1 == 1 {
            *r = u32_at(tilde, at)?;
            at += 4;
        }
    }
    if heap & 0x40 != 0 {
        at += 4; // extra data
    }
    let str_w = if heap & 1 != 0 { 4 } else { 2 };
    let guid_w = if heap & 2 != 0 { 4 } else { 2 };
    let blob_w = if heap & 4 != 0 { 4 } else { 2 };
    let width = |c: C| -> usize {
        match c {
            C::U16 => 2,
            C::U32 => 4,
            C::Str => str_w,
            C::Guid => guid_w,
            C::Blob => blob_w,
            C::T(t) => {
                if rows[t as usize] < 1 << 16 {
                    2
                } else {
                    4
                }
            }
            C::Coded(bits, tables) => {
                let max = tables
                    .iter()
                    .filter(|&&t| t != 0xff)
                    .map(|&t| rows[t as usize])
                    .max()
                    .unwrap_or(0);
                if max < 1 << (16 - bits) { 2 } else { 4 }
            }
        }
    };
    let mut start = [0usize; 64];
    let mut row_size = [0usize; 64];
    let mut widths: [Vec<usize>; 64] = std::array::from_fn(|_| Vec::new());
    for t in 0..64 {
        if rows[t] == 0 {
            continue;
        }
        let cols = schema(t);
        if cols.is_empty() {
            // A table we have no schema for: the layout of everything after it is unknown.
            break;
        }
        widths[t] = cols.iter().map(|&c| width(c)).collect();
        row_size[t] = widths[t].iter().sum();
        start[t] = at;
        at = at.checked_add(row_size[t].checked_mul(rows[t] as usize)?)?;
        if at > tilde.len() {
            // Truncated or lying row counts: keep the tables that fit.
            rows[t] = 0;
            break;
        }
    }
    let tb = Tables {
        data: tilde,
        rows,
        start,
        row_size,
        widths,
        strings: streams.get("#Strings").copied().unwrap_or_default(),
        blob: streams.get("#Blob").copied().unwrap_or_default(),
    };
    let _ = tb.blob;

    if tb.rows[0x20] > 0 {
        // Assembly: HashAlgId, Major, Minor, Build, Revision, Flags, PublicKey, Name, Culture.
        let v = (1..5)
            .filter_map(|c| tb.col(0x20, 1, c))
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".");
        dn.assembly = Some((tb.string(tb.col(0x20, 1, 7)?), v));
    }
    for r in 1..=tb.rows[0x23].min(MAX_LIST as u32) {
        if let Some(n) = tb.col(0x23, r, 6) {
            dn.assembly_refs.push((tb.string(n), tb.version(0x23, r)));
        }
    }
    for r in 1..=tb.rows[0x1a].min(MAX_LIST as u32) {
        if let Some(n) = tb.col(0x1a, r, 0) {
            dn.module_refs.push(tb.string(n));
        }
    }
    dn.type_count = tb.rows[0x02] as usize;
    dn.method_count = tb.rows[0x06] as usize;
    for r in 1..=tb.rows[0x02].min(MAX_LIST as u32) {
        let (Some(n), Some(ns)) = (tb.col(0x02, r, 1), tb.col(0x02, r, 2)) else {
            continue;
        };
        let (name, ns) = (tb.string(n), tb.string(ns));
        if name == "<Module>" {
            continue;
        }
        dn.types.push(if ns.is_empty() {
            name
        } else {
            format!("{ns}.{name}")
        });
    }
    for r in 1..=tb.rows[0x1c].min(MAX_LIST as u32) {
        // ImplMap: flags, MemberForwarded, ImportName, ImportScope (ModuleRef).
        let (Some(fwd), Some(imp), Some(scope)) =
            (tb.col(0x1c, r, 1), tb.col(0x1c, r, 2), tb.col(0x1c, r, 3))
        else {
            continue;
        };
        let method = if fwd & 1 == 1 {
            tb.col(0x06, fwd >> 1, 3)
                .map(|n| tb.string(n))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let module = tb
            .col(0x1a, scope, 0)
            .map(|n| tb.string(n))
            .unwrap_or_default();
        dn.pinvokes.push((module, tb.string(imp), method));
    }
    if let Some(us) = streams.get("#US") {
        dn.user_strings = user_strings(us);
    }
    Some(dn)
}

/// `#US` blobs: compressed length, UTF-16LE text, one trailing flag byte.
fn user_strings(us: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut p = 1; // index 0 is the empty string
    while p < us.len() && out.len() < MAX_LIST {
        let b0 = us[p];
        let (len, hdr) = if b0 & 0x80 == 0 {
            (b0 as usize, 1)
        } else if b0 & 0xc0 == 0x80 {
            let Some(&b1) = us.get(p + 1) else { break };
            ((((b0 & 0x3f) as usize) << 8) | b1 as usize, 2)
        } else {
            let Some(b) = us.get(p + 1..p + 4) else { break };
            (
                (((b0 & 0x1f) as usize) << 24)
                    | ((b[0] as usize) << 16)
                    | ((b[1] as usize) << 8)
                    | b[2] as usize,
                4,
            )
        };
        let body = p + hdr;
        let Some(raw) = us.get(body..body + len) else {
            break;
        };
        if len >= 3 {
            let units: Vec<u16> = raw[..len - 1]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&units);
            if s.chars().count() >= 3 {
                out.push(s);
            }
        }
        p = body + len;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_string_heap_is_decoded() {
        let mut us = vec![0u8];
        for s in ["http://x.test/beacon", "hi"] {
            let u: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
            us.push((u.len() + 1) as u8);
            us.extend(u);
            us.push(0);
        }
        assert_eq!(user_strings(&us), vec!["http://x.test/beacon".to_string()]);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse(b"BSJB\0\0\0\0\0\0\0\0\xff\xff\xff\xff", 0).is_none());
        assert!(parse(b"nope", 0).is_none());
        let mut m = b"BSJB".to_vec();
        m.extend([0; 8]);
        m.extend(4u32.to_le_bytes());
        m.extend(b"v4\0\0");
        m.extend([0, 0, 0xff, 0xff]); // 65535 streams claimed, none present
        assert!(parse(&m, 0).is_none());
    }
}
