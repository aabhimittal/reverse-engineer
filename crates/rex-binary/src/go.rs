//! Go binaries: build information and the function table.
//!
//! Go links everything statically and, even with `-ldflags="-s -w"`, keeps two structures the
//! runtime itself needs:
//!
//! * **Build info** (`\xff Go buildinf:`): the Go version, the main module and every dependency
//!   with its version and checksum, and build settings such as `GOOS`, `GOARCH` and `-ldflags`.
//!   It is the binary's own software bill of materials.
//! * **pclntab**: the table the runtime uses for stack traces. It maps every function's entry
//!   address to its fully qualified name (`main.check`, `net/http.(*Client).Do`). Stripping
//!   removes the ELF symbol table but cannot remove this, so it names functions in stripped
//!   binaries on every architecture Go supports.
//!
//! Both parsers bound every read; all offsets come from the file.

use serde::Serialize;

/// What the build-info blob says.
#[derive(Debug, Clone, Default, Serialize)]
pub struct BuildInfo {
    /// Toolchain, e.g. `go1.24.7`.
    pub go_version: String,
    /// Main package path, e.g. `example.com/tool/cmd/tool`.
    pub path: Option<String>,
    /// Main module path and version.
    pub module: Option<(String, String)>,
    /// Dependencies: module path, version.
    pub deps: Vec<(String, String)>,
    /// Build settings, e.g. `GOOS=linux`, `-ldflags=-s -w`, `vcs.revision=…`.
    pub settings: Vec<(String, String)>,
}

/// One function from the pclntab.
#[derive(Debug, Clone, Serialize)]
pub struct GoFunc {
    /// Entry address.
    pub addr: u64,
    /// Fully qualified name.
    pub name: String,
}

const BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";

/// Find and decode the build-info blob (Go 1.18+ inline format; older binaries yield the
/// version string only when it can be found).
pub fn build_info(data: &[u8]) -> Option<BuildInfo> {
    let mut at = 0;
    while let Some(i) = memmem(&data[at..], BUILDINFO_MAGIC) {
        let start = at + i;
        at = start + 1;
        // The blob is 16-byte aligned in the file's data section.
        if start % 16 != 0 {
            continue;
        }
        let hdr = data.get(start..start + 32)?;
        let flags = hdr[15];
        if flags & 2 == 0 {
            // Pre-1.18 layout stores pointers; resolving them needs the memory map. Report the
            // version if the usual string is nearby, which is enough to identify the toolchain.
            let near = &data[start..data.len().min(start + 4096)];
            let v = find_go_version(near).or_else(|| find_go_version(data))?;
            return Some(BuildInfo {
                go_version: v,
                ..Default::default()
            });
        }
        let mut p = start + 32;
        let version = String::from_utf8_lossy(varint_bytes(data, &mut p)?).into_owned();
        let modinfo = varint_bytes(data, &mut p).unwrap_or_default();
        let mut bi = BuildInfo {
            go_version: version,
            ..Default::default()
        };
        // modinfo is wrapped in 16-byte sentinels; cut them off as bytes, then decode.
        let body = String::from_utf8_lossy(
            modinfo
                .get(16..modinfo.len().saturating_sub(17))
                .unwrap_or_default(),
        );
        for line in body.lines() {
            let mut f = line.split('\t');
            match (f.next(), f.next(), f.next()) {
                (Some("path"), Some(p), _) => bi.path = Some(p.to_string()),
                (Some("mod"), Some(m), v) => {
                    bi.module = Some((m.to_string(), v.unwrap_or("").to_string()))
                }
                (Some("dep"), Some(m), v) => {
                    bi.deps.push((m.to_string(), v.unwrap_or("").to_string()))
                }
                (Some("build"), Some(kv), _) => {
                    let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
                    bi.settings.push((k.to_string(), v.to_string()));
                }
                _ => {}
            }
        }
        return Some(bi);
    }
    None
}

fn find_go_version(d: &[u8]) -> Option<String> {
    let i = memmem(d, b"go1.")?;
    let end = d[i..]
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
        .map_or(d.len(), |n| i + n);
    let v = std::str::from_utf8(&d[i..end]).ok()?;
    (v.len() >= 5 && v.len() < 32).then(|| v.to_string())
}

fn varint_bytes<'d>(data: &'d [u8], p: &mut usize) -> Option<&'d [u8]> {
    let mut n: u64 = 0;
    for shift in (0..64).step_by(7) {
        let b = *data.get(*p)?;
        *p += 1;
        n |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            break;
        }
    }
    let n = usize::try_from(n).ok().filter(|&n| n < 1 << 24)?;
    let s = data.get(*p..p.checked_add(n)?)?;
    *p += n;
    Some(s)
}

fn memmem(h: &[u8], n: &[u8]) -> Option<usize> {
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    let first = n[0];
    let mut i = 0;
    while i + n.len() <= h.len() {
        let j = h[i..h.len() - n.len() + 1]
            .iter()
            .position(|&b| b == first)?;
        i += j;
        if &h[i..i + n.len()] == n {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Cap on functions read from a pclntab (a large Go service has ~60k).
const MAX_FUNCS: usize = 500_000;

/// Read function entries and names from the pclntab, wherever it is in the file.
///
/// `hint` is the file offset of a `.gopclntab`/`__gopclntab` section when the container names
/// one; otherwise the file is searched for the table's magic and header.
pub fn functions(data: &[u8], hint: Option<usize>, little_endian: bool) -> Vec<GoFunc> {
    if let Some(off) = hint {
        if let Some(f) = parse_pclntab(data, off, little_endian) {
            return f;
        }
    }
    let magics: [[u8; 4]; 3] = [
        0xffff_fff1u32.to_le_bytes(), // Go 1.20+ (and 1.18/1.19 share the layout)
        0xffff_fff0u32.to_le_bytes(), // Go 1.18–1.19
        0xffff_fffau32.to_le_bytes(), // Go 1.16–1.17
    ];
    // A file can be stuffed with fake magic values; cap how many candidates are examined.
    const MAX_CANDIDATES: usize = 64;
    let mut tried = 0;
    let best: Vec<GoFunc> = Vec::new();
    for m in magics {
        let m = if little_endian {
            m
        } else {
            let mut b = m;
            b.reverse();
            b
        };
        let mut at = 0;
        while let Some(i) = memmem(&data[at..], &m) {
            let off = at + i;
            at = off + 1;
            tried += 1;
            if tried > MAX_CANDIDATES {
                return best;
            }
            if let Some(f) = parse_pclntab(data, off, little_endian) {
                // The first table that validates is the table; Go binaries carry one.
                return f;
            }
        }
    }
    best
}

fn parse_pclntab(data: &[u8], off: usize, le: bool) -> Option<Vec<GoFunc>> {
    let t = data.get(off..)?;
    let rd32 = |o: usize| -> Option<u32> {
        let b: [u8; 4] = t.get(o..o + 4)?.try_into().ok()?;
        Some(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let magic = rd32(0)?;
    // Header: magic, two zero pad bytes, instruction-size quantum, pointer size.
    if t.get(4..6)? != [0, 0] {
        return None;
    }
    let quantum = *t.get(6)?;
    let ptr = *t.get(7)? as usize;
    if !matches!(quantum, 1 | 2 | 4) || !matches!(ptr, 4 | 8) {
        return None;
    }
    let word = |i: usize| -> Option<u64> {
        let o = 8 + i * ptr;
        let b = t.get(o..o + ptr)?;
        let mut buf = [0u8; 8];
        Some(if le {
            buf[..ptr].copy_from_slice(b);
            u64::from_le_bytes(buf)
        } else {
            buf[8 - ptr..].copy_from_slice(b);
            u64::from_be_bytes(buf)
        })
    };
    let nfunc = usize::try_from(word(0)?).ok()?;
    if nfunc == 0 || nfunc > MAX_FUNCS || nfunc * 8 > t.len() {
        return None;
    }
    let cstr = |base: usize, o: usize| -> Option<String> {
        let s = t.get(base.checked_add(o)?..)?;
        let end = s.iter().take(512).position(|&b| b == 0)?;
        let name = std::str::from_utf8(&s[..end]).ok()?;
        (!name.is_empty()).then(|| name.to_string())
    };
    let mut out = Vec::with_capacity(nfunc);
    match magic {
        0xffff_fff1 | 0xffff_fff0 => {
            // nfunc, nfiles, textStart, funcnametab, cutab, filetab, pctab, functab offsets.
            let text = word(2)?;
            let names = usize::try_from(word(3)?).ok()?;
            let functab = usize::try_from(word(7)?).ok()?;
            // Reject a fake header cheaply: the first entries must resolve to names, in order.
            let probe = nfunc.min(16);
            let mut last = 0u32;
            for i in 0..probe {
                let e = functab + i * 8;
                let entry = rd32(e)?;
                let funcoff = rd32(e + 4)? as usize;
                let name_off = rd32(functab.checked_add(funcoff)? + 4)? as usize;
                if entry < last || cstr(names, name_off).is_none() {
                    return None;
                }
                last = entry;
            }
            for i in 0..nfunc {
                let e = functab + i * 8;
                let entry = rd32(e)? as u64;
                let funcoff = rd32(e + 4)? as usize;
                // _func: entryOff u32, nameOff i32, …
                let name_off = rd32(functab.checked_add(funcoff)? + 4)? as usize;
                if let Some(name) = cstr(names, name_off) {
                    out.push(GoFunc {
                        addr: text.checked_add(entry)?,
                        name,
                    });
                }
            }
        }
        0xffff_fffa => {
            // nfunc, nfiles, funcnametab, cutab, filetab, pctab, functab offsets; the functab
            // holds (entry pc, func offset) pairs of pointer size.
            let names = usize::try_from(word(2)?).ok()?;
            let functab = usize::try_from(word(6)?).ok()?;
            for i in 0..nfunc {
                let e = functab + i * 2 * ptr;
                let entry = word((e - 8) / ptr).filter(|_| (e - 8) % ptr == 0)?;
                let funcoff = usize::try_from(word((e - 8) / ptr + 1)?).ok()?;
                let name_off = rd32(functab.checked_add(funcoff)? + ptr)? as usize;
                if let Some(name) = cstr(names, name_off) {
                    out.push(GoFunc { addr: entry, name });
                }
            }
        }
        _ => return None,
    }
    // A real table names most of its functions and lists them in address order.
    let sorted = out.windows(2).all(|w| w[0].addr <= w[1].addr);
    (out.len() * 2 >= nfunc && sorted).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_strings_and_sentinels() {
        let mut blob = vec![0u8; 32];
        blob[..14].copy_from_slice(BUILDINFO_MAGIC);
        blob[14] = 8;
        blob[15] = 2;
        let v = b"go1.24.7";
        blob.push(v.len() as u8);
        blob.extend_from_slice(v);
        let mut modinfo = vec![b'x'; 16];
        modinfo.extend_from_slice(
            b"path\texample.com/t\nmod\texample.com/t\t(devel)\t\ndep\tgolang.org/x/net\tv0.30.0\th1:abc=\nbuild\tGOOS=linux\nbuild\t-ldflags=-s -w\n",
        );
        modinfo.extend_from_slice(&[b'y'; 17]);
        blob.push(modinfo.len() as u8);
        blob.push(1); // two-byte varint (len >= 128)
        blob.truncate(blob.len() - 2);
        let mut len = modinfo.len();
        while len >= 0x80 {
            blob.push((len as u8 & 0x7f) | 0x80);
            len >>= 7;
        }
        blob.push(len as u8);
        blob.extend_from_slice(&modinfo);
        let bi = build_info(&blob).unwrap();
        assert_eq!(bi.go_version, "go1.24.7");
        assert_eq!(bi.path.as_deref(), Some("example.com/t"));
        assert_eq!(bi.deps, vec![("golang.org/x/net".into(), "v0.30.0".into())]);
        assert!(bi.settings.contains(&("-ldflags".into(), "-s -w".into())));
    }

    #[test]
    fn garbage_is_not_a_pclntab() {
        let mut d = vec![0u8; 4096];
        d[100..104].copy_from_slice(&0xffff_fff1u32.to_le_bytes());
        d[107] = 8;
        d[106] = 1;
        d[108] = 0xff; // nfunc enormous
        assert!(functions(&d, None, true).is_empty());
        assert!(build_info(&d).is_none());
    }
}
