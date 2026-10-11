//! Signature scanning and extraction of embedded files ("carving").
//!
//! Firmware images are usually a bootloader, a kernel and a filesystem glued
//! together, often with no index. Carving is reading a book with the table of
//! contents torn out: you flip through looking for chapter headings (magic
//! bytes), then use each chapter's own structure to work out where it ends.
//!
//! Every signature has a *validator* that parses enough of the header to
//! reject coincidental matches and, where the format allows, compute the
//! exact embedded size.

use flate2::bufread::GzDecoder;
use serde::Serialize;
use std::io::Read;
use std::path::{Path, PathBuf};

/// A carved region.
#[derive(Debug, Clone, Serialize)]
pub struct Carved {
    /// File offset.
    pub offset: u64,
    /// Short type name (`gzip`, `squashfs`, …).
    pub kind: &'static str,
    /// Size if determinable from the format.
    pub size: Option<u64>,
    /// Description from header fields.
    pub description: String,
    /// Suggested file extension.
    pub ext: &'static str,
}

type Validator = fn(&[u8]) -> Option<(Option<u64>, String)>;

struct Sig {
    kind: &'static str,
    magic: &'static [u8],
    ext: &'static str,
    validate: Validator,
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    b.get(o..o + 2).map(|x| u16::from_le_bytes([x[0], x[1]]))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]))
}
fn u32be(b: &[u8], o: usize) -> Option<u32> {
    b.get(o..o + 4)
        .map(|x| u32::from_be_bytes([x[0], x[1], x[2], x[3]]))
}
fn u64le(b: &[u8], o: usize) -> Option<u64> {
    b.get(o..o + 8)
        .map(|x| u64::from_le_bytes(x.try_into().unwrap()))
}

fn v_gzip(b: &[u8]) -> Option<(Option<u64>, String)> {
    // method must be deflate (8), reserved flag bits zero.
    if *b.get(2)? != 8 || b.get(3)? & 0xe0 != 0 {
        return None;
    }
    let mut d = GzDecoder::new(b);
    let mut sink = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        match d.read(&mut sink) {
            Ok(0) => break,
            Ok(n) => {
                total += n as u64;
                if total > 4 << 30 {
                    return None; // decompression bomb guard
                }
            }
            Err(_) => return None,
        }
    }
    let remaining = d.into_inner().len();
    let size = (b.len() - remaining) as u64;
    let name = if b[3] & 0x08 != 0 {
        let s: Vec<u8> = b[10..]
            .iter()
            .take_while(|&&c| c != 0)
            .take(128)
            .copied()
            .collect();
        format!(", original name \"{}\"", String::from_utf8_lossy(&s))
    } else {
        String::new()
    };
    Some((
        Some(size),
        format!("gzip, {total} bytes uncompressed{name}"),
    ))
}

fn v_zip(b: &[u8]) -> Option<(Option<u64>, String)> {
    let ver = u16le(b, 4)?;
    if ver > 100 {
        return None;
    }
    let name_len = u16le(b, 26)? as usize;
    let name = b.get(30..30 + name_len.min(200))?;
    if name.is_empty() || name.iter().any(|&c| c < 0x20) {
        return None;
    }
    // Find the end-of-central-directory record to size the archive.
    let size = memchr::memmem::find_iter(b, b"PK\x05\x06").find_map(|eocd| {
        let cd_size = u32le(b, eocd + 12)? as usize;
        let cd_off = u32le(b, eocd + 16)? as usize;
        let comment = u16le(b, eocd + 20)? as usize;
        (cd_off + cd_size == eocd).then_some((eocd + 22 + comment) as u64)
    });
    Some((
        size,
        format!(
            "zip archive, first entry \"{}\"",
            String::from_utf8_lossy(name)
        ),
    ))
}

fn v_elf(b: &[u8]) -> Option<(Option<u64>, String)> {
    let class = *b.get(4)?;
    let endian = *b.get(5)?;
    if !(1..=2).contains(&class) || !(1..=2).contains(&endian) || *b.get(6)? != 1 {
        return None;
    }
    let size = goblin::elf::Elf::parse(b).ok().map(|e| {
        let sh = e.header.e_shoff + e.header.e_shnum as u64 * e.header.e_shentsize as u64;
        let ph = e
            .program_headers
            .iter()
            .map(|p| p.p_offset + p.p_filesz)
            .max()
            .unwrap_or(0);
        sh.max(ph)
    });
    let machine = if endian == 1 {
        u16le(b, 18)?
    } else {
        u16::from_be_bytes([b[18], b[19]])
    };
    Some((
        size.filter(|&s| s > 0 && s as usize <= b.len()),
        format!(
            "ELF {}-bit {}, {}",
            if class == 2 { 64 } else { 32 },
            if endian == 1 { "LE" } else { "BE" },
            goblin::elf::header::machine_to_str(machine)
        ),
    ))
}

fn v_pe(b: &[u8]) -> Option<(Option<u64>, String)> {
    let off = u32le(b, 0x3c)? as usize;
    if off > 0x1000 || b.get(off..off + 4)? != b"PE\0\0" {
        return None;
    }
    let size = goblin::pe::PE::parse(b).ok().map(|p| {
        p.sections
            .iter()
            .map(|s| s.pointer_to_raw_data as u64 + s.size_of_raw_data as u64)
            .max()
            .unwrap_or(0)
    });
    Some((
        size.filter(|&s| s > 0 && s as usize <= b.len()),
        "PE executable".into(),
    ))
}

fn v_png(b: &[u8]) -> Option<(Option<u64>, String)> {
    let mut o = 8usize;
    let w = u32be(b, 16)?;
    let h = u32be(b, 20)?;
    for _ in 0..100_000 {
        let len = u32be(b, o)? as usize;
        let ty = b.get(o + 4..o + 8)?;
        o = o.checked_add(12 + len)?;
        if ty == b"IEND" {
            return Some((Some(o as u64), format!("PNG image {w}x{h}")));
        }
    }
    None
}

fn v_jpeg(b: &[u8]) -> Option<(Option<u64>, String)> {
    // Walk segments to SOS, then scan entropy-coded data for EOI.
    let mut o = 2usize;
    loop {
        if *b.get(o)? != 0xff {
            return None;
        }
        let marker = *b.get(o + 1)?;
        if marker == 0xda {
            let len = u16::from_be_bytes([*b.get(o + 2)?, *b.get(o + 3)?]) as usize;
            let mut p = o + 2 + len;
            while p + 1 < b.len() {
                if b[p] == 0xff && b[p + 1] == 0xd9 {
                    return Some((Some((p + 2) as u64), "JPEG image".into()));
                }
                p += 1;
            }
            return Some((None, "JPEG image (truncated)".into()));
        }
        if (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            o += 2;
            continue;
        }
        let len = u16::from_be_bytes([*b.get(o + 2)?, *b.get(o + 3)?]) as usize;
        if len < 2 {
            return None;
        }
        o += 2 + len;
    }
}

fn v_squashfs(b: &[u8]) -> Option<(Option<u64>, String)> {
    let major = u16le(b, 28)?;
    let minor = u16le(b, 30)?;
    if !(1..=4).contains(&major) {
        return None;
    }
    let inodes = u32le(b, 4)?;
    let bytes_used = if major == 4 {
        u64le(b, 40)?
    } else {
        u32le(b, 8)? as u64
    };
    let comp = match u16le(b, 20)? {
        1 => "gzip",
        2 => "lzma",
        3 => "lzo",
        4 => "xz",
        5 => "lz4",
        6 => "zstd",
        _ => "?",
    };
    Some((
        (bytes_used > 0 && bytes_used as usize <= b.len()).then_some(bytes_used),
        format!("SquashFS v{major}.{minor}, {comp}, {inodes} inodes"),
    ))
}

fn v_cpio(b: &[u8]) -> Option<(Option<u64>, String)> {
    // newc: walk headers until TRAILER!!!
    let mut o = 0usize;
    let hex = |s: &[u8]| -> Option<usize> {
        usize::from_str_radix(std::str::from_utf8(s).ok()?, 16).ok()
    };
    for files in 0..1_000_000 {
        let h = b.get(o..o + 110)?;
        if &h[..6] != b"070701" && &h[..6] != b"070702" {
            return None;
        }
        let fsize = hex(&h[54..62])?;
        let nsize = hex(&h[94..102])?;
        let name = b.get(o + 110..o + 110 + nsize.saturating_sub(1))?;
        let after_name = (o + 110 + nsize + 3) & !3;
        let after_data = (after_name + fsize + 3) & !3;
        if name == b"TRAILER!!!" {
            return Some((
                Some(after_data.min(b.len()) as u64),
                format!("cpio newc archive, {files} entries"),
            ));
        }
        o = after_data;
    }
    None
}

fn v_uimage(b: &[u8]) -> Option<(Option<u64>, String)> {
    let size = u32be(b, 12)? as u64;
    let name: Vec<u8> = b
        .get(32..64)?
        .iter()
        .take_while(|&&c| c != 0)
        .copied()
        .collect();
    if name.iter().any(|&c| !(0x20..0x7f).contains(&c)) {
        return None;
    }
    let os = match b.get(28)? {
        5 => "Linux",
        17 => "U-Boot",
        _ => "other",
    };
    Some((
        Some(64 + size),
        format!(
            "uImage \"{}\", OS {os}, {size} bytes",
            String::from_utf8_lossy(&name)
        ),
    ))
}

fn v_xz(_b: &[u8]) -> Option<(Option<u64>, String)> {
    Some((None, "xz compressed data".into()))
}

fn v_bzip2(b: &[u8]) -> Option<(Option<u64>, String)> {
    let lvl = *b.get(3)?;
    if !(b'1'..=b'9').contains(&lvl) || b.get(4..10)? != [0x31, 0x41, 0x59, 0x26, 0x53, 0x59] {
        return None;
    }
    Some((
        None,
        format!("bzip2 compressed data, block size {}00k", lvl as char),
    ))
}

fn v_lzma(b: &[u8]) -> Option<(Option<u64>, String)> {
    // props byte 0x5d, dictionary size power of two, then uncompressed size (u64, often -1).
    let dict = u32le(b, 1)?;
    if !dict.is_power_of_two() || !(1 << 12..=1 << 28).contains(&dict) {
        return None;
    }
    let usize_ = u64le(b, 5)?;
    if usize_ != u64::MAX && usize_ > 1 << 32 {
        return None;
    }
    Some((
        None,
        format!("LZMA compressed data, dict {} KiB", dict / 1024),
    ))
}

fn v_7z(_b: &[u8]) -> Option<(Option<u64>, String)> {
    Some((None, "7-zip archive".into()))
}

fn v_pem(b: &[u8]) -> Option<(Option<u64>, String)> {
    let head: Vec<u8> = b
        .iter()
        .take(64)
        .take_while(|&&c| c != b'\n')
        .copied()
        .collect();
    let label = String::from_utf8_lossy(&head).trim().to_string();
    let end = memchr::memmem::find(b, b"-----END ")
        .and_then(|e| memchr::memchr(b'\n', &b[e..]).map(|n| (e + n + 1) as u64));
    Some((end, format!("PEM: {label}")))
}

fn v_pdf(_b: &[u8]) -> Option<(Option<u64>, String)> {
    Some((None, "PDF document".into()))
}

fn v_sqlite(_b: &[u8]) -> Option<(Option<u64>, String)> {
    Some((None, "SQLite 3 database".into()))
}

fn v_dtb(b: &[u8]) -> Option<(Option<u64>, String)> {
    let size = u32be(b, 4)? as u64;
    let ver = u32be(b, 20)?;
    if !(1..=17).contains(&ver) || size < 40 {
        return None;
    }
    Some((Some(size), format!("Flattened device tree v{ver}")))
}

fn v_jffs2(b: &[u8]) -> Option<(Option<u64>, String)> {
    let nodetype = u16le(b, 2)?;
    if ![0xe001u16, 0xe002, 0x2003, 0x2004, 0x2006].contains(&nodetype) {
        return None;
    }
    Some((None, "JFFS2 filesystem (LE)".into()))
}

fn v_ubi(_b: &[u8]) -> Option<(Option<u64>, String)> {
    Some((None, "UBI erase-count header".into()))
}

static SIGS: &[Sig] = &[
    Sig {
        kind: "gzip",
        magic: b"\x1f\x8b\x08",
        ext: "gz",
        validate: v_gzip,
    },
    Sig {
        kind: "zip",
        magic: b"PK\x03\x04",
        ext: "zip",
        validate: v_zip,
    },
    Sig {
        kind: "elf",
        magic: b"\x7fELF",
        ext: "elf",
        validate: v_elf,
    },
    Sig {
        kind: "pe",
        magic: b"MZ",
        ext: "exe",
        validate: v_pe,
    },
    Sig {
        kind: "png",
        magic: b"\x89PNG\r\n\x1a\n",
        ext: "png",
        validate: v_png,
    },
    Sig {
        kind: "jpeg",
        magic: b"\xff\xd8\xff",
        ext: "jpg",
        validate: v_jpeg,
    },
    Sig {
        kind: "squashfs",
        magic: b"hsqs",
        ext: "squashfs",
        validate: v_squashfs,
    },
    Sig {
        kind: "cpio",
        magic: b"070701",
        ext: "cpio",
        validate: v_cpio,
    },
    Sig {
        kind: "uimage",
        magic: b"\x27\x05\x19\x56",
        ext: "uimage",
        validate: v_uimage,
    },
    Sig {
        kind: "xz",
        magic: b"\xfd7zXZ\x00",
        ext: "xz",
        validate: v_xz,
    },
    Sig {
        kind: "bzip2",
        magic: b"BZh",
        ext: "bz2",
        validate: v_bzip2,
    },
    Sig {
        kind: "lzma",
        magic: b"\x5d\x00\x00",
        ext: "lzma",
        validate: v_lzma,
    },
    Sig {
        kind: "7z",
        magic: b"7z\xbc\xaf\x27\x1c",
        ext: "7z",
        validate: v_7z,
    },
    Sig {
        kind: "pem",
        magic: b"-----BEGIN ",
        ext: "pem",
        validate: v_pem,
    },
    Sig {
        kind: "pdf",
        magic: b"%PDF-",
        ext: "pdf",
        validate: v_pdf,
    },
    Sig {
        kind: "sqlite",
        magic: b"SQLite format 3\x00",
        ext: "sqlite",
        validate: v_sqlite,
    },
    Sig {
        kind: "dtb",
        magic: b"\xd0\x0d\xfe\xed",
        ext: "dtb",
        validate: v_dtb,
    },
    Sig {
        kind: "jffs2",
        magic: b"\x85\x19",
        ext: "jffs2",
        validate: v_jffs2,
    },
    Sig {
        kind: "ubi",
        magic: b"UBI#",
        ext: "ubi",
        validate: v_ubi,
    },
];

/// Scan `data` for embedded files. Regions nested inside an already-sized
/// region are skipped (e.g. the PNG inside a zip) unless `nested` is true.
pub fn scan(data: &[u8], nested: bool) -> Vec<Carved> {
    let mut hits: Vec<Carved> = Vec::new();
    for sig in SIGS {
        for off in memchr::memmem::find_iter(data, sig.magic) {
            let slice = &data[off..];
            let Some((size, description)) = std::panic::catch_unwind(|| (sig.validate)(slice))
                .ok()
                .flatten()
            else {
                continue;
            };
            hits.push(Carved {
                offset: off as u64,
                kind: sig.kind,
                size,
                description,
                ext: sig.ext,
            });
            // JFFS2 nodes repeat thousands of times; only report the first.
            if sig.kind == "jffs2" || sig.kind == "ubi" {
                break;
            }
        }
    }
    hits.sort_by_key(|h| h.offset);
    if nested {
        return hits;
    }
    let mut out: Vec<Carved> = Vec::new();
    let mut covered_until = 0u64;
    for h in hits {
        if h.offset < covered_until && h.offset != 0 {
            continue;
        }
        if let Some(s) = h.size {
            covered_until = covered_until.max(h.offset + s);
        }
        out.push(h);
    }
    out
}

/// Write carved regions into `dir`. Regions without a known size extend to the
/// next carved region (or end of file). Returns written paths.
pub fn extract(data: &[u8], carved: &[Carved], dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut paths = Vec::new();
    for (i, c) in carved.iter().enumerate() {
        let start = c.offset as usize;
        let end = match c.size {
            Some(s) => start + s as usize,
            None => carved
                .iter()
                .skip(i + 1)
                .map(|n| n.offset as usize)
                .find(|&o| o > start)
                .unwrap_or(data.len()),
        }
        .min(data.len());
        let path = dir.join(format!("{:08x}.{}", c.offset, c.ext));
        std::fs::write(&path, &data[start..end])?;
        // Unwrap common containers one level so the analyst gets the interesting bytes.
        let inner: Option<&[u8]> = match c.kind {
            "gzip" => Some(&data[start..end]),
            "uimage" if end - start > 64 => {
                let payload = &data[start + 64..end];
                let p = dir.join(format!("{:08x}.uimage.payload", c.offset));
                std::fs::write(&p, payload)?;
                paths.push(p);
                payload.starts_with(b"\x1f\x8b").then_some(payload)
            }
            _ => None,
        };
        if let Some(gz) = inner {
            let mut d = GzDecoder::new(gz).take(4 << 30);
            let mut out = Vec::new();
            if d.read_to_end(&mut out).is_ok() {
                let p = dir.join(format!("{:08x}.gunzipped", c.offset));
                std::fs::write(&p, &out)?;
                paths.push(p);
            }
        }
        paths.push(path);
    }
    Ok(paths)
}

/// Describe an entropy profile: where are the compressed / encrypted regions?
pub fn entropy_regions(
    profile: &[(usize, f64)],
    block: usize,
) -> Vec<(usize, usize, &'static str)> {
    let mut out: Vec<(usize, usize, &'static str)> = Vec::new();
    for &(off, e) in profile {
        let class = if e > 7.5 {
            "compressed/encrypted"
        } else if e < 1.0 {
            "padding/empty"
        } else if e < 5.5 {
            "text/structured"
        } else {
            "code/mixed"
        };
        match out.last_mut() {
            Some(last) if last.2 == class && last.1 == off => last.1 = off + block,
            _ => out.push((off, off + block, class)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, write::GzEncoder};
    use std::io::Write;

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn finds_and_sizes_gzip_and_png() {
        let payload = gz(b"hello firmware world, hello firmware world");
        let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
        png.extend([0, 0, 0, 13]);
        png.extend(b"IHDR");
        png.extend([0, 0, 0, 4, 0, 0, 0, 3, 8, 2, 0, 0, 0]);
        png.extend([0, 0, 0, 0]);
        png.extend([0, 0, 0, 0]);
        png.extend(b"IEND");
        png.extend([0xae, 0x42, 0x60, 0x82]);
        let mut blob = vec![0u8; 100];
        blob.extend(&payload);
        blob.extend(vec![0xffu8; 37]);
        let png_off = blob.len();
        blob.extend(&png);
        blob.extend(vec![0u8; 50]);

        let hits = scan(&blob, false);
        let g = hits.iter().find(|h| h.kind == "gzip").unwrap();
        assert_eq!(g.offset, 100);
        assert_eq!(g.size, Some(payload.len() as u64));
        let p = hits.iter().find(|h| h.kind == "png").unwrap();
        assert_eq!(p.offset as usize, png_off);
        assert_eq!(p.size, Some(png.len() as u64));
        assert!(p.description.contains("4x3"));

        let dir = tempfile::tempdir().unwrap();
        let written = extract(&blob, &hits, dir.path()).unwrap();
        let gz_path = written
            .iter()
            .find(|p| p.extension().unwrap() == "gz")
            .unwrap();
        assert_eq!(std::fs::read(gz_path).unwrap(), payload);
        let un = written
            .iter()
            .find(|p| p.extension().unwrap() == "gunzipped")
            .unwrap();
        assert_eq!(
            std::fs::read(un).unwrap(),
            b"hello firmware world, hello firmware world"
        );
    }

    #[test]
    fn rejects_false_positives() {
        // "MZ" without a PE header and "BZh" without the block magic.
        let blob = b"xxMZxxxxBZh9xxxxxx\x1f\x8b\x09xxxx";
        assert!(scan(blob, false).is_empty());
    }

    #[test]
    fn regions() {
        let r = entropy_regions(&[(0, 0.0), (16, 0.2), (32, 7.9), (48, 7.8)], 16);
        assert_eq!(
            r,
            vec![(0, 32, "padding/empty"), (32, 64, "compressed/encrypted")]
        );
    }
}
