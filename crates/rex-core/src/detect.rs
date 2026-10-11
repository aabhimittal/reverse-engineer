//! Magic-byte and structural detection of input kinds.
//!
//! Detection is the "triage nurse" of the pipeline: it doesn't diagnose, it
//! only decides which specialist (analyzer) should see the patient.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// What an artifact is, as far as rex can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Executable and Linkable Format (Linux, BSD, Android native, most firmware).
    Elf,
    /// Portable Executable (Windows .exe/.dll/.sys).
    Pe,
    /// Mach-O (macOS / iOS), single architecture.
    MachO,
    /// Mach-O universal ("fat") binary.
    MachOFat,
    /// Java class file.
    JavaClass,
    /// WebAssembly module.
    Wasm,
    /// Android application package.
    Apk,
    /// Dalvik executable.
    Dex,
    /// Android binary XML (compiled AndroidManifest.xml).
    AndroidBinaryXml,
    /// Generic zip archive.
    Zip,
    /// Electron ASAR application archive.
    Asar,
    /// HTTP Archive (browser / proxy traffic capture).
    Har,
    /// JavaScript source or bundle.
    JavaScript,
    /// JavaScript source map.
    SourceMap,
    /// Other JSON document.
    Json,
    /// A directory (treated as a source tree).
    Directory,
    /// Unidentified binary blob (firmware images often land here).
    Blob,
    /// Plain text.
    Text,
}

impl ArtifactKind {
    /// Human-readable label.
    pub fn label(self) -> &'static str {
        match self {
            ArtifactKind::Elf => "ELF executable",
            ArtifactKind::Pe => "PE executable",
            ArtifactKind::MachO => "Mach-O executable",
            ArtifactKind::MachOFat => "Mach-O universal binary",
            ArtifactKind::JavaClass => "Java class file",
            ArtifactKind::Wasm => "WebAssembly module",
            ArtifactKind::Apk => "Android APK",
            ArtifactKind::Dex => "Dalvik executable (DEX)",
            ArtifactKind::AndroidBinaryXml => "Android binary XML",
            ArtifactKind::Zip => "Zip archive",
            ArtifactKind::Asar => "Electron ASAR archive",
            ArtifactKind::Har => "HTTP Archive (HAR)",
            ArtifactKind::JavaScript => "JavaScript",
            ArtifactKind::SourceMap => "JavaScript source map",
            ArtifactKind::Json => "JSON document",
            ArtifactKind::Directory => "Source tree (directory)",
            ArtifactKind::Blob => "Binary blob / firmware",
            ArtifactKind::Text => "Text",
        }
    }

    /// True for native executable formats.
    pub fn is_native_binary(self) -> bool {
        matches!(
            self,
            ArtifactKind::Elf | ArtifactKind::Pe | ArtifactKind::MachO | ArtifactKind::MachOFat
        )
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

/// Detect a kind from bytes and an optional file name (used for extension hints).
pub fn detect_bytes(data: &[u8], name: Option<&str>) -> ArtifactKind {
    let ext = name
        .and_then(|n| Path::new(n).extension())
        .and_then(|e| e.to_str())
        .map(|e| e.to_ascii_lowercase());

    if data.starts_with(b"\x7fELF") {
        return ArtifactKind::Elf;
    }
    if data.starts_with(b"MZ") && is_pe(data) {
        return ArtifactKind::Pe;
    }
    if data.len() >= 4 {
        let m = [data[0], data[1], data[2], data[3]];
        match m {
            [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe] => return ArtifactKind::MachO,
            [0xca, 0xfe, 0xba, 0xbe] => {
                // Shared magic between fat Mach-O and Java class files. Fat
                // headers store a small architecture count where Java stores
                // its (large) major version number.
                if data.len() >= 8 {
                    let n = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                    if n > 0 && n < 30 {
                        return ArtifactKind::MachOFat;
                    }
                }
                return ArtifactKind::JavaClass;
            }
            _ => {}
        }
    }
    if data.starts_with(b"\0asm") {
        return ArtifactKind::Wasm;
    }
    if data.starts_with(b"dex\n") && data.len() >= 8 && data[7] == 0 {
        return ArtifactKind::Dex;
    }
    if data.len() >= 8 && data[0..4] == [0x03, 0x00, 0x08, 0x00] {
        return ArtifactKind::AndroidBinaryXml;
    }
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        if contains(data, b"AndroidManifest.xml") && contains(data, b"classes") {
            return ArtifactKind::Apk;
        }
        if ext.as_deref() == Some("apk") {
            return ArtifactKind::Apk;
        }
        return ArtifactKind::Zip;
    }

    if looks_like_asar(data) {
        return ArtifactKind::Asar;
    }

    // Text-ish formats.
    let head = &data[..data.len().min(4096)];
    let trimmed = trim_ascii_start(head);
    if trimmed.starts_with(b"{") || trimmed.starts_with(b"[") {
        if contains(head, b"\"log\"") && (contains(data, b"\"entries\"")) {
            return ArtifactKind::Har;
        }
        if contains(head, b"\"mappings\"") && contains(head, b"\"version\"") {
            return ArtifactKind::SourceMap;
        }
        if ext.as_deref() == Some("har") {
            return ArtifactKind::Har;
        }
        if ext.as_deref() == Some("map") {
            return ArtifactKind::SourceMap;
        }
        if looks_textual(head) {
            return ArtifactKind::Json;
        }
    }
    match ext.as_deref() {
        Some("js" | "mjs" | "cjs" | "jsx") if looks_textual(head) => {
            return ArtifactKind::JavaScript;
        }
        Some("har") => return ArtifactKind::Har,
        Some("map") => return ArtifactKind::SourceMap,
        Some("apk") => return ArtifactKind::Apk,
        _ => {}
    }
    if looks_textual(head) {
        if looks_like_js(head) {
            return ArtifactKind::JavaScript;
        }
        return ArtifactKind::Text;
    }
    ArtifactKind::Blob
}

/// Detect a kind for a filesystem path (directories become [`ArtifactKind::Directory`]).
pub fn detect_path(path: &Path, data: &[u8]) -> ArtifactKind {
    if path.is_dir() {
        return ArtifactKind::Directory;
    }
    detect_bytes(data, path.file_name().and_then(|n| n.to_str()))
}

/// ASAR has no magic number; recognise its framed JSON header instead.
fn looks_like_asar(d: &[u8]) -> bool {
    let u = |at: usize| -> Option<usize> {
        let b = d.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let (Some(four), Some(hsize), Some(payload), Some(jlen)) = (u(0), u(4), u(8), u(12)) else {
        return false;
    };
    four == 4
        && hsize >= 8
        && payload == hsize - 4
        && jlen <= payload - 4
        && d.get(16..16 + jlen)
            .is_some_and(|j| j.starts_with(br#"{"files""#))
}

fn is_pe(data: &[u8]) -> bool {
    if data.len() < 0x40 {
        return false;
    }
    let off = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    data.get(off..off + 4) == Some(b"PE\0\0")
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn trim_ascii_start(b: &[u8]) -> &[u8] {
    let b = b.strip_prefix(b"\xef\xbb\xbf").unwrap_or(b);
    let n = b.iter().take_while(|c| c.is_ascii_whitespace()).count();
    &b[n..]
}

fn looks_textual(head: &[u8]) -> bool {
    if head.is_empty() {
        return false;
    }
    if std::str::from_utf8(head).is_err() {
        // Allow a truncated multi-byte sequence at the end of the window.
        let valid = match std::str::from_utf8(head) {
            Ok(_) => head.len(),
            Err(e) => e.valid_up_to(),
        };
        if head.len() - valid > 3 {
            return false;
        }
    }
    let ctrl = head
        .iter()
        .filter(|&&c| c < 0x20 && !matches!(c, b'\n' | b'\r' | b'\t' | 0x0c))
        .count();
    ctrl * 100 < head.len()
}

fn looks_like_js(head: &[u8]) -> bool {
    let markers: [&[u8]; 8] = [
        b"function(",
        b"function (",
        b"=>",
        b"webpackChunk",
        b"__webpack_require__",
        b"\"use strict\"",
        b"module.exports",
        b"!function(",
    ];
    markers.iter().filter(|m| contains(head, m)).count() >= 2
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic() {
        assert_eq!(
            detect_bytes(b"\x7fELF\x02\x01\x01", None),
            ArtifactKind::Elf
        );
        assert_eq!(
            detect_bytes(b"\xcf\xfa\xed\xfe....", None),
            ArtifactKind::MachO
        );
        assert_eq!(
            detect_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x02", None),
            ArtifactKind::MachOFat
        );
        assert_eq!(
            detect_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x34", None),
            ArtifactKind::JavaClass
        );
        assert_eq!(detect_bytes(b"dex\n035\0rest", None), ArtifactKind::Dex);
        assert_eq!(detect_bytes(b"\0asm\x01\0\0\0", None), ArtifactKind::Wasm);
    }

    #[test]
    fn detects_pe_only_with_pe_signature() {
        let mut pe = vec![0u8; 0x100];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c] = 0x80;
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(detect_bytes(&pe, None), ArtifactKind::Pe);
        pe[0x80] = b'X';
        assert_ne!(detect_bytes(&pe, None), ArtifactKind::Pe);
    }

    #[test]
    fn detects_json_family() {
        assert_eq!(
            detect_bytes(br#"{"log":{"version":"1.2","entries":[]}}"#, None),
            ArtifactKind::Har
        );
        assert_eq!(
            detect_bytes(br#"{"version":3,"sources":[],"mappings":""}"#, None),
            ArtifactKind::SourceMap
        );
        assert_eq!(detect_bytes(br#"{"a":1}"#, None), ArtifactKind::Json);
    }

    #[test]
    fn detects_js_and_text() {
        assert_eq!(
            detect_bytes(b"var a = 1;", Some("app.js")),
            ArtifactKind::JavaScript
        );
        assert_eq!(
            detect_bytes(b"!function(e){\"use strict\";var t=()=>1}()", None),
            ArtifactKind::JavaScript
        );
        assert_eq!(detect_bytes(b"hello world\n", None), ArtifactKind::Text);
        assert_eq!(
            detect_bytes(&[0u8, 1, 2, 3, 0xff, 0xfe, 9, 0], None),
            ArtifactKind::Blob
        );
    }
}
