//! Packer / obfuscation heuristics.
//!
//! A packer compresses or encrypts the real program and prepends a small
//! unpacking stub. Analogy: a vacuum-sealed suitcase. From the outside you see
//! only the bag (high entropy, few imports, odd section names); the clothes
//! (real code) only appear once it's opened at runtime.

use crate::model::{BinFormat, Binary};
use serde::Serialize;

/// Verdict with the reasons behind it.
#[derive(Debug, Clone, Serialize)]
pub struct PackerVerdict {
    /// Named packer, if a signature matched.
    pub name: Option<String>,
    /// Heuristic score 0–100.
    pub score: u32,
    /// Reasons.
    pub reasons: Vec<String>,
}

impl PackerVerdict {
    /// Likely packed?
    pub fn is_packed(&self) -> bool {
        self.name.is_some() || self.score >= 50
    }
}

const SECTION_SIGNATURES: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    ("ASPack", "ASPack"),
    (".MPRESS1", "MPRESS"),
    (".MPRESS2", "MPRESS"),
    (".petite", "Petite"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    ("PEC2", "PECompact"),
    ("pec1", "PECompact"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".enigma1", "Enigma Protector"),
    (".perplex", "Perplex"),
    ("MEW", "MEW"),
    (".packed", "generic"),
    (".kkrunchy", "kkrunchy"),
    (".boom", "The Boomerang"),
    (".ccg", "CCG"),
    (".spack", "Simple Pack"),
    (".yP", "Y0da Protector"),
    (".y0da", "Y0da Protector"),
];

/// Run all heuristics.
pub fn detect(bin: &Binary, data: &[u8]) -> PackerVerdict {
    let mut score = 0u32;
    let mut reasons = Vec::new();
    let mut name = None;

    for s in &bin.sections {
        if let Some((_, p)) = SECTION_SIGNATURES.iter().find(|(n, _)| s.name == *n) {
            name = Some(p.to_string());
            reasons.push(format!("section name '{}' is a {} signature", s.name, p));
        }
    }
    if memchr::memmem::find(data, b"UPX!").is_some() {
        name.get_or_insert_with(|| "UPX".into());
        reasons.push("'UPX!' magic present".into());
    }
    if memchr::memmem::find(data, b"$Info: This file is packed with the UPX").is_some() {
        name.get_or_insert_with(|| "UPX".into());
    }

    let overall = rex_core::hash::entropy(data);
    if overall > 7.2 {
        score += 30;
        reasons.push(format!("overall entropy {overall:.2} > 7.2"));
    }
    let hi_exec: Vec<_> = bin
        .sections
        .iter()
        .filter(|s| s.perms.x && s.file_size > 512 && s.entropy > 7.0)
        .collect();
    if !hi_exec.is_empty() {
        score += 30;
        reasons.push(format!(
            "executable section(s) with entropy > 7.0: {}",
            hi_exec
                .iter()
                .map(|s| format!("{} ({:.2})", s.name, s.entropy))
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let wx: Vec<_> = bin
        .sections
        .iter()
        .filter(|s| s.perms.w && s.perms.x)
        .collect();
    if !wx.is_empty() {
        score += 20;
        reasons.push(format!(
            "writable+executable section(s): {}",
            wx.iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let virt_only: Vec<_> = bin
        .sections
        .iter()
        .filter(|s| s.perms.x && s.file_size == 0 && s.size > 0)
        .collect();
    if !virt_only.is_empty() {
        score += 15;
        reasons.push("executable section with no file data (filled at runtime)".into());
    }
    if bin.format == BinFormat::Pe && !bin.imports.is_empty() && bin.imports.len() < 10 {
        let names = bin.import_names();
        if names.iter().any(|n| n == "GetProcAddress")
            && names.iter().any(|n| n.starts_with("LoadLibrary"))
        {
            score += 20;
            reasons.push(format!(
                "tiny import table ({} imports) with LoadLibrary+GetProcAddress",
                bin.imports.len()
            ));
        }
    }
    if bin.entry != 0 {
        if let Some(sec) = bin.section_for(bin.entry) {
            let last_exec = bin.code_sections().last().map(|s| s.name.clone());
            let first_exec = bin.code_sections().next().map(|s| s.name.clone());
            if bin.format == BinFormat::Pe
                && first_exec != last_exec
                && last_exec.as_deref() == Some(sec.name.as_str())
            {
                score += 15;
                reasons.push(format!(
                    "entry point in last executable section '{}'",
                    sec.name
                ));
            }
            if !sec.perms.x {
                score += 25;
                reasons.push(format!(
                    "entry point in non-executable section '{}'",
                    sec.name
                ));
            }
        } else {
            score += 25;
            reasons.push("entry point outside all sections".into());
        }
    }
    if name.is_some() {
        score = score.max(90);
    }
    PackerVerdict {
        name,
        score: score.min(100),
        reasons,
    }
}
