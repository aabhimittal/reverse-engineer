//! YARA scanning via the pure-Rust YARA-X engine (feature `yara`).

use rex_core::{Error, Result};
use serde::Serialize;
use std::path::Path;

/// Starter rules bundled with rex. Extend with `--rules <dir|file>`.
pub const BUNDLED_RULES: &str = include_str!("../rules/rex_starter.yar");

/// One rule match.
#[derive(Debug, Clone, Serialize)]
pub struct YaraMatch {
    /// Rule identifier.
    pub rule: String,
    /// Namespace.
    pub namespace: String,
    /// Matched pattern identifiers with first offsets.
    pub patterns: Vec<(String, u64)>,
}

/// Compile bundled rules plus any `.yar`/`.yara` files under `extra`.
pub fn compile(extra: Option<&Path>) -> Result<yara_x::Rules> {
    let mut c = yara_x::Compiler::new();
    c.new_namespace("rex");
    c.add_source(BUNDLED_RULES)
        .map_err(|e| Error::Other(format!("bundled rules: {e}")))?;
    if let Some(p) = extra {
        let files: Vec<std::path::PathBuf> = if p.is_dir() {
            std::fs::read_dir(p)
                .map_err(|e| Error::Io {
                    path: p.into(),
                    source: e,
                })?
                .filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| matches!(p.extension().and_then(|e| e.to_str()), Some("yar" | "yara")))
                .collect()
        } else {
            vec![p.to_path_buf()]
        };
        for f in files {
            let src = std::fs::read_to_string(&f).map_err(|e| Error::Io {
                path: f.clone(),
                source: e,
            })?;
            c.new_namespace(f.file_stem().and_then(|s| s.to_str()).unwrap_or("user"));
            c.add_source(src.as_str())
                .map_err(|e| Error::Other(format!("{}: {e}", f.display())))?;
        }
    }
    Ok(c.build())
}

/// Scan bytes.
pub fn scan(rules: &yara_x::Rules, data: &[u8]) -> Result<Vec<YaraMatch>> {
    let mut s = yara_x::Scanner::new(rules);
    s.set_timeout(std::time::Duration::from_secs(60));
    let res = s.scan(data).map_err(|e| Error::Other(e.to_string()))?;
    Ok(res
        .matching_rules()
        .map(|r| YaraMatch {
            rule: r.identifier().to_string(),
            namespace: r.namespace().to_string(),
            patterns: r
                .patterns()
                .filter_map(|p| {
                    p.matches()
                        .next()
                        .map(|m| (p.identifier().to_string(), m.range().start as u64))
                })
                .collect(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundled_rules_compile_and_match() {
        let rules = compile(None).unwrap();
        let clean = scan(&rules, b"just some ordinary bytes").unwrap();
        assert!(clean.is_empty());
        let hit = scan(&rules, b"cmd /c vssadmin delete shadows /all /quiet").unwrap();
        assert!(
            hit.iter().any(|m| m.rule == "rex_shadow_copy_deletion"),
            "{hit:?}"
        );
    }

    #[test]
    fn user_rules_are_loaded() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(
            d.path().join("mine.yar"),
            "rule mine { strings: $a = \"rexlab-marker\" condition: $a }",
        )
        .unwrap();
        let rules = compile(Some(d.path())).unwrap();
        let hit = scan(&rules, b"xx rexlab-marker xx").unwrap();
        assert!(
            hit.iter()
                .any(|m| m.rule == "mine" && m.namespace == "mine")
        );
    }
}
