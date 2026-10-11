//! Language detection and line counting.

use serde::Serialize;

/// Languages rex knows about. Six have full syntax support (tree-sitter);
/// the rest are counted for the language breakdown.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Lang {
    /// Rust.
    Rust,
    /// Python.
    Python,
    /// JavaScript.
    JavaScript,
    /// TypeScript.
    TypeScript,
    /// TSX.
    Tsx,
    /// Go.
    Go,
    /// Java.
    Java,
    /// C.
    C,
    /// C++.
    Cpp,
    /// C#.
    CSharp,
    /// Kotlin.
    Kotlin,
    /// Swift.
    Swift,
    /// Objective-C.
    ObjC,
    /// Ruby.
    Ruby,
    /// PHP.
    Php,
    /// Scala.
    Scala,
    /// Dart.
    Dart,
    /// Lua.
    Lua,
    /// Shell.
    Shell,
    /// PowerShell.
    PowerShell,
    /// SQL.
    Sql,
    /// HTML.
    Html,
    /// CSS / SCSS.
    Css,
    /// Vue SFC.
    Vue,
    /// Svelte.
    Svelte,
    /// Markdown.
    Markdown,
    /// YAML.
    Yaml,
    /// TOML.
    Toml,
    /// JSON.
    Json,
    /// Protocol Buffers.
    Proto,
    /// Terraform / HCL.
    Hcl,
    /// Dockerfile.
    Dockerfile,
    /// Makefile.
    Make,
    /// Assembly.
    Asm,
    /// Zig.
    Zig,
    /// Elixir.
    Elixir,
    /// Haskell.
    Haskell,
    /// Solidity.
    Solidity,
}

impl Lang {
    /// Detect from a file name.
    pub fn from_path(path: &std::path::Path) -> Option<Lang> {
        let name = path.file_name()?.to_str()?;
        match name {
            "Dockerfile" | "Containerfile" => return Some(Lang::Dockerfile),
            "Makefile" | "makefile" | "GNUmakefile" => return Some(Lang::Make),
            "Rakefile" | "Gemfile" => return Some(Lang::Ruby),
            _ => {}
        }
        if name.starts_with("Dockerfile.") {
            return Some(Lang::Dockerfile);
        }
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Some(match ext.as_str() {
            "rs" => Lang::Rust,
            "py" | "pyi" | "pyw" => Lang::Python,
            "js" | "mjs" | "cjs" | "jsx" => Lang::JavaScript,
            "ts" | "mts" | "cts" => Lang::TypeScript,
            "tsx" => Lang::Tsx,
            "go" => Lang::Go,
            "java" => Lang::Java,
            "c" | "h" => Lang::C,
            "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" | "ino" => Lang::Cpp,
            "cs" => Lang::CSharp,
            "kt" | "kts" => Lang::Kotlin,
            "swift" => Lang::Swift,
            "m" | "mm" => Lang::ObjC,
            "rb" => Lang::Ruby,
            "php" => Lang::Php,
            "scala" | "sc" => Lang::Scala,
            "dart" => Lang::Dart,
            "lua" => Lang::Lua,
            "sh" | "bash" | "zsh" | "fish" => Lang::Shell,
            "ps1" | "psm1" => Lang::PowerShell,
            "sql" => Lang::Sql,
            "html" | "htm" => Lang::Html,
            "css" | "scss" | "sass" | "less" => Lang::Css,
            "vue" => Lang::Vue,
            "svelte" => Lang::Svelte,
            "md" | "markdown" | "mdx" => Lang::Markdown,
            "yml" | "yaml" => Lang::Yaml,
            "toml" => Lang::Toml,
            "json" | "jsonc" => Lang::Json,
            "proto" => Lang::Proto,
            "tf" | "hcl" => Lang::Hcl,
            "mk" => Lang::Make,
            "s" | "asm" => Lang::Asm,
            "zig" => Lang::Zig,
            "ex" | "exs" => Lang::Elixir,
            "hs" => Lang::Haskell,
            "sol" => Lang::Solidity,
            _ => return None,
        })
    }

    /// Display name.
    pub fn name(self) -> &'static str {
        match self {
            Lang::Rust => "Rust",
            Lang::Python => "Python",
            Lang::JavaScript => "JavaScript",
            Lang::TypeScript => "TypeScript",
            Lang::Tsx => "TSX",
            Lang::Go => "Go",
            Lang::Java => "Java",
            Lang::C => "C",
            Lang::Cpp => "C++",
            Lang::CSharp => "C#",
            Lang::Kotlin => "Kotlin",
            Lang::Swift => "Swift",
            Lang::ObjC => "Objective-C",
            Lang::Ruby => "Ruby",
            Lang::Php => "PHP",
            Lang::Scala => "Scala",
            Lang::Dart => "Dart",
            Lang::Lua => "Lua",
            Lang::Shell => "Shell",
            Lang::PowerShell => "PowerShell",
            Lang::Sql => "SQL",
            Lang::Html => "HTML",
            Lang::Css => "CSS",
            Lang::Vue => "Vue",
            Lang::Svelte => "Svelte",
            Lang::Markdown => "Markdown",
            Lang::Yaml => "YAML",
            Lang::Toml => "TOML",
            Lang::Json => "JSON",
            Lang::Proto => "Protobuf",
            Lang::Hcl => "HCL/Terraform",
            Lang::Dockerfile => "Dockerfile",
            Lang::Make => "Makefile",
            Lang::Asm => "Assembly",
            Lang::Zig => "Zig",
            Lang::Elixir => "Elixir",
            Lang::Haskell => "Haskell",
            Lang::Solidity => "Solidity",
        }
    }

    /// Is this source code (as opposed to docs/config/data)?
    pub fn is_code(self) -> bool {
        !matches!(
            self,
            Lang::Markdown | Lang::Yaml | Lang::Toml | Lang::Json | Lang::Html | Lang::Css
        )
    }

    /// Does rex have a syntax parser for it?
    pub fn has_syntax(self) -> bool {
        matches!(
            self,
            Lang::Rust
                | Lang::Python
                | Lang::JavaScript
                | Lang::TypeScript
                | Lang::Tsx
                | Lang::Go
                | Lang::Java
        )
    }

    fn comments(
        self,
    ) -> (
        &'static [&'static str],
        Option<(&'static str, &'static str)>,
    ) {
        match self {
            Lang::Python
            | Lang::Ruby
            | Lang::Shell
            | Lang::Yaml
            | Lang::Toml
            | Lang::Make
            | Lang::Dockerfile
            | Lang::Hcl
            | Lang::Elixir
            | Lang::PowerShell => (
                &["#"],
                if self == Lang::Python {
                    Some(("\"\"\"", "\"\"\""))
                } else {
                    None
                },
            ),
            Lang::Sql | Lang::Lua | Lang::Haskell => (&["--"], None),
            Lang::Html | Lang::Markdown | Lang::Vue | Lang::Svelte => (&[], Some(("<!--", "-->"))),
            Lang::Asm => (&[";", "#", "//"], None),
            Lang::Json => (&[], None),
            _ => (&["//"], Some(("/*", "*/"))),
        }
    }
}

/// Line counts for a file.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Loc {
    /// Lines of code.
    pub code: usize,
    /// Comment lines.
    pub comment: usize,
    /// Blank lines.
    pub blank: usize,
}

/// Count code / comment / blank lines (heuristic; ignores comment markers inside strings).
pub fn count(lang: Lang, src: &str) -> Loc {
    let (line_c, block) = lang.comments();
    let mut loc = Loc::default();
    let mut in_block = false;
    for line in src.lines() {
        let t = line.trim();
        if t.is_empty() {
            loc.blank += 1;
            continue;
        }
        if in_block {
            loc.comment += 1;
            if let Some((_, end)) = block {
                if t.contains(end) {
                    in_block = false;
                }
            }
            continue;
        }
        if line_c.iter().any(|c| t.starts_with(c)) {
            loc.comment += 1;
            continue;
        }
        if let Some((start, end)) = block {
            if let Some(rest) = t.strip_prefix(start) {
                loc.comment += 1;
                if !rest.contains(end) {
                    in_block = true;
                }
                continue;
            }
        }
        loc.code += 1;
    }
    loc
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn detects() {
        assert_eq!(Lang::from_path(Path::new("a/b.rs")), Some(Lang::Rust));
        assert_eq!(
            Lang::from_path(Path::new("Dockerfile")),
            Some(Lang::Dockerfile)
        );
        assert_eq!(Lang::from_path(Path::new("x.TSX")), Some(Lang::Tsx));
        assert_eq!(Lang::from_path(Path::new("x.bin")), None);
    }

    #[test]
    fn counts() {
        let l = count(
            Lang::Rust,
            "// c\nfn a() {}\n\n/* x\n y */\nlet b = 1; // tail\n",
        );
        assert_eq!((l.code, l.comment, l.blank), (2, 3, 1));
        let p = count(Lang::Python, "# c\n\"\"\"doc\nmore\n\"\"\"\nx = 1\n");
        assert_eq!((p.code, p.comment), (1, 4));
    }
}
