//! Syntax-aware extraction with tree-sitter: definitions, imports, calls, complexity.
//!
//! tree-sitter builds a concrete syntax tree for each file. Queries are
//! patterns over that tree, a structural `grep`: "give me every
//! `function_item` and its `name`". This is what turns a pile of text into
//! a map of symbols you can navigate.

use crate::lang::Lang;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::OnceLock;
use tree_sitter::{Language, Node, Parser, Query, QueryCursor, StreamingIterator};

/// Kind of definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DefKind {
    /// Free function.
    Function,
    /// Method (function inside a class/impl).
    Method,
    /// Class.
    Class,
    /// Struct.
    Struct,
    /// Enum.
    Enum,
    /// Trait.
    Trait,
    /// Interface.
    Interface,
}

impl DefKind {
    /// Is it callable?
    pub fn callable(self) -> bool {
        matches!(self, DefKind::Function | DefKind::Method)
    }
}

/// A definition found in a file.
#[derive(Debug, Clone, Serialize)]
pub struct Def {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: DefKind,
    /// Enclosing class/impl/struct name.
    pub container: Option<String>,
    /// 1-based start line.
    pub line: u32,
    /// 1-based end line.
    pub end_line: u32,
    /// Cyclomatic complexity (1 + decision points), callables only.
    pub complexity: u32,
    /// Names called from within this definition.
    pub calls: Vec<String>,
}

/// What we learn from parsing one file.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FileSyntax {
    /// Definitions.
    pub defs: Vec<Def>,
    /// Raw import specifiers (`os.path`, `./util`, `crate::model`, `github.com/x/y`).
    pub imports: Vec<String>,
    /// `mod foo;` declarations (Rust).
    pub mods: Vec<String>,
    /// Syntax errors encountered.
    pub has_errors: bool,
}

const RUST_Q: &str = r#"
(function_item name: (identifier) @name) @def.function
(function_signature_item name: (identifier) @name) @def.function
(struct_item name: (type_identifier) @name) @def.struct
(enum_item name: (type_identifier) @name) @def.enum
(trait_item name: (type_identifier) @name) @def.trait
(use_declaration argument: (_) @import)
(mod_item name: (identifier) @mod)
(call_expression function: (identifier) @call)
(call_expression function: (field_expression field: (field_identifier) @call))
(call_expression function: (scoped_identifier name: (identifier) @call))
"#;

const PY_Q: &str = r#"
(function_definition name: (identifier) @name) @def.function
(class_definition name: (identifier) @name) @def.class
(import_statement name: (dotted_name) @import)
(import_statement name: (aliased_import name: (dotted_name) @import))
(import_from_statement module_name: (_) @import)
(call function: (identifier) @call)
(call function: (attribute attribute: (identifier) @call))
"#;

const JS_Q: &str = r#"
(function_declaration name: (identifier) @name) @def.function
(generator_function_declaration name: (identifier) @name) @def.function
(method_definition name: (property_identifier) @name) @def.method
(class_declaration name: (_) @name) @def.class
(variable_declarator name: (identifier) @name value: (arrow_function)) @def.function
(variable_declarator name: (identifier) @name value: (function_expression)) @def.function
(import_statement source: (string) @import)
(export_statement source: (string) @import)
(call_expression function: (identifier) @call)
(call_expression function: (member_expression property: (property_identifier) @call))
"#;

const TS_EXTRA_Q: &str = r#"
(interface_declaration name: (type_identifier) @name) @def.interface
(enum_declaration name: (identifier) @name) @def.enum
"#;

const GO_Q: &str = r#"
(function_declaration name: (identifier) @name) @def.function
(method_declaration name: (field_identifier) @name) @def.method
(type_spec name: (type_identifier) @name type: (struct_type)) @def.struct
(type_spec name: (type_identifier) @name type: (interface_type)) @def.interface
(import_spec path: (interpreted_string_literal) @import)
(call_expression function: (identifier) @call)
(call_expression function: (selector_expression field: (field_identifier) @call))
"#;

const JAVA_Q: &str = r#"
(method_declaration name: (identifier) @name) @def.method
(constructor_declaration name: (identifier) @name) @def.method
(class_declaration name: (identifier) @name) @def.class
(interface_declaration name: (identifier) @name) @def.interface
(enum_declaration name: (identifier) @name) @def.enum
(record_declaration name: (identifier) @name) @def.class
(import_declaration (scoped_identifier) @import)
(method_invocation name: (identifier) @call)
(object_creation_expression type: (type_identifier) @call)
"#;

/// Node kinds that add a decision point (cyclomatic complexity).
const DECISION: &[&str] = &[
    "if_expression",
    "if_statement",
    "if_let_expression",
    "elif_clause",
    "else_if_clause",
    "for_expression",
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "while_expression",
    "while_statement",
    "do_statement",
    "loop_expression",
    "match_arm",
    "case_clause",
    "switch_case",
    "expression_case",
    "type_case",
    "communication_case",
    "switch_label",
    "catch_clause",
    "except_clause",
    "conditional_expression",
    "ternary_expression",
    "list_comprehension",
    "&&",
    "||",
    "and",
    "or",
];

fn language(l: Lang) -> Option<Language> {
    Some(match l {
        Lang::Rust => tree_sitter_rust::LANGUAGE.into(),
        Lang::Python => tree_sitter_python::LANGUAGE.into(),
        Lang::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        Lang::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        Lang::Tsx => tree_sitter_typescript::LANGUAGE_TSX.into(),
        Lang::Go => tree_sitter_go::LANGUAGE.into(),
        Lang::Java => tree_sitter_java::LANGUAGE.into(),
        _ => return None,
    })
}

fn query_src(l: Lang) -> Option<String> {
    Some(match l {
        Lang::Rust => RUST_Q.into(),
        Lang::Python => PY_Q.into(),
        Lang::JavaScript => JS_Q.into(),
        Lang::TypeScript | Lang::Tsx => format!("{JS_Q}\n{TS_EXTRA_Q}"),
        Lang::Go => GO_Q.into(),
        Lang::Java => JAVA_Q.into(),
        _ => return None,
    })
}

/// Compiled queries are cached per language (compilation is the expensive part).
fn query(l: Lang) -> Option<&'static Query> {
    static CACHE: OnceLock<HashMap<Lang, Query>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let mut m = HashMap::new();
            for l in [
                Lang::Rust,
                Lang::Python,
                Lang::JavaScript,
                Lang::TypeScript,
                Lang::Tsx,
                Lang::Go,
                Lang::Java,
            ] {
                if let (Some(lang), Some(src)) = (language(l), query_src(l)) {
                    match Query::new(&lang, &src) {
                        Ok(q) => {
                            m.insert(l, q);
                        }
                        Err(e) => {
                            tracing_warn(&format!("tree-sitter query for {} failed: {e}", l.name()))
                        }
                    }
                }
            }
            m
        })
        .get(&l)
}

fn tracing_warn(msg: &str) {
    // Kept dependency-free; surfaced through tests if a grammar update breaks a query.
    if std::env::var_os("REX_DEBUG").is_some() {
        eprintln!("rex-code: {msg}");
    }
}

fn container_of(node: Node, src: &[u8], lang: Lang) -> Option<String> {
    let mut p = node.parent();
    while let Some(n) = p {
        let name = match (lang, n.kind()) {
            (Lang::Rust, "impl_item") => n.child_by_field_name("type"),
            (Lang::Rust, "trait_item") => n.child_by_field_name("name"),
            (
                _,
                "class_definition"
                | "class_declaration"
                | "class"
                | "interface_declaration"
                | "enum_declaration"
                | "record_declaration",
            ) => n.child_by_field_name("name"),
            _ => None,
        };
        if let Some(nm) = name {
            return nm.utf8_text(src).ok().map(|s| s.to_string());
        }
        p = n.parent();
    }
    None
}

fn go_receiver(node: Node, src: &[u8]) -> Option<String> {
    let recv = node.child_by_field_name("receiver")?;
    let text = recv.utf8_text(src).ok()?;
    let ty = text
        .trim_matches(|c| c == '(' || c == ')')
        .split_whitespace()
        .last()?;
    Some(ty.trim_start_matches('*').to_string())
}

fn complexity(node: Node) -> u32 {
    let mut n = 1;
    let mut cursor = node.walk();
    let mut stack = vec![node];
    while let Some(cur) = stack.pop() {
        if cur.id() != node.id() && DECISION.contains(&cur.kind()) {
            n += 1;
        }
        for c in cur.children(&mut cursor) {
            stack.push(c);
        }
    }
    n
}

fn unquote(s: &str) -> String {
    s.trim_matches(|c| c == '"' || c == '\'' || c == '`')
        .to_string()
}

/// Parse and extract.
pub fn extract(lang: Lang, src: &str) -> Option<FileSyntax> {
    let ts_lang = language(lang)?;
    let q = query(lang)?;
    let mut parser = Parser::new();
    parser.set_language(&ts_lang).ok()?;
    let tree = parser.parse(src, None)?;
    let root = tree.root_node();
    let bytes = src.as_bytes();
    let mut out = FileSyntax {
        has_errors: root.has_error(),
        ..Default::default()
    };

    let names = q.capture_names();
    let mut defs: Vec<(Def, usize, usize)> = Vec::new(); // def + byte range
    let mut calls: Vec<(usize, String)> = Vec::new();
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(q, root, bytes);
    while let Some(m) = matches.next() {
        let mut def_node = None;
        let mut def_kind = None;
        let mut name = None;
        for c in m.captures() {
            let cap = names[c.index as usize];
            let text = c.node.utf8_text(bytes).unwrap_or("");
            match cap {
                "name" => name = Some(text.to_string()),
                "import" => out.imports.push(unquote(text)),
                "mod" => {
                    // Only `mod foo;` (no body) refers to another file.
                    if c.node
                        .parent()
                        .and_then(|p| p.child_by_field_name("body"))
                        .is_none()
                    {
                        out.mods.push(text.to_string());
                    }
                }
                "call" => calls.push((c.node.start_byte(), text.to_string())),
                k if k.starts_with("def.") => {
                    def_node = Some(c.node);
                    def_kind = Some(match &k[4..] {
                        "function" => DefKind::Function,
                        "method" => DefKind::Method,
                        "class" => DefKind::Class,
                        "struct" => DefKind::Struct,
                        "enum" => DefKind::Enum,
                        "trait" => DefKind::Trait,
                        _ => DefKind::Interface,
                    });
                }
                _ => {}
            }
        }
        if let (Some(node), Some(mut kind), Some(name)) = (def_node, def_kind, name) {
            let container = if lang == Lang::Go && node.kind() == "method_declaration" {
                go_receiver(node, bytes)
            } else {
                container_of(node, bytes, lang)
            };
            if kind == DefKind::Function && container.is_some() {
                kind = DefKind::Method;
            }
            let cx = if kind.callable() { complexity(node) } else { 0 };
            defs.push((
                Def {
                    name,
                    kind,
                    container,
                    line: node.start_position().row as u32 + 1,
                    end_line: node.end_position().row as u32 + 1,
                    complexity: cx,
                    calls: Vec::new(),
                },
                node.start_byte(),
                node.end_byte(),
            ));
        }
    }
    // Attribute each call to the innermost enclosing callable.
    for (pos, name) in calls {
        if let Some((d, _, _)) = defs
            .iter_mut()
            .filter(|(d, s, e)| d.kind.callable() && *s <= pos && pos < *e)
            .min_by_key(|(_, s, e)| e - s)
        {
            if !d.calls.contains(&name) {
                d.calls.push(name);
            }
        }
    }
    out.defs = defs.into_iter().map(|(d, _, _)| d).collect();
    out.imports.sort();
    out.imports.dedup();
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(fs: &FileSyntax) -> Vec<String> {
        fs.defs
            .iter()
            .map(|d| {
                format!(
                    "{:?}:{}{}",
                    d.kind,
                    d.container
                        .as_deref()
                        .map(|c| format!("{c}."))
                        .unwrap_or_default(),
                    d.name
                )
            })
            .collect()
    }

    #[test]
    fn all_queries_compile() {
        for l in [
            Lang::Rust,
            Lang::Python,
            Lang::JavaScript,
            Lang::TypeScript,
            Lang::Tsx,
            Lang::Go,
            Lang::Java,
        ] {
            let lang = language(l).unwrap();
            Query::new(&lang, &query_src(l).unwrap())
                .unwrap_or_else(|e| panic!("{}: {e}", l.name()));
        }
    }

    #[test]
    fn rust() {
        let src = "use crate::model::Binary;\nmod disasm;\nmod inline { fn x() {} }\nstruct S;\nimpl S {\n    fn go(&self, a: bool) -> u8 { if a && true { helper() } else { 0 } }\n}\nfn helper() -> u8 { S.go(false); 1 }\n";
        let fs = extract(Lang::Rust, src).unwrap();
        let n = names(&fs);
        assert!(n.contains(&"Method:S.go".to_string()), "{n:?}");
        assert!(n.contains(&"Function:helper".to_string()));
        assert!(n.contains(&"Struct:S".to_string()));
        assert_eq!(fs.imports, vec!["crate::model::Binary"]);
        assert_eq!(fs.mods, vec!["disasm"]);
        let go = fs.defs.iter().find(|d| d.name == "go").unwrap();
        assert_eq!(go.complexity, 3, "if + &&");
        assert_eq!(go.calls, vec!["helper"]);
        assert!(
            fs.defs
                .iter()
                .find(|d| d.name == "helper")
                .unwrap()
                .calls
                .contains(&"go".to_string())
        );
    }

    #[test]
    fn python() {
        let src = "import os.path\nfrom .util import x\nimport numpy as np\nclass A:\n    def m(self):\n        for i in range(3):\n            os.path.join('a')\n\ndef f():\n    return A().m()\n";
        let fs = extract(Lang::Python, src).unwrap();
        let n = names(&fs);
        assert!(n.contains(&"Method:A.m".to_string()), "{n:?}");
        assert!(n.contains(&"Class:A".to_string()));
        assert!(fs.imports.contains(&"os.path".to_string()));
        assert!(fs.imports.contains(&".util".to_string()));
        assert!(
            fs.imports.contains(&"numpy".to_string()),
            "{:?}",
            fs.imports
        );
        let m = fs.defs.iter().find(|d| d.name == "m").unwrap();
        assert_eq!(m.complexity, 2);
        assert!(m.calls.contains(&"join".to_string()));
    }

    #[test]
    fn javascript_and_typescript() {
        let src = "import { a } from './a';\nexport * from \"./b\";\nclass C { run() { return a(); } }\nconst f = () => fetch('/x');\nfunction g() { return x ? 1 : 2; }\n";
        let fs = extract(Lang::JavaScript, src).unwrap();
        let n = names(&fs);
        assert!(n.contains(&"Method:C.run".to_string()), "{n:?}");
        assert!(n.contains(&"Function:f".to_string()));
        assert_eq!(fs.imports, vec!["./a", "./b"]);
        assert_eq!(
            fs.defs.iter().find(|d| d.name == "g").unwrap().complexity,
            2
        );
        let ts = extract(Lang::TypeScript, "interface I { x: number }\nexport class K implements I { x = 1; m(): void {} }\nenum E { A }\n").unwrap();
        let n = names(&ts);
        assert!(n.contains(&"Interface:I".to_string()), "{n:?}");
        assert!(n.contains(&"Class:K".to_string()));
        assert!(n.contains(&"Method:K.m".to_string()));
        assert!(extract(Lang::Tsx, "const A = () => <div/>;\n").is_some());
    }

    #[test]
    fn go() {
        let src = "package main\nimport (\n  \"fmt\"\n  \"example.com/app/internal/db\"\n)\ntype Server struct{}\ntype Store interface{ Get() }\nfunc (s *Server) Handle() { if true { fmt.Println(db.Open()) } }\nfunc main() { (&Server{}).Handle() }\n";
        let fs = extract(Lang::Go, src).unwrap();
        let n = names(&fs);
        assert!(n.contains(&"Method:Server.Handle".to_string()), "{n:?}");
        assert!(n.contains(&"Struct:Server".to_string()));
        assert!(n.contains(&"Interface:Store".to_string()));
        assert_eq!(fs.imports, vec!["example.com/app/internal/db", "fmt"]);
        assert!(
            fs.defs
                .iter()
                .find(|d| d.name == "main")
                .unwrap()
                .calls
                .contains(&"Handle".to_string())
        );
    }

    #[test]
    fn java() {
        let src = "package com.x;\nimport com.x.db.Repo;\npublic class Svc implements Api {\n  public Svc() {}\n  void run() { try { new Repo().save(); } catch (Exception e) {} }\n}\ninterface Api {}\n";
        let fs = extract(Lang::Java, src).unwrap();
        let n = names(&fs);
        assert!(n.contains(&"Method:Svc.run".to_string()), "{n:?}");
        assert!(n.contains(&"Class:Svc".to_string()));
        assert!(n.contains(&"Interface:Api".to_string()));
        assert_eq!(fs.imports, vec!["com.x.db.Repo"]);
        let run = fs.defs.iter().find(|d| d.name == "run").unwrap();
        assert_eq!(run.complexity, 2);
        assert!(run.calls.contains(&"save".to_string()) && run.calls.contains(&"Repo".to_string()));
    }
}
