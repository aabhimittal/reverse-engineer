//! Mutation testing for the syntax layer: broken, truncated and non-UTF-8-ish sources must not panic.

use rex_code::{lang::Lang, syntax};

#[test]
fn mutated_sources_never_panic() {
    let seeds: Vec<(Lang, String)> = vec![
        (Lang::Rust, "use a::b;\nmod m;\nstruct S;\nimpl S { fn f(&self) -> u8 { if true { g() } else { 0 } } }\nfn g() -> u8 { 1 }\n".into()),
        (Lang::Python, "import os\nfrom . import x\nclass A:\n    def m(self):\n        for i in range(3):\n            os.system('é')\n".into()),
        (Lang::TypeScript, "import { a } from './a';\nexport class C { run() { return a() ? 1 : 2; } }\nconst f = () => fetch('/x');\n".into()),
        (Lang::Go, "package main\nimport \"fmt\"\ntype S struct{}\nfunc (s *S) H() { fmt.Println(1) }\nfunc main() {}\n".into()),
        (Lang::Java, "package p;\nimport a.B;\nclass C { C() {} void m() { try { new B().x(); } catch (Exception e) {} } }\n".into()),
    ];
    let mut state = 0xdead_beef_cafe_f00du64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..800 {
        let (lang, src) = &seeds[round % seeds.len()];
        let mut bytes = src.clone().into_bytes();
        for _ in 0..1 + next() % 6 {
            let i = (next() as usize) % bytes.len();
            match next() % 3 {
                0 => bytes[i] = b"{}()[];\"'<>\\"[(next() % 12) as usize],
                1 => {
                    bytes.remove(i);
                }
                _ => bytes.insert(i, 0xc3),
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        let _ = syntax::extract(*lang, &text);
        let _ = rex_code::lang::count(*lang, &text);
    }
}
