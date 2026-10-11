# Contributing to rex

Thanks for helping! The fastest way to land a change is a small, well-tested pull request.

## Setup

```sh
git clone https://github.com/aabhimittal/reverse-engineer && cd reverse-engineer
cargo test --workspace            # ~100 tests, no external toolchains needed
make -C labs                      # optional: build lab binaries (needs a C compiler)
```

Before opening a PR:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
scripts/gen-cli-docs.sh           # if you changed CLI flags
```

## Good first contributions

- **Capability rules** (`crates/rex-binary/src/capabilities.rs`): add a rule with an ATT&CK id and a test.
- **Route patterns** for another web framework (`crates/rex-code/src/patterns.rs`).
- **Language support** in `rex-code` (a tree-sitter grammar plus a query and a test).
- **Handbook chapters and lab exercises** (`docs/`, `labs/`).
- **Analyzer ideas**: see [architecture](docs/src/reference/architecture.md) for the trait you implement.

## Ground rules

1. **Never execute the input.** rex is static analysis only.
2. **Hostile input is the default.** No `unwrap()` on data derived from the input; bound loops and allocations; slice
   strings on char boundaries. New parsers need a truncation/mutation test (see `crates/*/tests/robustness.rs`).
3. **Findings need stable ids, a severity, and evidence**, and should say why they matter.
4. **Fixtures must be benign and reproducible.** No real malware, no real credentials. Assemble key-shaped test
   values at runtime so secret scanners stay quiet (see existing tests).
5. **No `unsafe`.** Every crate is `#![forbid(unsafe_code)]`.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Don't file vulnerabilities as public issues.
