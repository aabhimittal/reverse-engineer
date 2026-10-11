## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- [ ] New parsing code has a truncation/mutation test and does not `unwrap()` input-derived data
- [ ] New findings have a stable id, severity, evidence and description
- [ ] Fixtures are benign; key-shaped values are built at runtime
- [ ] Docs updated (`docs/`, `scripts/gen-cli-docs.sh` if flags changed)
