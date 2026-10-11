# Security policy

## Reporting a vulnerability in rex

rex parses untrusted files by design, so parser bugs (panics, hangs, out-of-bounds reads, path traversal in
extraction, excessive memory use) are in scope. Please report them privately through GitHub's
**"Report a vulnerability"** (Security tab) rather than a public issue. Include a minimal input that reproduces
the problem. We aim to acknowledge reports within 7 days.

## Safe handling of samples

- rex never executes its input, but other tools might. Analyse malware only in an isolated environment.
- Don't attach live malware or real credentials to issues. Describe the sample or share a hash; use a synthetic
  reproducer where possible.
- HAR files contain live tokens and cookies. Sanitise before sharing.

## Design guarantees

- `#![forbid(unsafe_code)]` in every crate.
- Size limits (`--max-size`), bounded loops and allocations, per-analyzer panic isolation.
- Archive extraction (`carve`, source maps) never writes outside the chosen output directory.
- AI features are opt-in, redact detected secrets, and can run fully local (`--ai-provider ollama`).
