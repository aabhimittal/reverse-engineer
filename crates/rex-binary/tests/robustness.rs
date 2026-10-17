//! Seeded mutation testing for the native parsers, disassembler and carver.

use rex_binary::{Binary, carve, functions, packer, strings};
use rex_core::AnalysisOptions;
use std::path::PathBuf;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

#[test]
fn mutated_binaries_never_panic() {
    let seeds: Vec<Vec<u8>> = [
        "crackme.elf",
        "vuln.elf",
        "sample.exe",
        "hello.macho",
        "sample_thumb.elf",
    ]
    .iter()
    .map(|n| fixture(n))
    .collect();
    let opts = AnalysisOptions {
        max_functions: 100,
        max_insns_per_function: 1000,
        ..Default::default()
    };
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..600 {
        let mut d = seeds[round % seeds.len()].clone();
        for _ in 0..1 + (next() % 12) {
            // Bias mutations toward headers, where the interesting parsing happens.
            let i = if next() % 2 == 0 {
                (next() as usize) % d.len().min(1024)
            } else {
                (next() as usize) % d.len()
            };
            d[i] = (next() & 0xff) as u8;
        }
        if next() % 5 == 0 {
            d.truncate((next() as usize) % d.len());
        }
        if let Ok(b) = Binary::parse(&d) {
            let _ = functions::analyze(&b, &d, &opts);
            let _ = packer::detect(&b, &d);
        }
        let _ = carve::scan(&d, round % 2 == 0);
        let _ = strings::extract(&d, 4);
    }
}
