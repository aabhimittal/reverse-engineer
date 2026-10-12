#![no_main]
use libfuzzer_sys::fuzz_target;

// The whole `rex analyze` pipeline (detection, then every applicable analyzer) on arbitrary bytes,
// with small limits so each input stays fast. Catches panics in analyzers that the per-format
// targets don't reach, such as capabilities, strings, fingerprints and findings rules.
fuzz_target!(|data: &[u8]| {
    rex_fuzz::only_rex_panics_are_bugs();
    let a = rex_core::Artifact::from_bytes("fuzz.bin", data.to_vec());
    let opts = rex_core::AnalysisOptions {
        max_functions: 100,
        max_insns_per_function: 2000,
        max_rows: 20,
        ..Default::default()
    };
    let _ = rex_engine::analyze(&a, &opts, &[]);
});
