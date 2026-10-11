#![no_main]
use libfuzzer_sys::fuzz_target;

// Hostile executables must never panic or hang: parse, then recover functions.
fuzz_target!(|data: &[u8]| {
    if let Ok(b) = rex_binary::Binary::parse(data) {
        let opts = rex_core::AnalysisOptions { max_functions: 200, max_insns_per_function: 2000, ..Default::default() };
        let _ = rex_binary::functions::analyze(&b, data, &opts);
        let _ = rex_binary::packer::detect(&b, data);
    }
});
