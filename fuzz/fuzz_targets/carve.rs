#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rex_fuzz::only_rex_panics_are_bugs();
    let _ = rex_binary::carve::scan(data, false);
    let _ = rex_binary::strings::extract(data, 4);
});
