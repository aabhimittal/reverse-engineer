#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = rex_binary::wasm::parse(data) {
        for i in 0..8 {
            let _ = m.func_name(i);
        }
    }
    if let Ok(a) = rex_web::asar::parse(data) {
        for e in &a.entries {
            let _ = a.read(e);
        }
    }
});
