#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = rex_binary::wasm::parse(data) {
        for i in 0..(m.imported_functions + m.defined_functions).min(64) {
            let _ = m.func_name(i as u32);
            if let Ok(l) = rex_binary::wasm_ops::disassemble(&m, data, i as u32) {
                let _ = l.render();
            }
        }
    }
    if let Ok(a) = rex_web::asar::parse(data) {
        for e in &a.entries {
            let _ = a.read(e);
        }
    }
});
