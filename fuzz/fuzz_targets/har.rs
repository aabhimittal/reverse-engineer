#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    rex_fuzz::only_rex_panics_are_bugs();
    if let Ok(h) = rex_web::har::parse(data) {
        let eps = rex_web::har::extract(&h, &Default::default());
        let _ = rex_web::openapi::build(&h, &eps, None);
        let _ = rex_web::audit::audit(&h);
    }
    let _ = rex_web::js::analyze(&String::from_utf8_lossy(data));
});
