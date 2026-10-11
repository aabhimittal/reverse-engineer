#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(x) = rex_web::axml::parse(data) {
        let _ = rex_web::axml::Manifest::from_xml(&x);
        let _ = x.to_xml();
    }
    if let Ok(d) = rex_web::dex::parse(data) {
        let _ = rex_web::dex::risky_apis(&d);
    }
    let _ = rex_web::apk::analyze(data);
});
