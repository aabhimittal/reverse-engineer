//! Shared setup for the fuzz targets.

/// libfuzzer-sys aborts on every panic. rex wraps third-party parsers in `catch_unwind`, so a
/// panic inside goblin, capstone or zip is already contained in production. Mirror that: abort
/// only when the panic comes from rex's own code, where it would mean lost analysis or a crash.
pub fn only_rex_panics_are_bugs() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            let ours = info
                .location()
                .is_some_and(|l| l.file().contains("crates/rex-") || l.file().contains("fuzz_targets"));
            if ours {
                eprintln!("{info}");
                std::process::abort();
            }
        }));
    });
}
