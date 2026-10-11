//! Library usage: analyse a HAR / JS bundle / source map / APK / DEX and print a report.
//!
//! ```sh
//! cargo run -p rex-web --example analyze -- labs/web/sample.har
//! ```
use rex_core::{AnalysisOptions, Artifact, DEFAULT_MAX_SIZE, Registry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: analyze <file>")?;
    let artifact = Artifact::from_path(&path, DEFAULT_MAX_SIZE)?;
    let mut registry = Registry::new();
    rex_web::register(&mut registry);
    let report = registry.run(&artifact, &AnalysisOptions::default(), &[]);
    print!(
        "{}",
        rex_report::render(&report, rex_report::Format::Text, Default::default())
    );
    Ok(())
}
