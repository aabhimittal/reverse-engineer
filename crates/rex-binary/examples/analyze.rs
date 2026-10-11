//! Library usage: run every binary analyzer on a file and print a terminal report.
//!
//! ```sh
//! cargo run -p rex-binary --example analyze -- /bin/ls
//! ```
use rex_core::{AnalysisOptions, Artifact, DEFAULT_MAX_SIZE, Registry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: analyze <file>")?;
    let artifact = Artifact::from_path(&path, DEFAULT_MAX_SIZE)?;
    let mut registry = Registry::new();
    rex_binary::register(&mut registry);
    let report = registry.run(&artifact, &AnalysisOptions::default(), &[]);
    print!(
        "{}",
        rex_report::render(&report, rex_report::Format::Text, Default::default())
    );
    Ok(())
}
