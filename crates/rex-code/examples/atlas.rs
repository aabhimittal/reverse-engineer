//! Library usage: generate a Markdown codebase atlas.
//!
//! ```sh
//! cargo run -p rex-code --example atlas -- path/to/repo > ATLAS.md
//! ```
use rex_core::{AnalysisOptions, Artifact, DEFAULT_MAX_SIZE, Registry};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let artifact = Artifact::from_path(&path, DEFAULT_MAX_SIZE)?;
    let mut registry = Registry::new();
    rex_code::register(&mut registry);
    let report = registry.run(&artifact, &AnalysisOptions::default(), &[]);
    print!(
        "{}",
        rex_report::render(&report, rex_report::Format::Markdown, Default::default())
    );
    Ok(())
}
