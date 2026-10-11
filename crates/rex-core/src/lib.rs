//! # rex-core
//!
//! The shared vocabulary of the `rex` reverse-engineering toolkit.
//!
//! Every analysis in rex follows one pipeline:
//!
//! ```text
//!   input path ──► Artifact ──► detect kind ──► Analyzers (parallel) ──► Sections + Findings ──► Report
//! ```
//!
//! * [`Artifact`] is the thing under study: bytes plus an identified [`ArtifactKind`].
//! * [`Analyzer`] is a plugin that knows how to look at certain kinds of artifacts.
//! * [`Section`] is a renderable chunk of results (tables, key/values, diagrams, code).
//! * [`Finding`] is a judgement with a severity ("NX is disabled", "AWS key in bundle").
//! * [`Report`] bundles it all and is rendered by `rex-report` into text, JSON,
//!   Markdown, SARIF or HTML.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod analyzer;
mod artifact;
mod detect;
mod error;
mod finding;
pub mod hash;
mod report;
pub mod secrets;

pub use analyzer::{AnalysisOptions, Analyzer, AnalyzerOutput, Registry};
pub use artifact::{Artifact, DEFAULT_MAX_SIZE};
pub use detect::{ArtifactKind, detect_bytes, detect_path};
pub use error::{Error, Result};
pub use finding::{Finding, Location, Severity};
pub use report::{ArtifactSummary, Report, Section, SectionBody, ToolInfo};

/// Version of the rex toolkit (shared by all crates in the workspace).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
