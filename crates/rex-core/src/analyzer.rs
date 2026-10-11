use crate::artifact::Artifact;
use crate::error::Result;
use crate::finding::Finding;
use crate::report::{ArtifactSummary, Report, Section};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

/// Tunables shared by all analyzers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisOptions {
    /// Minimum string length for string extraction.
    pub min_string_len: usize,
    /// Maximum rows to show in large tables (0 = unlimited).
    pub max_rows: usize,
    /// Maximum number of functions to discover in binaries.
    pub max_functions: usize,
    /// Maximum instructions to decode per function.
    pub max_insns_per_function: usize,
    /// Deep mode: enables expensive passes (full disassembly listings, etc.).
    pub deep: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            min_string_len: 5,
            max_rows: 50,
            max_functions: 5000,
            max_insns_per_function: 20_000,
            deep: false,
        }
    }
}

/// What one analyzer contributes.
#[derive(Debug, Default)]
pub struct AnalyzerOutput {
    /// Sections to append to the report.
    pub sections: Vec<Section>,
    /// Findings to merge into the report.
    pub findings: Vec<Finding>,
}

impl AnalyzerOutput {
    /// Empty output.
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a section.
    pub fn section(&mut self, s: Section) -> &mut Self {
        self.sections.push(s);
        self
    }
    /// Append a finding.
    pub fn finding(&mut self, f: Finding) -> &mut Self {
        self.findings.push(f);
        self
    }
    /// Merge another output into this one.
    pub fn extend(&mut self, other: AnalyzerOutput) {
        self.sections.extend(other.sections);
        self.findings.extend(other.findings);
    }
}

/// A pluggable analysis pass.
///
/// Implementors should be *total*: return `Err` for malformed input, never panic.
/// (The [`Registry`] also catches panics as a last line of defence, because
/// analyzers parse attacker-controlled bytes.)
pub trait Analyzer: Send + Sync {
    /// Short unique name, e.g. `binary.checksec`.
    fn name(&self) -> &'static str;
    /// One-line description for `rex analyzers`.
    fn description(&self) -> &'static str;
    /// Whether this analyzer applies to the artifact.
    fn supports(&self, artifact: &Artifact) -> bool;
    /// Display order; lower runs/appears first.
    fn priority(&self) -> i32 {
        100
    }
    /// Run the analysis.
    fn analyze(&self, artifact: &Artifact, opts: &AnalysisOptions) -> Result<AnalyzerOutput>;
}

/// Holds analyzers and runs the applicable ones in parallel.
#[derive(Default)]
pub struct Registry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl Registry {
    /// Empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an analyzer.
    pub fn register(&mut self, a: impl Analyzer + 'static) -> &mut Self {
        self.analyzers.push(Box::new(a));
        self
    }

    /// Register a boxed analyzer.
    pub fn register_boxed(&mut self, a: Box<dyn Analyzer>) -> &mut Self {
        self.analyzers.push(a);
        self
    }

    /// All analyzers.
    pub fn analyzers(&self) -> impl Iterator<Item = &dyn Analyzer> {
        self.analyzers.iter().map(|a| a.as_ref())
    }

    /// Run every applicable analyzer and assemble a report.
    ///
    /// `only` restricts to analyzers whose name starts with one of the given prefixes.
    pub fn run(&self, artifact: &Artifact, opts: &AnalysisOptions, only: &[String]) -> Report {
        let start = Instant::now();
        let mut selected: Vec<&dyn Analyzer> = self
            .analyzers()
            .filter(|a| a.supports(artifact))
            .filter(|a| only.is_empty() || only.iter().any(|p| a.name().starts_with(p.as_str())))
            .collect();
        selected.sort_by_key(|a| (a.priority(), a.name()));

        let results: Vec<(&'static str, Result<AnalyzerOutput, String>)> = selected
            .par_iter()
            .map(|a| {
                let r = catch_unwind(AssertUnwindSafe(|| a.analyze(artifact, opts)));
                let r = match r {
                    Ok(Ok(out)) => Ok(out),
                    Ok(Err(e)) => Err(e.to_string()),
                    Err(p) => Err(format!(
                        "analyzer panicked: {}",
                        p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown".into())
                    )),
                };
                (a.name(), r)
            })
            .collect();

        let mut report = Report::new(
            format!("rex analysis: {}", artifact.name()),
            ArtifactSummary::of(artifact),
        );
        for (name, r) in results {
            match r {
                Ok(out) => {
                    report.sections.extend(out.sections);
                    report.findings.extend(out.findings);
                }
                Err(e) => {
                    tracing::warn!(analyzer = name, error = %e, "analyzer failed");
                    report.errors.push(format!("{name}: {e}"));
                }
            }
        }
        report.sort_findings();
        report.duration_ms = start.elapsed().as_millis() as u64;
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Finding, Severity};

    struct Ok1;
    impl Analyzer for Ok1 {
        fn name(&self) -> &'static str {
            "test.ok"
        }
        fn description(&self) -> &'static str {
            "ok"
        }
        fn supports(&self, _: &Artifact) -> bool {
            true
        }
        fn analyze(&self, _: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
            let mut o = AnalyzerOutput::new();
            o.section(Section::text("t", "T", "hello"));
            o.finding(Finding::new("A", Severity::Low, "x", "low"));
            o.finding(Finding::new("B", Severity::High, "x", "high"));
            Ok(o)
        }
    }

    struct Boom;
    impl Analyzer for Boom {
        fn name(&self) -> &'static str {
            "test.boom"
        }
        fn description(&self) -> &'static str {
            "panics"
        }
        fn supports(&self, _: &Artifact) -> bool {
            true
        }
        fn analyze(&self, _: &Artifact, _: &AnalysisOptions) -> Result<AnalyzerOutput> {
            panic!("kaboom")
        }
    }

    #[test]
    fn runs_and_isolates_panics() {
        let mut r = Registry::new();
        r.register(Ok1).register(Boom);
        let a = Artifact::from_bytes("x", b"hi".to_vec());
        let rep = r.run(&a, &AnalysisOptions::default(), &[]);
        assert_eq!(rep.sections.len(), 1);
        assert_eq!(rep.findings[0].severity, Severity::High);
        assert_eq!(rep.errors.len(), 1);
        assert!(rep.errors[0].contains("kaboom"));
    }

    #[test]
    fn filters_by_prefix() {
        let mut r = Registry::new();
        r.register(Ok1).register(Boom);
        let a = Artifact::from_bytes("x", b"hi".to_vec());
        let rep = r.run(&a, &AnalysisOptions::default(), &["test.ok".into()]);
        assert!(rep.errors.is_empty());
    }
}
