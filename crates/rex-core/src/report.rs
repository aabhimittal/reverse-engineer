use crate::detect::ArtifactKind;
use crate::finding::{Finding, Severity};
use serde::{Deserialize, Serialize};

/// Identifies the producing tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolInfo {
    /// Tool name ("rex").
    pub name: String,
    /// Tool version.
    pub version: String,
}

impl Default for ToolInfo {
    fn default() -> Self {
        Self {
            name: "rex".into(),
            version: crate::VERSION.into(),
        }
    }
}

/// Summary of the analysed input.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ArtifactSummary {
    /// File name.
    pub name: String,
    /// Path as given.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Detected kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ArtifactKind>,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

impl ArtifactSummary {
    /// Summarise an [`crate::Artifact`].
    pub fn of(a: &crate::Artifact) -> Self {
        let is_dir = a.kind() == ArtifactKind::Directory;
        Self {
            name: a.name().to_string(),
            path: a.path().map(|p| p.display().to_string()),
            kind: Some(a.kind()),
            size: a.size(),
            sha256: (!is_dir).then(|| a.sha256().to_string()),
        }
    }
}

/// The renderable payload of a section.
///
/// Analyzers describe *what* they found with these primitives; renderers
/// decide *how* it looks in a terminal, Markdown, or HTML. This keeps every
/// domain (binary, web, code) visually consistent for free.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SectionBody {
    /// Ordered key/value pairs.
    KeyValue {
        /// Pairs.
        pairs: Vec<(String, String)>,
    },
    /// A table.
    Table {
        /// Column headers.
        columns: Vec<String>,
        /// Rows (each the same length as `columns`).
        rows: Vec<Vec<String>>,
        /// Number of rows omitted for brevity (0 if none).
        #[serde(default, skip_serializing_if = "is_zero")]
        truncated: usize,
    },
    /// Free text / prose (Markdown allowed).
    Text {
        /// Content.
        text: String,
    },
    /// Preformatted code or listing.
    Code {
        /// Language hint (e.g. `asm`, `yaml`, `xml`).
        lang: String,
        /// Content.
        text: String,
    },
    /// Diagram source.
    Diagram {
        /// `mermaid` or `dot`.
        kind: String,
        /// Diagram source text.
        text: String,
    },
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// A titled block of results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Section {
    /// Stable machine id, e.g. `binary.sections`.
    pub id: String,
    /// Human title.
    pub title: String,
    /// What to render.
    pub body: SectionBody,
    /// Structured data for JSON consumers (may be richer than `body`).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    pub data: serde_json::Value,
}

impl Section {
    /// Key/value section.
    pub fn kv<K: Into<String>, V: Into<String>>(
        id: impl Into<String>,
        title: impl Into<String>,
        pairs: impl IntoIterator<Item = (K, V)>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            body: SectionBody::KeyValue {
                pairs: pairs
                    .into_iter()
                    .map(|(k, v)| (k.into(), v.into()))
                    .collect(),
            },
            data: serde_json::Value::Null,
        }
    }

    /// Table section; rows beyond `limit` are truncated (0 = unlimited).
    pub fn table(
        id: impl Into<String>,
        title: impl Into<String>,
        columns: &[&str],
        mut rows: Vec<Vec<String>>,
        limit: usize,
    ) -> Self {
        let mut truncated = 0;
        if limit > 0 && rows.len() > limit {
            truncated = rows.len() - limit;
            rows.truncate(limit);
        }
        Self {
            id: id.into(),
            title: title.into(),
            body: SectionBody::Table {
                columns: columns.iter().map(|c| c.to_string()).collect(),
                rows,
                truncated,
            },
            data: serde_json::Value::Null,
        }
    }

    /// Text section.
    pub fn text(id: impl Into<String>, title: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            body: SectionBody::Text { text: text.into() },
            data: serde_json::Value::Null,
        }
    }

    /// Code section.
    pub fn code(
        id: impl Into<String>,
        title: impl Into<String>,
        lang: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            body: SectionBody::Code {
                lang: lang.into(),
                text: text.into(),
            },
            data: serde_json::Value::Null,
        }
    }

    /// Diagram section.
    pub fn diagram(
        id: impl Into<String>,
        title: impl Into<String>,
        kind: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            body: SectionBody::Diagram {
                kind: kind.into(),
                text: text.into(),
            },
            data: serde_json::Value::Null,
        }
    }

    /// Attach structured data.
    pub fn with_data(mut self, data: impl Serialize) -> Self {
        self.data = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
        self
    }
}

/// The complete result of running rex on one input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    /// Report schema version (bumped on breaking JSON changes).
    pub schema_version: u32,
    /// Producing tool.
    pub tool: ToolInfo,
    /// Report title.
    pub title: String,
    /// Input summary.
    pub artifact: ArtifactSummary,
    /// Sections in display order.
    pub sections: Vec<Section>,
    /// Findings, most severe first.
    pub findings: Vec<Finding>,
    /// Non-fatal errors from analyzers.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    /// Wall-clock time in milliseconds.
    pub duration_ms: u64,
}

impl Report {
    /// JSON schema version.
    pub const SCHEMA_VERSION: u32 = 1;

    /// New empty report.
    pub fn new(title: impl Into<String>, artifact: ArtifactSummary) -> Self {
        Self {
            schema_version: Self::SCHEMA_VERSION,
            tool: ToolInfo::default(),
            title: title.into(),
            artifact,
            sections: Vec::new(),
            findings: Vec::new(),
            errors: Vec::new(),
            duration_ms: 0,
        }
    }

    /// Append a section.
    pub fn push(&mut self, s: Section) -> &mut Self {
        self.sections.push(s);
        self
    }

    /// Sort findings by severity (desc), then id.
    pub fn sort_findings(&mut self) {
        self.findings
            .sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    }

    /// Highest severity among findings.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Count of findings per severity, most severe first.
    pub fn severity_counts(&self) -> Vec<(Severity, usize)> {
        [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ]
        .into_iter()
        .map(|s| (s, self.findings.iter().filter(|f| f.severity == s).count()))
        .collect()
    }

    /// Find a section by id.
    pub fn section(&self, id: &str) -> Option<&Section> {
        self.sections.iter().find(|s| s.id == id)
    }
}
