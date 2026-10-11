use serde::{Deserialize, Serialize};

/// How much a finding matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Purely informational.
    Info,
    /// Minor weakness or noteworthy trait.
    Low,
    /// Worth a closer look.
    Medium,
    /// Likely a real problem.
    High,
    /// Act now.
    Critical,
}

impl Severity {
    /// Lower-case label.
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "info" => Severity::Info,
            "low" => Severity::Low,
            "medium" | "med" => Severity::Medium,
            "high" => Severity::High,
            "critical" | "crit" => Severity::Critical,
            other => return Err(format!("unknown severity '{other}'")),
        })
    }
}

/// Where a finding points.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    /// File (path inside an archive, or source file).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Byte offset into the file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u64>,
    /// Virtual address (binaries).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<u64>,
    /// 1-based line number (text).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

/// A judgement produced by an analyzer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable rule id, e.g. `BIN-NX-DISABLED`. Used as the SARIF rule id.
    pub id: String,
    /// One-line title.
    pub title: String,
    /// Severity.
    pub severity: Severity,
    /// Category, e.g. `mitigation`, `secret`, `capability`, `packer`.
    pub category: String,
    /// Longer explanation (why it matters, what to do).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Concrete evidence strings.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    /// MITRE ATT&CK technique ids, where applicable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attack: Vec<String>,
    /// Where.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
}

impl Finding {
    /// Create a finding with the required fields.
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            severity,
            category: category.into(),
            description: String::new(),
            evidence: Vec::new(),
            attack: Vec::new(),
            location: None,
        }
    }

    /// Builder: description.
    pub fn describe(mut self, d: impl Into<String>) -> Self {
        self.description = d.into();
        self
    }

    /// Builder: add evidence.
    pub fn evidence(mut self, e: impl Into<String>) -> Self {
        self.evidence.push(e.into());
        self
    }

    /// Builder: add many evidence items.
    pub fn evidence_all<I, S>(mut self, items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.evidence.extend(items.into_iter().map(Into::into));
        self
    }

    /// Builder: ATT&CK technique id.
    pub fn attack(mut self, t: impl Into<String>) -> Self {
        self.attack.push(t.into());
        self
    }

    /// Builder: location.
    pub fn at(mut self, loc: Location) -> Self {
        self.location = Some(loc);
        self
    }
}
