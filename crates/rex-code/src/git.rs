//! Version-control archaeology: churn, ownership and hotspots.
//!
//! Analogy: wear marks on a staircase. Steps that are worn down (files that
//! change constantly) *and* are steep (complex) are where people trip, so
//! that's where bugs cluster. This is Adam Tornhill's "hotspot" idea:
//! churn × complexity.

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;
use std::process::Command;

/// Per-file history.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FileHistory {
    /// Commits touching the file in the window.
    pub commits: usize,
    /// Distinct authors.
    pub authors: BTreeSet<String>,
    /// Commits per author.
    pub by_author: BTreeMap<String, usize>,
}

impl FileHistory {
    /// Share of commits by the top author (0–1).
    pub fn top_author_share(&self) -> f64 {
        let max = self.by_author.values().max().copied().unwrap_or(0);
        if self.commits == 0 {
            0.0
        } else {
            max as f64 / self.commits as f64
        }
    }
}

/// Repository-level history.
#[derive(Debug, Clone, Default, Serialize)]
pub struct History {
    /// Window used (`git log --since`).
    pub since: String,
    /// Commits in window.
    pub commits: usize,
    /// Commits per author in window.
    pub authors: BTreeMap<String, usize>,
    /// Per-file stats (paths relative to repo root as git reports them).
    pub files: HashMap<String, FileHistory>,
    /// Date of first commit.
    pub first_commit: Option<String>,
    /// Date of last commit.
    pub last_commit: Option<String>,
    /// Total commits ever.
    pub total_commits: Option<usize>,
}

impl History {
    /// Minimum number of authors responsible for ≥ 50% of commits ("bus factor").
    pub fn bus_factor(&self) -> usize {
        let mut v: Vec<usize> = self.authors.values().copied().collect();
        v.sort_unstable_by(|a, b| b.cmp(a));
        let total: usize = v.iter().sum();
        let mut acc = 0;
        for (i, n) in v.iter().enumerate() {
            acc += n;
            if acc * 2 >= total {
                return i + 1;
            }
        }
        v.len()
    }
}

fn git(root: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Collect history for `root` (must be inside a git work tree). Returns `None` otherwise.
pub fn history(root: &Path, since: &str) -> Option<History> {
    let top = git(root, &["rev-parse", "--show-toplevel"])?;
    let top = Path::new(top.trim());
    let prefix = root
        .canonicalize()
        .ok()?
        .strip_prefix(top.canonicalize().ok()?)
        .ok()?
        .to_string_lossy()
        .replace('\\', "/");
    let log = git(
        root,
        &[
            "log",
            "--no-merges",
            "--no-renames",
            &format!("--since={since}"),
            "--format=%x00%aN",
            "--name-only",
            "--",
            ".",
        ],
    )?;
    let mut h = History {
        since: since.to_string(),
        ..Default::default()
    };
    let mut author = String::new();
    for line in log.lines() {
        if let Some(a) = line.strip_prefix('\0') {
            author = a.to_string();
            h.commits += 1;
            *h.authors.entry(author.clone()).or_default() += 1;
        } else if !line.is_empty() {
            let rel = if prefix.is_empty() {
                line.to_string()
            } else {
                line.strip_prefix(&format!("{prefix}/"))
                    .unwrap_or(line)
                    .to_string()
            };
            let f = h.files.entry(rel).or_default();
            f.commits += 1;
            f.authors.insert(author.clone());
            *f.by_author.entry(author.clone()).or_default() += 1;
        }
    }
    h.last_commit = git(root, &["log", "-1", "--format=%ad", "--date=short"])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    h.first_commit = git(
        root,
        &[
            "log",
            "--reverse",
            "--format=%ad",
            "--date=short",
            "--max-parents=0",
        ],
    )
    .and_then(|s| s.lines().next().map(str::to_string));
    h.total_commits =
        git(root, &["rev-list", "--count", "HEAD"]).and_then(|s| s.trim().parse().ok());
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_factor() {
        let mut h = History::default();
        h.authors.insert("a".into(), 60);
        h.authors.insert("b".into(), 30);
        h.authors.insert("c".into(), 10);
        assert_eq!(h.bus_factor(), 1);
        h.authors.insert("a".into(), 35); // 35 of 75 < 50%, so two authors are needed
        assert_eq!(h.bus_factor(), 2);
    }

    #[test]
    fn reads_a_real_repo() {
        let d = tempfile::tempdir().unwrap();
        let run = |args: &[&str]| {
            Command::new("git")
                .arg("-C")
                .arg(d.path())
                .args(args)
                .env("GIT_AUTHOR_NAME", "Ada")
                .env("GIT_AUTHOR_EMAIL", "a@x")
                .env("GIT_COMMITTER_NAME", "Ada")
                .env("GIT_COMMITTER_EMAIL", "a@x")
                .output()
                .unwrap()
        };
        if run(&["init", "-q"]).status.code() != Some(0) {
            return; // git unavailable
        }
        std::fs::write(d.path().join("a.txt"), "1").unwrap();
        run(&["add", "."]);
        run(&["-c", "commit.gpgsign=false", "commit", "-qm", "one"]);
        std::fs::write(d.path().join("a.txt"), "2").unwrap();
        run(&["-c", "commit.gpgsign=false", "commit", "-qam", "two"]);
        let h = history(d.path(), "10.years").unwrap();
        assert_eq!(h.commits, 2);
        assert_eq!(h.files["a.txt"].commits, 2);
        assert_eq!(h.bus_factor(), 1);
        assert_eq!(h.total_commits, Some(2));
    }
}
