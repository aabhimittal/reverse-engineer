//! Optional decompiler bridge: run Ghidra's headless analyzer on the input and return pseudo-C.
//!
//! rex has no decompiler of its own. When Ghidra is installed, `rex decompile` imports the file
//! into a throwaway Ghidra project, lets auto-analysis run, and has a bundled post-script
//! ([`SCRIPT`]) decompile the requested functions to JSON. Nothing is installed or kept: the
//! project lives in a temporary directory that is deleted afterwards.

use rex_core::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The Ghidra post-script that does the decompiling.
pub const SCRIPT: &str = include_str!("RexDecompile.java");

/// Default limit for one `rex decompile` run (JVM start-up and auto-analysis included).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

/// How much of Ghidra's log an error message quotes.
const LOG_TAIL: usize = 2000;

/// One decompiled function.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decompiled {
    /// Ghidra's name for the function.
    pub name: String,
    /// Entry address, in rex's addressing.
    pub entry: u64,
    /// Pseudo-C, when decompilation succeeded.
    pub c: Option<String>,
    /// Why it failed, otherwise.
    pub error: Option<String>,
}

fn headless_name() -> &'static str {
    if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    }
}

/// Find `analyzeHeadless`: `REX_GHIDRA` (the script itself or a Ghidra install directory), then
/// `GHIDRA_INSTALL_DIR`, then `PATH` (via `find`).
pub fn locate(
    env: &dyn Fn(&str) -> Option<String>,
    find: &dyn Fn(&str) -> Option<PathBuf>,
) -> Option<PathBuf> {
    for var in ["REX_GHIDRA", "GHIDRA_INSTALL_DIR"] {
        let Some(v) = env(var).filter(|v| !v.is_empty()) else {
            continue;
        };
        let p = PathBuf::from(v);
        if p.is_file() {
            return Some(p);
        }
        let script = p.join("support").join(headless_name());
        if script.is_file() {
            return Some(script);
        }
    }
    find("analyzeHeadless")
}

/// What to decompile.
pub struct Request<'a> {
    /// `analyzeHeadless` to run.
    pub headless: &'a Path,
    /// Input file name (Ghidra names the program after it).
    pub file_name: &'a str,
    /// Input bytes.
    pub data: &'a [u8],
    /// rex's image base for the file, so the script can map addresses.
    pub image_base: u64,
    /// Function entry addresses; empty means every function (up to the script's cap).
    pub targets: &'a [u64],
    /// Limit for the whole run.
    pub timeout: Duration,
}

/// Run Ghidra and collect its output.
pub fn run(req: &Request) -> Result<Vec<Decompiled>> {
    let io = |what: &str, e: std::io::Error| Error::Other(format!("ghidra: {what}: {e}"));
    let dir = tempfile::tempdir().map_err(|e| io("temporary directory", e))?;
    let input_dir = dir.path().join("input");
    let project = dir.path().join("project");
    for d in [&input_dir, &project] {
        std::fs::create_dir(d).map_err(|e| io("temporary directory", e))?;
    }
    // Ghidra uses the file name as the program name; keep it to safe characters.
    let name: String = req
        .file_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let input = input_dir.join(if name.is_empty() {
        "input".into()
    } else {
        name
    });
    std::fs::write(&input, req.data).map_err(|e| io("write input", e))?;
    std::fs::write(dir.path().join("RexDecompile.java"), SCRIPT)
        .map_err(|e| io("write script", e))?;
    let out = dir.path().join("out.json");
    let log = dir.path().join("ghidra.log");
    let log_file = std::fs::File::create(&log).map_err(|e| io("log", e))?;
    let log_err = log_file.try_clone().map_err(|e| io("log", e))?;

    let per_function = req.timeout.as_secs().clamp(10, 120).to_string();
    let mut cmd = Command::new(req.headless);
    cmd.arg(&project)
        .arg("rex")
        .arg("-import")
        .arg(&input)
        .arg("-scriptPath")
        .arg(dir.path())
        .arg("-postScript")
        .arg("RexDecompile.java")
        .arg(&out)
        .arg(format!("{:x}", req.image_base))
        .arg(per_function);
    if req.targets.is_empty() {
        cmd.arg("all");
    } else {
        cmd.args(req.targets.iter().map(|a| format!("{a:x}")));
    }
    cmd.arg("-deleteProject")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_err));
    let mut child = cmd
        .spawn()
        .map_err(|e| io(&format!("start {}", req.headless.display()), e))?;

    let start = Instant::now();
    let status = loop {
        match child.try_wait().map_err(|e| io("wait", e))? {
            Some(s) => break s,
            None if start.elapsed() >= req.timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::Other(format!(
                    "ghidra: no result after {}s (raise --timeout; large binaries take minutes to analyse)",
                    req.timeout.as_secs()
                )));
            }
            None => std::thread::sleep(Duration::from_millis(100)),
        }
    };
    let tail = || log_tail(&log);
    if !status.success() {
        return Err(Error::Other(format!(
            "ghidra exited with {status}:\n{}",
            tail()
        )));
    }
    let json = std::fs::read_to_string(&out).map_err(|_| {
        Error::Other(format!(
            "ghidra finished but the decompile script wrote no results:\n{}",
            tail()
        ))
    })?;
    serde_json::from_str(&json)
        .map_err(|e| Error::Other(format!("ghidra: unreadable script output: {e}")))
}

/// The end of Ghidra's log, for error messages.
fn log_tail(path: &Path) -> String {
    let text = std::fs::read(path).unwrap_or_default();
    let text = String::from_utf8_lossy(&text);
    let mut start = text.len().saturating_sub(LOG_TAIL);
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text[start..].trim().to_string()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A stand-in `analyzeHeadless`: finds the output path after the script name, records its
    /// arguments, then runs `body`.
    fn stub(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("analyzeHeadless");
        std::fs::write(
            &p,
            format!(
                "#!/bin/sh\necho \"$@\" > \"{}\"\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = RexDecompile.java ]; then out=$2; fi\n  shift\ndone\n{body}\n",
                dir.join("args").display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn req<'a>(headless: &'a Path, targets: &'a [u64], timeout: Duration) -> Request<'a> {
        Request {
            headless,
            file_name: "a b/c.elf",
            data: b"\x7fELF",
            image_base: 0x400000,
            targets,
            timeout,
        }
    }

    #[test]
    fn runs_headless_and_reads_the_results() {
        let d = tempfile::tempdir().unwrap();
        let h = stub(
            d.path(),
            r#"printf '[{"name":"check","entry":4198400,"c":"int check(void)\\n{\\n  return 1;\\n}\\n","error":null}]' > "$out""#,
        );
        let r = run(&req(&h, &[0x401000], Duration::from_secs(30))).unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].entry, 0x401000);
        assert!(r[0].c.as_deref().unwrap().contains("return 1"));
        let args = std::fs::read_to_string(d.path().join("args")).unwrap();
        assert!(
            args.contains("-import") && args.contains("-deleteProject"),
            "{args}"
        );
        // The script gets rex's image base and the address in hex; the input name is sanitised.
        assert!(
            args.contains(" 400000 ") && args.ends_with("401000 -deleteProject\n"),
            "{args}"
        );
        assert!(args.contains("a_b_c.elf"), "{args}");
        let all = run(&req(&h, &[], Duration::from_secs(30)));
        assert!(all.is_ok());
        assert!(
            std::fs::read_to_string(d.path().join("args"))
                .unwrap()
                .contains(" all ")
        );
    }

    #[test]
    fn failures_are_errors_with_ghidras_log() {
        let d = tempfile::tempdir().unwrap();
        let h = stub(d.path(), "echo 'ERROR REPORT: Import failed' >&2; exit 3");
        let e = run(&req(&h, &[1], Duration::from_secs(30))).unwrap_err();
        assert!(e.to_string().contains("Import failed"), "{e}");

        let h = stub(d.path(), "echo analysis done");
        let e = run(&req(&h, &[1], Duration::from_secs(30))).unwrap_err();
        assert!(e.to_string().contains("wrote no results"), "{e}");

        let h = stub(d.path(), r#"echo 'not json' > "$out""#);
        let e = run(&req(&h, &[1], Duration::from_secs(30))).unwrap_err();
        assert!(e.to_string().contains("unreadable"), "{e}");
    }

    #[test]
    fn a_hung_ghidra_is_killed_at_the_timeout() {
        let d = tempfile::tempdir().unwrap();
        let h = stub(d.path(), "exec sleep 30");
        let t = Instant::now();
        let e = run(&req(&h, &[1], Duration::from_secs(1))).unwrap_err();
        assert!(e.to_string().contains("no result after 1s"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn locate_prefers_rex_ghidra_then_the_install_dir_then_path() {
        let d = tempfile::tempdir().unwrap();
        let support = d.path().join("ghidra_12/support");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::write(support.join("analyzeHeadless"), "").unwrap();
        let install = d.path().join("ghidra_12").display().to_string();
        let none = |_: &str| None;
        let env = |k: &str| (k == "GHIDRA_INSTALL_DIR").then(|| install.clone());
        assert_eq!(locate(&env, &none), Some(support.join("analyzeHeadless")));
        let script = support.join("analyzeHeadless").display().to_string();
        let env = |k: &str| (k == "REX_GHIDRA").then(|| script.clone());
        assert_eq!(locate(&env, &none), Some(support.join("analyzeHeadless")));
        let on_path = |n: &str| Some(PathBuf::from(format!("/opt/bin/{n}")));
        assert_eq!(
            locate(&|_| None, &on_path),
            Some(PathBuf::from("/opt/bin/analyzeHeadless"))
        );
        assert_eq!(locate(&|_| Some("/nonexistent".into()), &none), None);
    }
}
