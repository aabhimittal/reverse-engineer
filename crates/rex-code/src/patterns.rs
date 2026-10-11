//! Line-level pattern scans: HTTP routes, entry points, technology stack and security smells.
//!
//! These are deliberately regex-based. Routes and smells are framework
//! idioms that read the same in every codebase, and regexes keep the scan
//! fast across dozens of languages, including ones without a parser.

use crate::lang::Lang;
use crate::project::Project;
use regex::Regex;
use rex_core::Severity;
use serde::Serialize;
use std::collections::BTreeSet;
use std::sync::OnceLock;

/// An HTTP route.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Route {
    /// Method (`GET`, `ANY`, …).
    pub method: String,
    /// Path.
    pub path: String,
    /// Framework idiom that matched.
    pub framework: &'static str,
    /// `file:line`.
    pub at: String,
}

/// An entry point.
#[derive(Debug, Clone, Serialize)]
pub struct EntryPoint {
    /// Kind (`main`, `cli`, `serverless`, `container`, `script`).
    pub kind: &'static str,
    /// Description.
    pub what: String,
    /// `file:line`.
    pub at: String,
}

/// A security smell.
#[derive(Debug, Clone, Serialize)]
pub struct Smell {
    /// Rule id.
    pub id: &'static str,
    /// Title.
    pub title: &'static str,
    /// Severity.
    pub severity: Severity,
    /// File.
    pub file: String,
    /// Line.
    pub line: u32,
    /// Offending line (trimmed).
    pub snippet: String,
}

type RouteRule = (&'static str, Regex, Option<usize>, usize);

fn route_rules() -> &'static Vec<RouteRule> {
    static R: OnceLock<Vec<RouteRule>> = OnceLock::new();
    // (framework, regex, method group, path group)
    R.get_or_init(|| {
        vec![
            ("express/koa/fastify", Regex::new(r#"\b(?:app|router|server|fastify|api|routes)\.(get|post|put|patch|delete|all)\(\s*["'`]([^"'`]+)["'`]"#).unwrap(), Some(1), 2),
            ("flask/fastapi", Regex::new(r#"@\w+(?:\.\w+)?\.(route|get|post|put|patch|delete|api_route)\(\s*["']([^"']+)["']"#).unwrap(), Some(1), 2),
            ("django", Regex::new(r#"\b(?:re_)?path\(\s*r?["']([^"']*)["']\s*,"#).unwrap(), None, 1),
            ("spring", Regex::new(r#"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\{?\s*"([^"]*)""#).unwrap(), Some(1), 2),
            ("go net/http, gin, echo, chi", Regex::new(r#"\.(GET|POST|PUT|PATCH|DELETE|Get|Post|Put|Patch|Delete|HandleFunc|Handle)\(\s*"(/[^"]*)""#).unwrap(), Some(1), 2),
            ("axum", Regex::new(r#"\.route\(\s*"([^"]+)"\s*,\s*(get|post|put|patch|delete|any)"#).unwrap(), Some(2), 1),
            ("actix/rocket", Regex::new(r#"#\[(get|post|put|patch|delete)\(\s*"([^"]+)""#).unwrap(), Some(1), 2),
            ("rails", Regex::new(r#"^\s*(get|post|put|patch|delete)\s+['"]([^'"]+)['"]"#).unwrap(), Some(1), 2),
            ("laravel", Regex::new(r#"Route::(get|post|put|patch|delete|any)\(\s*['"]([^'"]+)['"]"#).unwrap(), Some(1), 2),
            ("nestjs", Regex::new(r#"@(Get|Post|Put|Patch|Delete)\(\s*['"]([^'"]*)['"]"#).unwrap(), Some(1), 2),
            ("aspnet", Regex::new(r#"\[(?:Http)(Get|Post|Put|Patch|Delete)\(\s*"([^"]*)""#).unwrap(), Some(1), 2),
        ]
    })
}

/// Find HTTP routes in the project.
pub fn routes(p: &Project) -> Vec<Route> {
    let mut out = BTreeSet::new();
    for f in &p.files {
        if !f.lang.is_code() || f.generated || f.test {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(p.root.join(&f.path)) else {
            continue;
        };
        for (ln, line) in src.lines().enumerate() {
            if line.len() > 400 || f.is_test_line(ln as u32 + 1) || line.contains("Regex::new(") {
                continue;
            }
            for (fw, re, mg, pg) in route_rules() {
                if *fw == "rails" && !f.path.ends_with("routes.rb") {
                    continue;
                }
                if *fw == "django" && !f.path.ends_with("urls.py") {
                    continue;
                }
                if let Some(c) = re.captures(line) {
                    let method =
                        mg.and_then(|g| c.get(g))
                            .map(|m| m.as_str().to_ascii_uppercase())
                            .map(|m| match m.as_str() {
                                "ROUTE" | "API_ROUTE" | "ALL" | "HANDLE" | "HANDLEFUNC"
                                | "REQUEST" => "ANY".to_string(),
                                _ => m,
                            })
                            .unwrap_or_else(|| "ANY".into());
                    let path = c.get(*pg).map(|m| m.as_str()).unwrap_or("").to_string();
                    let path = if *fw == "django" && !path.starts_with('/') {
                        format!("/{path}")
                    } else {
                        path
                    };
                    out.insert(Route {
                        method,
                        path,
                        framework: fw,
                        at: format!("{}:{}", f.path, ln + 1),
                    });
                }
            }
        }
    }
    out.into_iter().collect()
}

/// Find program entry points.
pub fn entry_points(p: &Project) -> Vec<EntryPoint> {
    let mut out = Vec::new();
    for f in &p.files {
        if f.test || f.generated {
            continue;
        }
        if let Some(sx) = &f.syntax {
            for d in &sx.defs {
                let at = format!("{}:{}", f.path, d.line);
                let is_main = match f.lang {
                    Lang::Rust | Lang::Go | Lang::Java => {
                        d.name == "main" && d.container.is_none()
                            || (f.lang == Lang::Java && d.name == "main")
                    }
                    _ => false,
                };
                if is_main {
                    out.push(EntryPoint {
                        kind: "main",
                        what: format!("{} main()", f.lang.name()),
                        at,
                    });
                } else if matches!(d.name.as_str(), "lambda_handler" | "handler")
                    && matches!(f.lang, Lang::Python | Lang::JavaScript | Lang::TypeScript)
                    && d.container.is_none()
                {
                    out.push(EntryPoint {
                        kind: "serverless",
                        what: format!("{} (likely cloud function)", d.name),
                        at,
                    });
                }
            }
        }
        let interesting = matches!(
            f.lang,
            Lang::Python
                | Lang::Dockerfile
                | Lang::Json
                | Lang::Toml
                | Lang::JavaScript
                | Lang::TypeScript
                | Lang::Rust
                | Lang::Go
        );
        if !interesting {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(p.root.join(&f.path)) else {
            continue;
        };
        for (ln, line) in src.lines().enumerate() {
            let at = format!("{}:{}", f.path, ln + 1);
            let t = line.trim();
            match f.lang {
                Lang::Python if t.starts_with("if __name__") && t.contains("__main__") => {
                    out.push(EntryPoint {
                        kind: "script",
                        what: "python __main__ block".into(),
                        at,
                    })
                }
                Lang::Python
                    if t.contains("argparse.ArgumentParser(")
                        || t.starts_with("@click.command")
                        || t.starts_with("@app.command") =>
                {
                    out.push(EntryPoint {
                        kind: "cli",
                        what: "command-line parser".into(),
                        at,
                    })
                }
                Lang::Dockerfile if t.starts_with("ENTRYPOINT") || t.starts_with("CMD") => out
                    .push(EntryPoint {
                        kind: "container",
                        what: t.to_string(),
                        at,
                    }),
                Lang::Rust
                    if (t.starts_with("#[derive(") && t.contains("Parser"))
                        || t.starts_with("#[tokio::main]") =>
                {
                    out.push(EntryPoint {
                        kind: if t.contains("Parser") { "cli" } else { "main" },
                        what: t.to_string(),
                        at,
                    })
                }
                Lang::Go if t.contains("&cobra.Command{") => out.push(EntryPoint {
                    kind: "cli",
                    what: "cobra command".into(),
                    at,
                }),
                Lang::Json
                    if f.path.ends_with("package.json")
                        && (t.starts_with("\"main\"")
                            || t.starts_with("\"bin\"")
                            || t.starts_with("\"start\"")) =>
                {
                    out.push(EntryPoint {
                        kind: "script",
                        what: t.trim_end_matches(',').to_string(),
                        at,
                    })
                }
                Lang::Toml
                    if (f.path.ends_with("pyproject.toml")
                        && t.contains("= \"")
                        && t.contains(':'))
                        || t == "[[bin]]" =>
                {
                    out.push(EntryPoint {
                        kind: "cli",
                        what: t.to_string(),
                        at,
                    })
                }
                _ => {}
            }
        }
    }
    out
}

/// Detect technologies from manifests and infrastructure files.
pub fn stack(p: &Project) -> Vec<(String, String)> {
    let mut out: BTreeSet<(String, String)> = BTreeSet::new();
    let has = |suffix: &str| {
        p.files
            .iter()
            .any(|f| f.path == suffix || f.path.ends_with(&format!("/{suffix}")))
    };
    const KNOWN: &[(&str, &str, &str)] = &[
        // (manifest, dependency needle, technology)
        ("package.json", "\"react\"", "React"),
        ("package.json", "\"next\"", "Next.js"),
        ("package.json", "\"vue\"", "Vue"),
        ("package.json", "\"@angular/core\"", "Angular"),
        ("package.json", "\"svelte\"", "Svelte"),
        ("package.json", "\"express\"", "Express"),
        ("package.json", "\"@nestjs/core\"", "NestJS"),
        ("package.json", "\"fastify\"", "Fastify"),
        ("package.json", "\"electron\"", "Electron"),
        ("package.json", "\"react-native\"", "React Native"),
        ("package.json", "\"prisma\"", "Prisma"),
        ("package.json", "\"mongoose\"", "MongoDB (Mongoose)"),
        ("package.json", "\"typeorm\"", "TypeORM"),
        ("package.json", "\"graphql\"", "GraphQL"),
        ("package.json", "\"jest\"", "Jest"),
        ("package.json", "\"vitest\"", "Vitest"),
        ("package.json", "\"vite\"", "Vite"),
        ("package.json", "\"webpack\"", "webpack"),
        ("Cargo.toml", "tokio", "Tokio"),
        ("Cargo.toml", "axum", "axum"),
        ("Cargo.toml", "actix-web", "Actix Web"),
        ("Cargo.toml", "rocket", "Rocket"),
        ("Cargo.toml", "clap", "clap (CLI)"),
        ("Cargo.toml", "serde", "serde"),
        ("Cargo.toml", "sqlx", "SQLx"),
        ("Cargo.toml", "diesel", "Diesel"),
        ("Cargo.toml", "tauri", "Tauri"),
        ("Cargo.toml", "tree-sitter", "tree-sitter"),
        ("requirements.txt", "django", "Django"),
        ("requirements.txt", "flask", "Flask"),
        ("requirements.txt", "fastapi", "FastAPI"),
        ("requirements.txt", "sqlalchemy", "SQLAlchemy"),
        ("requirements.txt", "celery", "Celery"),
        ("requirements.txt", "torch", "PyTorch"),
        ("requirements.txt", "tensorflow", "TensorFlow"),
        ("requirements.txt", "pandas", "pandas"),
        ("requirements.txt", "pytest", "pytest"),
        ("pyproject.toml", "django", "Django"),
        ("pyproject.toml", "flask", "Flask"),
        ("pyproject.toml", "fastapi", "FastAPI"),
        ("pyproject.toml", "torch", "PyTorch"),
        ("pyproject.toml", "pytest", "pytest"),
        ("go.mod", "gin-gonic/gin", "Gin"),
        ("go.mod", "labstack/echo", "Echo"),
        ("go.mod", "gofiber/fiber", "Fiber"),
        ("go.mod", "spf13/cobra", "Cobra (CLI)"),
        ("go.mod", "gorm.io", "GORM"),
        ("go.mod", "google.golang.org/grpc", "gRPC"),
        ("pom.xml", "spring-boot", "Spring Boot"),
        ("pom.xml", "hibernate", "Hibernate"),
        ("build.gradle", "spring-boot", "Spring Boot"),
        ("build.gradle", "com.android", "Android"),
        ("build.gradle.kts", "spring-boot", "Spring Boot"),
        ("build.gradle.kts", "com.android", "Android"),
        ("Gemfile", "rails", "Ruby on Rails"),
        ("composer.json", "laravel", "Laravel"),
    ];
    for f in &p.files {
        let name = f.path.rsplit('/').next().unwrap_or(&f.path);
        let relevant: Vec<&(&str, &str, &str)> =
            KNOWN.iter().filter(|(m, _, _)| *m == name).collect();
        if relevant.is_empty() {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(p.root.join(&f.path)) else {
            continue;
        };
        let lower = src.to_ascii_lowercase();
        out.insert(("manifest".into(), f.path.clone()));
        for (_, needle, tech) in relevant {
            if lower.contains(&needle.to_ascii_lowercase()) {
                out.insert(("framework".into(), tech.to_string()));
            }
        }
    }
    for (path, tech) in [
        ("Dockerfile", "Docker"),
        ("docker-compose.yml", "Docker Compose"),
        ("docker-compose.yaml", "Docker Compose"),
        ("compose.yaml", "Docker Compose"),
        ("Chart.yaml", "Helm"),
        ("serverless.yml", "Serverless Framework"),
        ("template.yaml", "AWS SAM"),
        (".gitlab-ci.yml", "GitLab CI"),
        ("Jenkinsfile", "Jenkins"),
        ("vercel.json", "Vercel"),
        ("netlify.toml", "Netlify"),
    ] {
        if has(path) {
            out.insert(("infrastructure".into(), tech.into()));
        }
    }
    if p.files.iter().any(|f| f.lang == Lang::Hcl) {
        out.insert(("infrastructure".into(), "Terraform".into()));
    }
    if p.root.join(".github/workflows").is_dir() {
        out.insert(("infrastructure".into(), "GitHub Actions".into()));
    }
    if p.files.iter().any(|f| {
        f.lang == Lang::Yaml
            && (f.path.contains("k8s")
                || f.path.contains("kubernetes")
                || f.path.contains("manifests/"))
    }) {
        out.insert(("infrastructure".into(), "Kubernetes".into()));
    }
    out.into_iter().collect()
}

type SmellRule = (&'static str, &'static str, Severity, &'static [Lang], Regex);

fn smell_rules() -> &'static Vec<SmellRule> {
    use Lang::*;
    static R: OnceLock<Vec<SmellRule>> = OnceLock::new();
    R.get_or_init(|| {
        vec![
            ("CODE-SHELL-INJECTION", "subprocess with shell=True", Severity::Medium, &[Python], Regex::new(r"subprocess\.\w+\([^)]*shell\s*=\s*True").unwrap()),
            ("CODE-OS-SYSTEM", "os.system / os.popen", Severity::Low, &[Python], Regex::new(r"\bos\.(system|popen)\(").unwrap()),
            ("CODE-EVAL", "eval/exec on dynamic input", Severity::Medium, &[Python, JavaScript, TypeScript, Tsx, Ruby, Php], Regex::new(r"(?:^|[^\w.])(?:eval|exec)\s*\(\s*[A-Za-z_]").unwrap()),
            ("CODE-PICKLE", "unsafe deserialisation (pickle / yaml.load / Marshal)", Severity::Medium, &[Python, Ruby], Regex::new(r"\b(?:pickle\.loads?|cPickle\.loads?|yaml\.load\(|Marshal\.load)").unwrap()),
            ("CODE-TLS-VERIFY-OFF", "TLS certificate verification disabled", Severity::High, &[Python, Go, JavaScript, TypeScript, Java, Kotlin, Rust, CSharp],
                Regex::new(r"verify\s*=\s*False|InsecureSkipVerify:\s*true|rejectUnauthorized:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|danger_accept_invalid_certs\(true\)|ALLOW_ALL_HOSTNAME_VERIFIER|ServerCertificateValidationCallback\s*=").unwrap()),
            ("CODE-SQL-CONCAT", "SQL built with string formatting", Severity::Medium, &[Python, Go, JavaScript, TypeScript, Java, Php, CSharp],
                Regex::new(r#"(?i)(?:execute|query|exec|raw|prepare)\w*\(\s*(?:f["']|["'](?:select|insert|update|delete)\b[^"']*["']\s*(?:\+|%|\.format)|fmt\.Sprintf\(\s*"(?:select|insert|update|delete)\b)"#).unwrap()),
            ("CODE-CHILD-PROCESS", "child_process.exec with dynamic command", Severity::Medium, &[JavaScript, TypeScript], Regex::new(r"\bexec(?:Sync)?\(\s*(?:`[^`]*\$\{|[A-Za-z_][\w.]*\s*\+)").unwrap()),
            ("CODE-DOM-XSS", "raw HTML injection sink", Severity::Low, &[JavaScript, TypeScript, Tsx, Vue, Svelte], Regex::new(r"\.innerHTML\s*=|dangerouslySetInnerHTML|v-html=|\{@html").unwrap()),
            ("CODE-GO-SHELL", "exec.Command via shell", Severity::Medium, &[Go], Regex::new(r#"exec\.Command\(\s*"(?:sh|bash|cmd)"\s*,\s*"(?:-c|/c)""#).unwrap()),
            ("CODE-JAVA-EXEC", "Runtime.exec", Severity::Low, &[Java, Kotlin], Regex::new(r"Runtime\.getRuntime\(\)\.exec\(").unwrap()),
            ("CODE-WEAK-HASH", "MD5/SHA-1 used (check it isn't for passwords or signatures)", Severity::Info, &[Python, Go, JavaScript, TypeScript, Java, Php, Rust, CSharp],
                Regex::new(r#"\b(?:hashlib\.(?:md5|sha1)|md5\.New|sha1\.New|createHash\(\s*['"](?:md5|sha1)|MessageDigest\.getInstance\(\s*"(?:MD5|SHA-?1)"|md5\(|Md5::new|Sha1::new)"#).unwrap()),
            ("CODE-RUST-UNSAFE", "unsafe block", Severity::Info, &[Rust], Regex::new(r"\bunsafe\s*\{").unwrap()),
            ("CODE-DEBUG-ON", "debug mode enabled in config", Severity::Low, &[Python, JavaScript, TypeScript], Regex::new(r"(?:^|\s)DEBUG\s*=\s*True\b|app\.run\([^)]*debug\s*=\s*True").unwrap()),
            ("CODE-CORS-ANY", "CORS allows any origin", Severity::Low, &[Python, JavaScript, TypeScript, Go, Java], Regex::new(r#"Access-Control-Allow-Origin["']?\s*[,:]\s*["']\*|origins?\s*[:=]\s*["']\*["']|AllowAllOrigins:\s*true|CORS_ORIGIN_ALLOW_ALL\s*=\s*True"#).unwrap()),
        ]
    })
}

/// Scan for security smells and hard-coded secrets.
pub fn smells(p: &Project) -> (Vec<Smell>, Vec<(String, rex_core::secrets::SecretHit)>) {
    let mut out = Vec::new();
    let mut secrets = Vec::new();
    for f in &p.files {
        if f.generated || f.bytes > crate::project::MAX_PARSE_BYTES {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(p.root.join(&f.path)) else {
            continue;
        };
        if !f.test && f.lang != Lang::Markdown {
            for h in rex_core::secrets::scan(&src) {
                if !f.is_test_line(h.line) {
                    secrets.push((f.path.clone(), h));
                }
            }
        }
        if f.test || !f.lang.is_code() {
            continue;
        }
        let rules: Vec<&SmellRule> = smell_rules()
            .iter()
            .filter(|r| r.3.contains(&f.lang))
            .collect();
        if rules.is_empty() {
            continue;
        }
        for (ln, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("//")
                || t.starts_with('#')
                || t.starts_with('*')
                || line.len() > 500
                || f.is_test_line(ln as u32 + 1)
            {
                continue;
            }
            // Lines that *define* detection patterns aren't uses of the pattern.
            if [
                "Regex::new(",
                "re.compile(",
                "new RegExp(",
                "Pattern.compile(",
                "regexp.MustCompile(",
            ]
            .iter()
            .any(|r| line.contains(r))
            {
                continue;
            }
            for (id, title, sev, _, re) in &rules {
                if re.is_match(line) {
                    if *id == "CODE-PICKLE"
                        && (line.contains("SafeLoader") || line.contains("CSafeLoader"))
                    {
                        continue;
                    }
                    out.push(Smell {
                        id,
                        title,
                        severity: *sev,
                        file: f.path.clone(),
                        line: ln as u32 + 1,
                        snippet: line.trim().chars().take(160).collect(),
                    });
                }
            }
        }
    }
    (out, secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn project(files: &[(&str, &str)]) -> (tempfile::TempDir, Project) {
        let d = tempfile::tempdir().unwrap();
        for (p, c) in files {
            let path = d.path().join(p);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, c).unwrap();
        }
        let p = crate::project::scan(d.path(), 1000);
        (d, p)
    }

    #[test]
    fn finds_routes_entries_stack_smells() {
        let (_d, p) = project(&[
            (
                "server.js",
                "const app = express();\napp.get('/api/users/:id', h);\nrouter.post(\"/login\", h);\n",
            ),
            (
                "api/views.py",
                "@app.route('/health')\ndef health():\n    return 'ok'\n\n@router.get(\"/items/{id}\")\nasync def item(id):\n    subprocess.run(cmd, shell=True)\n    requests.get(u, verify=False)\n\nif __name__ == '__main__':\n    main()\n",
            ),
            (
                "main.go",
                "package main\nfunc main() {\n  http.HandleFunc(\"/metrics\", m)\n  r.GET(\"/v1/ping\", p)\n  db.Query(fmt.Sprintf(\"SELECT * FROM t WHERE id=%s\", id))\n}\n",
            ),
            (
                "src/main.rs",
                "fn main() {\n    let app = Router::new().route(\"/hello\", get(hello));\n    unsafe { x() }\n}\n",
            ),
            (
                "package.json",
                "{\n  \"main\": \"server.js\",\n  \"dependencies\": { \"express\": \"^4\", \"react\": \"^18\" }\n}\n",
            ),
            (
                "Dockerfile",
                "FROM node:20\nCMD [\"node\", \"server.js\"]\n",
            ),
            (
                "config.py",
                "client_secret = \"Zq8r3TfL0pWm2xYb7Nc4Vd9K\"\n",
            ),
        ]);
        let r = routes(&p);
        let rs: Vec<String> = r
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect();
        for want in [
            "GET /api/users/:id",
            "POST /login",
            "ANY /health",
            "GET /items/{id}",
            "ANY /metrics",
            "GET /v1/ping",
            "GET /hello",
        ] {
            assert!(rs.contains(&want.to_string()), "missing {want}: {rs:?}");
        }
        let e = entry_points(&p);
        let kinds: Vec<&str> = e.iter().map(|e| e.kind).collect();
        assert!(
            kinds.contains(&"main") && kinds.contains(&"script") && kinds.contains(&"container"),
            "{e:?}"
        );
        let st = stack(&p);
        assert!(st.contains(&("framework".into(), "Express".into())));
        assert!(st.contains(&("framework".into(), "React".into())));
        assert!(st.contains(&("infrastructure".into(), "Docker".into())));
        let (sm, secrets) = smells(&p);
        let ids: Vec<&str> = sm.iter().map(|s| s.id).collect();
        for id in [
            "CODE-SHELL-INJECTION",
            "CODE-TLS-VERIFY-OFF",
            "CODE-SQL-CONCAT",
            "CODE-RUST-UNSAFE",
        ] {
            assert!(ids.contains(&id), "missing {id}: {ids:?}");
        }
        assert!(secrets.iter().any(|(f, h)| f == "config.py" && h.high));
    }
}
