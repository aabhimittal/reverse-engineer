//! End-to-end tests over the committed lab artefacts in `labs/`.

use rex_core::{AnalysisOptions, Artifact, ArtifactKind, Registry, Severity};
use rex_web::{apk, har, js, openapi, yaml};
use std::path::PathBuf;

fn lab(p: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../labs")
        .join(p)
}

fn run(p: &str) -> rex_core::Report {
    let a = Artifact::from_path(lab(p), rex_core::DEFAULT_MAX_SIZE).unwrap();
    let mut r = Registry::new();
    rex_web::register(&mut r);
    let rep = r.run(&a, &AnalysisOptions::default(), &[]);
    assert!(rep.errors.is_empty(), "{p}: {:?}", rep.errors);
    rep
}

#[test]
fn har_to_openapi() {
    let data = std::fs::read(lab("web/sample.har")).unwrap();
    assert_eq!(rex_core::detect_bytes(&data, None), ArtifactKind::Har);
    let h = har::parse(&data).unwrap();
    let eps = har::extract(&h, &har::ExtractOptions::default());
    let paths: Vec<String> = eps
        .iter()
        .map(|e| format!("{} {}", e.method, e.path))
        .collect();
    for want in [
        "GET /api/v1/products/{productId}",
        "GET /api/v1/orders/{orderId}",
        "GET /api/v1/orders/{orderId}/invoice",
        "POST /api/v1/cart/items",
        "PATCH /api/v1/users/me",
    ] {
        assert!(
            paths.iter().any(|p| p == want),
            "missing {want} in {paths:#?}"
        );
    }
    assert!(
        !paths.iter().any(|p| p.contains("app.4f9c2.js")),
        "static assets skipped"
    );
    assert!(
        !paths.iter().any(|p| p.starts_with("OPTIONS")),
        "preflights skipped"
    );

    let spec = openapi::build(&h, &eps, None);
    assert_eq!(spec["openapi"], "3.1.0");
    let prod = &spec["paths"]["/api/v1/products/{productId}"]["get"];
    assert_eq!(prod["parameters"][0]["schema"]["type"], "integer");
    assert!(prod["responses"]["404"].is_object());
    let schema = &prod["responses"]["200"]["content"]["application/json"]["schema"];
    assert_eq!(
        schema["properties"]["price"]["type"], "number",
        "19.5 and 129 → number"
    );
    assert_eq!(schema["properties"]["created_at"]["format"], "date-time");
    let list = &spec["paths"]["/api/v1/products"]["get"]["parameters"];
    let sort = list
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["name"] == "sort")
        .unwrap();
    assert_eq!(sort["required"], false, "only in one of two calls");
    let body = &spec["paths"]["/api/v1/cart/items"]["post"]["requestBody"]["content"]["application/json"]
        ["schema"];
    let req: Vec<&str> = body["required"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(req, vec!["product_id", "quantity"], "gift is optional");
    let me = &spec["paths"]["/api/v1/users/me"]["get"]["responses"]["200"]["content"]["application/json"]
        ["schema"];
    assert_eq!(me["properties"]["address"]["type"], "null");
    assert_eq!(
        spec["components"]["securitySchemes"]["bearerAuth"]["scheme"],
        "bearer"
    );

    let y = yaml::to_yaml(&spec);
    assert!(y.starts_with("openapi: 3.1.0\n"));
    assert!(y.contains("  /api/v1/products/{productId}:\n"));
}

#[test]
fn har_audit_findings() {
    let r = run("web/sample.har");
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    for id in [
        "WEB-CLEARTEXT",
        "WEB-CAPTURE-CREDENTIALS",
        "WEB-JWT-LONG-LIVED",
        "WEB-VERBOSE-ERRORS",
        "WEB-COOKIE-FLAGS",
        "WEB-PII-IN-URL",
    ] {
        assert!(ids.contains(&id), "missing {id}: {ids:?}");
    }
    let creds = r
        .findings
        .iter()
        .find(|f| f.id == "WEB-CAPTURE-CREDENTIALS")
        .unwrap();
    assert!(
        creds.evidence.iter().all(|e| !e.contains("correct horse")),
        "values must be masked"
    );
}

#[test]
fn js_bundle_and_sourcemap() {
    let r = run("web/bundle/app.min.js");
    assert_eq!(r.findings[0].id, "JS-SECRET");
    let ep = r.section("web.js.endpoints").unwrap();
    let txt = serde_json::to_string(&ep.body).unwrap();
    assert!(txt.contains(r#"["POST","/api/v1/orders","call"]"#), "{txt}");

    let r = run("web/bundle/app.min.js.map");
    assert!(r.findings.iter().any(|f| f.id == "JS-SOURCEMAP-SECRET"));
    let map =
        js::parse_source_map(&std::fs::read(lab("web/bundle/app.min.js.map")).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let (written, missing) = js::unpack(&map, dir.path()).unwrap();
    assert_eq!((written.len(), missing), (3, 0));
    assert!(dir.path().join("src/api/client.ts").exists());
}

#[test]
fn android_lab_apk() {
    let data = std::fs::read(lab("android/rexlab.apk")).unwrap();
    let x = apk::analyze(&data).unwrap();
    assert_eq!(x.manifest.as_ref().unwrap().package, "com.example.rexlab");
    let r = run("android/rexlab.apk");
    let ids: Vec<&str> = r.findings.iter().map(|f| f.id.as_str()).collect();
    for id in [
        "APK-DEBUGGABLE",
        "APK-DEBUG-CERT",
        "APK-EXPORTED",
        "APK-SMS-READ",
        "APK-CUSTOM-TRUST",
        "APK-DYNAMIC-CODE",
        "APK-CLEARTEXT",
    ] {
        assert!(ids.contains(&id), "missing {id}: {ids:?}");
    }
    assert_eq!(r.max_severity(), Some(Severity::High));
    let exported = r.findings.iter().find(|f| f.id == "APK-EXPORTED").unwrap();
    assert!(
        !exported.evidence.iter().any(|e| e.contains("MainActivity")),
        "launcher activity is expected to be exported"
    );
}

#[test]
fn electron_lab_is_detected_and_triaged() {
    let data = std::fs::read(lab("electron/app.asar")).unwrap();
    assert_eq!(rex_core::detect_bytes(&data, None), ArtifactKind::Asar);
    let rep = run("electron/app.asar");
    let ids: Vec<&str> = rep.findings.iter().map(|f| f.id.as_str()).collect();
    for want in [
        "ELECTRON-NODE-INTEGRATION",
        "ELECTRON-NO-CONTEXT-ISOLATION",
        "ELECTRON-SECRETS",
        "ELECTRON-LOADS-HTTP",
        "ELECTRON-OPEN-EXTERNAL",
    ] {
        assert!(ids.contains(&want), "missing {want}: {ids:?}");
    }
    assert_eq!(rep.max_severity(), Some(Severity::High));
    let secret = rep
        .findings
        .iter()
        .find(|f| f.id == "ELECTRON-SECRETS")
        .unwrap();
    assert!(
        secret
            .evidence
            .iter()
            .all(|e| !e.contains("AKIAIOSFODNN7EXAMPLE")),
        "secrets must be masked: {:?}",
        secret.evidence
    );
}

#[test]
fn electron_lab_extracts_into_the_output_directory_only() {
    let a = Artifact::from_path(lab("electron/app.asar"), rex_core::DEFAULT_MAX_SIZE).unwrap();
    let ar = rex_web::asar::parse(a.data()).unwrap();
    let tmp = tempfile::tempdir().unwrap();
    let (written, skipped) = ar.extract(tmp.path()).unwrap();
    assert_eq!((written, skipped), (8, 0));
    let main = std::fs::read_to_string(tmp.path().join("main.js")).unwrap();
    assert!(main.contains("ipcMain.handle(\"notes:read\""));
}
