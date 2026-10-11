//! Generate the Android lab APK (`labs/android/rexlab.apk`) from scratch.
//!
//! The APK is synthetic: a hand-assembled binary manifest and a DEX file with
//! class definitions and method *references* (no bytecode). That is enough
//! for static triage tools, and it's fully reproducible.
//!
//! ```sh
//! cargo run -p rex-web --example make_lab_apk -- labs/android/rexlab.apk
//! ```
use rex_web::axml::builder::{AxmlBuilder, Val};
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "rexlab.apk".into());
    let mut m = AxmlBuilder::new();
    m.start(
        "manifest",
        &[
            ("!package", Val::Str("com.example.rexlab")),
            ("versionCode", Val::Int(12)),
            ("versionName", Val::Str("1.4.0")),
        ],
    )
    .start(
        "uses-sdk",
        &[
            ("minSdkVersion", Val::Int(21)),
            ("targetSdkVersion", Val::Int(30)),
        ],
    )
    .end("uses-sdk");
    for p in [
        "INTERNET",
        "RECEIVE_SMS",
        "READ_SMS",
        "SYSTEM_ALERT_WINDOW",
        "REQUEST_INSTALL_PACKAGES",
        "ACCESS_FINE_LOCATION",
    ] {
        m.start(
            "uses-permission",
            &[("name", Val::Str(&format!("android.permission.{p}")))],
        )
        .end("uses-permission");
    }
    m.start(
        "permission",
        &[
            ("name", Val::Str("com.example.rexlab.permission.SYNC")),
            ("protectionLevel", Val::Str("normal")),
        ],
    )
    .end("permission")
    .start(
        "application",
        &[
            ("name", Val::Str(".RexApp")),
            ("debuggable", Val::Bool(true)),
            ("usesCleartextTraffic", Val::Bool(true)),
        ],
    )
    .start(
        "activity",
        &[
            ("name", Val::Str(".MainActivity")),
            ("exported", Val::Bool(true)),
        ],
    )
    .start("intent-filter", &[])
    .start(
        "action",
        &[("name", Val::Str("android.intent.action.MAIN"))],
    )
    .end("action")
    .end("intent-filter")
    .end("activity")
    .start("activity", &[("name", Val::Str(".DeepLinkActivity"))])
    .start("intent-filter", &[])
    .start(
        "action",
        &[("name", Val::Str("android.intent.action.VIEW"))],
    )
    .end("action")
    .start(
        "data",
        &[("scheme", Val::Str("rexlab")), ("host", Val::Str("pay"))],
    )
    .end("data")
    .end("intent-filter")
    .end("activity")
    .start("receiver", &[("name", Val::Str(".SmsReceiver"))])
    .start("intent-filter", &[])
    .start(
        "action",
        &[("name", Val::Str("android.provider.Telephony.SMS_RECEIVED"))],
    )
    .end("action")
    .end("intent-filter")
    .end("receiver")
    .start(
        "provider",
        &[
            ("name", Val::Str(".ExportProvider")),
            ("exported", Val::Bool(true)),
            ("authorities", Val::Str("com.example.rexlab.export")),
        ],
    )
    .end("provider")
    .end("application")
    .end("manifest");

    let dex = rex_web::dex::builder::build(
        &[
            (
                "Lcom/example/rexlab/RexApp;",
                "Landroid/app/Application;",
                &[],
            ),
            (
                "Lcom/example/rexlab/MainActivity;",
                "Landroid/app/Activity;",
                &[],
            ),
            (
                "Lcom/example/rexlab/DeepLinkActivity;",
                "Landroid/app/Activity;",
                &[],
            ),
            (
                "Lcom/example/rexlab/SmsReceiver;",
                "Landroid/content/BroadcastReceiver;",
                &[],
            ),
            (
                "Lcom/example/rexlab/ExportProvider;",
                "Landroid/content/ContentProvider;",
                &[],
            ),
            (
                "Lcom/example/rexlab/net/a;",
                "Ljava/lang/Object;",
                &["Ljavax/net/ssl/X509TrustManager;"],
            ),
            ("Lcom/example/rexlab/net/b;", "Ljava/lang/Object;", &[]),
        ],
        &[
            ("Landroid/telephony/SmsMessage;", "createFromPdu"),
            ("Ldalvik/system/DexClassLoader;", "<init>"),
            ("Landroid/webkit/WebView;", "addJavascriptInterface"),
            ("Ljava/lang/Runtime;", "exec"),
            ("Landroid/location/LocationManager;", "getLastKnownLocation"),
            ("Ljava/lang/System;", "loadLibrary"),
        ],
        &[
            "http://collector.example.net/api/v2/sms",
            "https://api.example.com/v1/config",
            "/system/xbin/su",
            "su -c id",
        ],
    );

    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default();
    w.start_file("AndroidManifest.xml", opts)?;
    w.write_all(&m.finish())?;
    w.start_file("classes.dex", opts)?;
    w.write_all(&dex)?;
    w.start_file("assets/endpoints.json", opts)?;
    w.write_all(br#"{"api":"https://api.example.com/v1","debug":"http://10.0.2.2:8080"}"#)?;
    w.start_file("res/raw/pinning.bks", opts)?;
    w.write_all(b"not a real keystore")?;
    w.start_file("META-INF/CERT.RSA", opts)?;
    w.write_all(b"(lab placeholder) CN=Android Debug, O=Android, C=US")?;
    std::fs::write(&out, w.finish()?.into_inner())?;
    println!("wrote {out}");
    Ok(())
}
