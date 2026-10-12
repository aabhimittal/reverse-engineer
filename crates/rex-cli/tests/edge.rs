//! Hostile and odd inputs, end to end. Each one must finish quickly with a report or a clean
//! error message, never a panic, hang or runaway memory use.

use assert_cmd::Command;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../rex-binary/tests/fixtures")
        .join(name);
    std::fs::read(p).unwrap()
}

/// Run rex and return (exit code, stdout, stderr), failing on panics, crashes and timeouts.
fn run(args: &[&str], path: &Path) -> (i32, String, String) {
    let out = Command::cargo_bin("rex")
        .unwrap()
        .env("NO_COLOR", "1")
        .args(args)
        .arg(path)
        .timeout(Duration::from_secs(60))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let code = out.status.code().unwrap_or_else(|| {
        panic!(
            "rex {args:?} {} was killed (timeout or signal): {stderr}",
            path.display()
        )
    });
    assert!(
        !stderr.contains("panicked") && !stderr.contains("stack overflow"),
        "rex {args:?} {} panicked:\n{stderr}",
        path.display()
    );
    assert!(
        matches!(code, 0 | 1 | 3),
        "rex {args:?} {}: unexpected exit {code}\n{stderr}",
        path.display()
    );
    (
        code,
        String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr,
    )
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

fn uleb(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let b = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

/// Every hand-made hostile input, by file name.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut v: Vec<(&'static str, Vec<u8>)> = vec![("empty", vec![]), ("one-byte", vec![0x7f])];

    // ELF whose program and section header tables point far past the end of the file.
    let mut elf = fixture("crackme.elf");
    elf[0x20..0x28].copy_from_slice(&0xffff_ffff_0000u64.to_le_bytes()); // e_phoff
    elf[0x28..0x30].copy_from_slice(&0xffff_ffff_0000u64.to_le_bytes()); // e_shoff
    elf[0x38..0x3a].copy_from_slice(&0xffffu16.to_le_bytes()); // e_phnum
    elf[0x3c..0x3e].copy_from_slice(&0xffffu16.to_le_bytes()); // e_shnum
    v.push(("elf-offsets-past-eof", elf));
    // ELF whose section-name string table index is out of range, and one that is only a header.
    let mut elf = fixture("crackme.elf");
    elf[0x3e..0x40].copy_from_slice(&0xfff0u16.to_le_bytes());
    v.push(("elf-bad-shstrndx", elf.clone()));
    v.push(("elf-header-only", elf[..64].to_vec()));
    // ELF claiming to be AArch64 while holding x86 code.
    let mut elf = fixture("crackme.elf");
    elf[0x12..0x14].copy_from_slice(&183u16.to_le_bytes());
    v.push(("elf-wrong-machine", elf));
    // Every section's offset and size inflated so they overlap and run past EOF.
    let mut elf = fixture("crackme.elf");
    let shoff = u64::from_le_bytes(elf[0x28..0x30].try_into().unwrap()) as usize;
    let shnum = u16::from_le_bytes(elf[0x3c..0x3e].try_into().unwrap()) as usize;
    for i in 0..shnum {
        let sh = shoff + i * 64;
        if sh + 64 <= elf.len() {
            elf[sh + 0x18..sh + 0x20].copy_from_slice(&(i as u64 * 7).to_le_bytes());
            elf[sh + 0x20..sh + 0x28].copy_from_slice(&0x7fff_ffff_ffffu64.to_le_bytes());
        }
    }
    v.push(("elf-sections-overlap-and-overrun", elf));

    // PE whose e_lfanew points past EOF, and one claiming 65535 sections.
    let mut pe = fixture("sample.exe");
    pe[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
    v.push(("pe-lfanew-past-eof", pe));
    let mut pe = fixture("sample.exe");
    let lfanew = u32::from_le_bytes(pe[0x3c..0x40].try_into().unwrap()) as usize;
    pe[lfanew + 6..lfanew + 8].copy_from_slice(&0xffffu16.to_le_bytes());
    v.push(("pe-65535-sections", pe));
    // PE whose import directory points at itself.
    let mut pe = fixture("sample.exe");
    let opt = lfanew + 24;
    let dd = opt
        + if pe[opt] == 0x0b && pe[opt + 1] == 0x02 {
            112
        } else {
            96
        };
    let rva = u32::from_le_bytes(pe[dd + 8..dd + 12].try_into().unwrap());
    pe[dd + 8..dd + 12].copy_from_slice(&rva.to_le_bytes());
    pe[dd + 12..dd + 16].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    v.push(("pe-import-dir-huge", pe));

    // Mach-O universal headers with 0 and 1000 slices but no slice data.
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe];
    fat.extend_from_slice(&1000u32.to_be_bytes());
    v.push(("macho-fat-1000-slices", fat));
    let mut fat = vec![0xca, 0xfe, 0xba, 0xbe];
    fat.extend_from_slice(&0u32.to_be_bytes());
    v.push(("macho-fat-0-slices", fat));
    let mut mo = fixture("hello.macho");
    mo[0x10..0x14].copy_from_slice(&0xffff_ffffu32.to_le_bytes()); // ncmds
    v.push(("macho-ncmds-max", mo));

    // WebAssembly claiming 2^32-1 functions, and a code body larger than the file.
    let mut w = b"\0asm\x01\0\0\0".to_vec();
    w.push(3);
    let mut payload = Vec::new();
    uleb(0xffff_ffff, &mut payload);
    uleb(payload.len() as u64, &mut w);
    w.extend(payload);
    v.push(("wasm-huge-function-count.wasm", w));
    let mut w = b"\0asm\x01\0\0\0".to_vec();
    w.extend([10, 6, 1]);
    uleb(0x7fff_ffff, &mut w);
    w.extend([0, 0x0b]);
    v.push(("wasm-body-past-eof.wasm", w));

    // ASAR with a 10,000-level directory tree in its header JSON.
    let mut json = String::new();
    for _ in 0..10_000 {
        json.push_str(r#"{"files":{"d":"#);
    }
    json.push_str("{}");
    for _ in 0..10_000 {
        json.push_str("}}");
    }
    let mut asar = Vec::new();
    let l = json.len() as u32;
    let padded = (l + 3) & !3;
    asar.extend_from_slice(&4u32.to_le_bytes());
    asar.extend_from_slice(&(padded + 8).to_le_bytes());
    asar.extend_from_slice(&(padded + 4).to_le_bytes());
    asar.extend_from_slice(&l.to_le_bytes());
    asar.extend_from_slice(json.as_bytes());
    asar.resize(16 + padded as usize, 0);
    v.push(("deep.asar", asar));

    // HAR and JSON nested far beyond any sane depth.
    v.push(("deep.har", "[".repeat(200_000).into_bytes()));
    // Source map whose mappings decode to negative source and line indexes.
    v.push((
        "negative.js.map",
        br#"{"version":3,"sources":["a.js"],"names":[],"mappings":"DDDD,DDDD;FFFF"}"#.to_vec(),
    ));
    // JavaScript pointing at an inline source map that is not base64.
    v.push((
        "bad-inline.js",
        b"var a=1;\n//# sourceMappingURL=data:application/json;base64,!!!!\n".to_vec(),
    ));

    // A megabyte of deterministic noise, and a megabyte of one repeated byte.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    v.push((
        "noise.bin",
        (0..1 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect(),
    ));
    v.push(("zeros.bin", vec![0; 1 << 20]));
    v
}

#[test]
fn hostile_inputs_finish_without_panicking() {
    let d = tempfile::tempdir().unwrap();
    for (name, data) in corpus() {
        let p = write(d.path(), name, &data);
        run(&["analyze", "-f", "json"], &p);
    }
}

#[test]
fn forcing_the_wrong_type_is_an_error_not_a_crash() {
    let d = tempfile::tempdir().unwrap();
    let elf = write(d.path(), "crackme.elf", &fixture("crackme.elf"));
    let noise = write(
        d.path(),
        "noise.bin",
        &corpus().into_iter().find(|c| c.0 == "noise.bin").unwrap().1,
    );
    for kind in [
        "elf",
        "pe",
        "macho",
        "apk",
        "dex",
        "axml",
        "har",
        "js",
        "sourcemap",
        "wasm",
        "asar",
        "blob",
    ] {
        run(&["analyze", "--as", kind], &elf);
        run(&["analyze", "--as", kind], &noise);
    }
}

#[test]
fn code_commands_on_hostile_binaries_do_not_crash() {
    let d = tempfile::tempdir().unwrap();
    for (name, data) in corpus().into_iter().filter(|c| {
        c.0.starts_with("elf")
            || c.0.starts_with("pe")
            || c.0.starts_with("macho")
            || c.0.ends_with(".wasm")
    }) {
        let p = write(d.path(), name, &data);
        for args in [
            &["functions"][..],
            &["disasm", "--count", "64"],
            &["cfg", "main"],
            &["xrefs", "puts"],
            &["callgraph"],
        ] {
            run(args, &p);
        }
    }
}

#[test]
fn zip_bomb_apk_is_capped() {
    // 300 MiB of zeros compress to ~300 KiB. The APK reader caps every entry, so this must finish
    // quickly instead of inflating it all.
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("bomb.apk");
    let mut z = zip::ZipWriter::new(std::fs::File::create(&p).unwrap());
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    z.start_file("AndroidManifest.xml", opts).unwrap();
    let chunk = vec![0u8; 1 << 20];
    for _ in 0..300 {
        z.write_all(&chunk).unwrap();
    }
    z.start_file("classes.dex", opts).unwrap();
    for _ in 0..300 {
        z.write_all(&chunk).unwrap();
    }
    z.finish().unwrap();
    let start = std::time::Instant::now();
    run(&["analyze"], &p);
    assert!(
        start.elapsed() < Duration::from_secs(45),
        "took {:?}",
        start.elapsed()
    );
}

#[test]
fn oversized_input_is_refused_up_front() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("sparse.bin");
    let f = std::fs::File::create(&p).unwrap();
    f.set_len(3 << 20).unwrap(); // sparse: no disk used
    let (code, _, err) = run(&["analyze", "--max-size", "1"], &p);
    assert_eq!(code, 1);
    assert!(err.contains("exceeds the limit"), "{err}");
}

#[test]
fn missing_and_special_paths_are_clean_errors() {
    let d = tempfile::tempdir().unwrap();
    let (code, _, err) = run(&["analyze"], &d.path().join("nope"));
    assert_eq!(code, 1);
    assert!(err.contains("nope"), "{err}");

    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        // Symlink loop.
        let a = d.path().join("loop-a");
        std::os::unix::fs::symlink(d.path().join("loop-b"), &a).unwrap();
        std::os::unix::fs::symlink(&a, d.path().join("loop-b")).unwrap();
        assert_eq!(run(&["analyze"], &a).0, 1);
        // Non-UTF-8 file name.
        let odd = d
            .path()
            .join(std::ffi::OsStr::from_bytes(b"bin\xff\xfe.elf"));
        std::fs::write(&odd, fixture("crackme.elf")).unwrap();
        assert_eq!(run(&["analyze"], &odd).0, 0);
        // A FIFO blocks forever if read; a device never ends. Both are refused, not read.
        let fifo = d.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (code, _, err) = run(&["analyze"], &fifo);
        assert_eq!(code, 1);
        assert!(err.contains("not a regular file"), "{err}");
        let (code, _, _) = run(&["analyze"], Path::new("/dev/zero"));
        assert_eq!(code, 1);
    }
}

#[test]
fn fuzz_regressions_stay_fixed() {
    // Inputs the fuzzers once crashed rex with. The test binary is a debug build, so integer
    // overflow panics here even though release builds would silently wrap. A parser panic is
    // caught and turned into "malformed input", so also require that nothing was thrown away.
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fuzz-regressions");
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        let (_, out, err) = run(&["analyze", "-f", "json"], &p);
        assert!(!err.contains("parser panicked"), "{}: {err}", p.display());
        assert!(!out.contains("parser panicked"), "{}", p.display());
        run(&["functions"], &p);
        n += 1;
    }
    assert!(n > 0);
}
