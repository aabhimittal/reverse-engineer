//! Seeded mutation testing on stable Rust: flip, truncate and splice bytes in valid inputs and
//! make sure no parser panics or hangs. (`fuzz/` holds coverage-guided libFuzzer targets for deeper runs.)

use std::path::PathBuf;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(data: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut d = data.to_vec();
    match rng.below(4) {
        0 => d.truncate(rng.below(d.len().max(1))),
        1 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
        }
        2 => {
            let i = rng.below(d.len());
            let n = rng.below(16).min(d.len() - i);
            for b in &mut d[i..i + n] {
                *b = [0x00, 0xff, 0x7f, 0x80][rng.below(4)];
            }
        }
        _ => {
            let i = rng.below(d.len());
            let j = rng.below(d.len());
            let chunk: Vec<u8> = d[i..(i + 32).min(d.len())].to_vec();
            d.splice(j..j, chunk);
        }
    }
    d
}

fn lab(p: &str) -> Vec<u8> {
    std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../labs")
            .join(p),
    )
    .unwrap()
}

#[test]
fn mutated_inputs_never_panic() {
    let apk = lab("android/rexlab.apk");
    let har = lab("web/sample.har");
    let js = lab("web/bundle/app.min.js");
    let map = lab("web/bundle/app.min.js.map");
    let manifest = {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(&apk[..])).unwrap();
        let mut f = z.by_name("AndroidManifest.xml").unwrap();
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut v).unwrap();
        v
    };
    let dex = {
        let mut z = zip::ZipArchive::new(std::io::Cursor::new(&apk[..])).unwrap();
        let mut f = z.by_name("classes.dex").unwrap();
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut v).unwrap();
        v
    };
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    for round in 0..1500 {
        let m = mutate(&manifest, &mut rng);
        if let Ok(x) = rex_web::axml::parse(&m) {
            let _ = rex_web::axml::Manifest::from_xml(&x);
            let _ = x.to_xml();
        }
        let _ = rex_web::dex::parse(&mutate(&dex, &mut rng)).map(|d| rex_web::dex::risky_apis(&d));
        let _ = rex_web::apk::analyze(&mutate(&apk, &mut rng));
        if let Ok(h) = rex_web::har::parse(&mutate(&har, &mut rng)) {
            let eps = rex_web::har::extract(&h, &Default::default());
            let _ = rex_web::openapi::build(&h, &eps, None);
            let _ = rex_web::audit::audit(&h);
        }
        let _ = rex_web::js::analyze(&String::from_utf8_lossy(&mutate(&js, &mut rng)));
        let _ = rex_web::js::parse_source_map(&mutate(&map, &mut rng));
        assert!(round < 1500);
    }
}
