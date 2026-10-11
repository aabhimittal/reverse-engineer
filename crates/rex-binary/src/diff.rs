//! Binary diffing ("what changed between these two builds?").
//!
//! Patch diffing is how researchers find the bug a security update fixed:
//! diff the old and new binary, and the function with a small, surgical
//! change (a new bounds check) is usually the vulnerability. Analogy: two
//! editions of a book. Chapters are matched by title first (symbol names), then
//! by their exact wording (instruction-sequence hash), and finally by
//! resemblance (n-gram similarity) for chapters that were renamed.

use crate::functions::{Function, Program};
use crate::model::Binary;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};

/// How a function changed.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Change {
    /// Same instruction sequence.
    Identical,
    /// Matched, but the code differs.
    Changed,
    /// Only in the new binary.
    Added,
    /// Only in the old binary.
    Removed,
}

/// One row of a function diff.
#[derive(Debug, Clone, Serialize)]
pub struct FnDiff {
    /// Function name (new name if matched).
    pub name: String,
    /// Change kind.
    pub change: Change,
    /// Similarity 0.0–1.0 (1.0 for identical).
    pub similarity: f64,
    /// Address in old binary.
    pub old_addr: Option<u64>,
    /// Address in new binary.
    pub new_addr: Option<u64>,
    /// Instruction count delta (new − old).
    pub insn_delta: i64,
    /// Basic-block count delta (new − old).
    pub block_delta: i64,
    /// How it was matched (`name`, `hash`, `similarity`).
    pub matched_by: &'static str,
}

/// Whole diff result.
#[derive(Debug, Clone, Serialize)]
pub struct BinDiff {
    /// Function-level rows (changed first, sorted by similarity ascending).
    pub functions: Vec<FnDiff>,
    /// Imports only in the new binary.
    pub imports_added: Vec<String>,
    /// Imports only in the old binary.
    pub imports_removed: Vec<String>,
    /// Strings only in the new binary (interesting ones).
    pub strings_added: Vec<String>,
    /// Strings only in the old binary.
    pub strings_removed: Vec<String>,
    /// Section size changes: (name, old size, new size).
    pub sections: Vec<(String, u64, u64)>,
}

impl BinDiff {
    /// Count rows of a given change kind.
    pub fn count(&self, c: Change) -> usize {
        self.functions.iter().filter(|f| f.change == c).count()
    }
}

fn ngrams(f: &Function) -> HashSet<u64> {
    let m: Vec<&str> = f.insns().map(|i| i.mnemonic.as_str()).collect();
    m.windows(3)
        .map(|w| {
            use std::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            w.hash(&mut h);
            h.finish()
        })
        .collect()
}

fn jaccard(a: &HashSet<u64>, b: &HashSet<u64>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    inter / union
}

fn row(
    name: String,
    change: Change,
    sim: f64,
    a: Option<&Function>,
    b: Option<&Function>,
    by: &'static str,
) -> FnDiff {
    let ic = |f: Option<&Function>| f.map(|f| f.insn_count() as i64).unwrap_or(0);
    let bc = |f: Option<&Function>| f.map(|f| f.blocks.len() as i64).unwrap_or(0);
    FnDiff {
        name,
        change,
        similarity: (sim * 1000.0).round() / 1000.0,
        old_addr: a.map(|f| f.addr),
        new_addr: b.map(|f| f.addr),
        insn_delta: ic(b) - ic(a),
        block_delta: bc(b) - bc(a),
        matched_by: by,
    }
}

/// Diff two analysed binaries.
pub fn diff(old: (&Binary, &Program, &[String]), new: (&Binary, &Program, &[String])) -> BinDiff {
    let (ba, pa, sa) = old;
    let (bb, pb, sb) = new;
    let mut rows = Vec::new();
    let mut used_a: HashSet<u64> = HashSet::new();
    let mut used_b: HashSet<u64> = HashSet::new();

    let named = |p: &Program| -> HashMap<String, u64> {
        p.functions
            .values()
            .filter(|f| !f.name.starts_with("sub_"))
            .map(|f| (f.name.clone(), f.addr))
            .collect()
    };
    let na = named(pa);
    let nb = named(pb);

    // 1. By name.
    for (name, &aa) in &na {
        if let Some(&ab) = nb.get(name) {
            let (fa, fb) = (&pa.functions[&aa], &pb.functions[&ab]);
            let (change, sim) = if fa.mnemonic_hash() == fb.mnemonic_hash() {
                (Change::Identical, 1.0)
            } else {
                (Change::Changed, jaccard(&ngrams(fa), &ngrams(fb)))
            };
            rows.push(row(name.clone(), change, sim, Some(fa), Some(fb), "name"));
            used_a.insert(aa);
            used_b.insert(ab);
        }
    }

    // 2. By unique exact hash.
    let hashes = |p: &Program, used: &HashSet<u64>| -> HashMap<String, Vec<u64>> {
        let mut m: HashMap<String, Vec<u64>> = HashMap::new();
        for f in p
            .functions
            .values()
            .filter(|f| !used.contains(&f.addr) && f.insn_count() >= 4)
        {
            m.entry(f.mnemonic_hash()).or_default().push(f.addr);
        }
        m
    };
    let ha = hashes(pa, &used_a);
    let hb = hashes(pb, &used_b);
    for (h, va) in &ha {
        if let Some(vb) = hb.get(h) {
            if va.len() == 1 && vb.len() == 1 {
                let (fa, fb) = (&pa.functions[&va[0]], &pb.functions[&vb[0]]);
                rows.push(row(
                    fb.name.clone(),
                    Change::Identical,
                    1.0,
                    Some(fa),
                    Some(fb),
                    "hash",
                ));
                used_a.insert(fa.addr);
                used_b.insert(fb.addr);
            }
        }
    }

    // 3. Best similarity for the rest (bounded to keep it O(n·m) small).
    let rest_a: Vec<&Function> = pa
        .functions
        .values()
        .filter(|f| !used_a.contains(&f.addr))
        .collect();
    let rest_b: Vec<&Function> = pb
        .functions
        .values()
        .filter(|f| !used_b.contains(&f.addr))
        .collect();
    if rest_a.len() * rest_b.len() <= 4_000_000 {
        let ga: Vec<_> = rest_a.iter().map(|f| ngrams(f)).collect();
        let gb: Vec<_> = rest_b.iter().map(|f| ngrams(f)).collect();
        let mut cands = Vec::new();
        for (i, a) in ga.iter().enumerate() {
            for (j, b) in gb.iter().enumerate() {
                let s = jaccard(a, b);
                if s >= 0.6 {
                    cands.push((s, i, j));
                }
            }
        }
        cands.sort_by(|x, y| y.0.total_cmp(&x.0));
        for (s, i, j) in cands {
            let (fa, fb) = (rest_a[i], rest_b[j]);
            if used_a.contains(&fa.addr) || used_b.contains(&fb.addr) {
                continue;
            }
            let change = if s >= 0.999 && fa.mnemonic_hash() == fb.mnemonic_hash() {
                Change::Identical
            } else {
                Change::Changed
            };
            rows.push(row(
                fb.name.clone(),
                change,
                s,
                Some(fa),
                Some(fb),
                "similarity",
            ));
            used_a.insert(fa.addr);
            used_b.insert(fb.addr);
        }
    }
    for f in pa.functions.values().filter(|f| !used_a.contains(&f.addr)) {
        rows.push(row(
            f.name.clone(),
            Change::Removed,
            0.0,
            Some(f),
            None,
            "-",
        ));
    }
    for f in pb.functions.values().filter(|f| !used_b.contains(&f.addr)) {
        rows.push(row(f.name.clone(), Change::Added, 0.0, None, Some(f), "-"));
    }
    let order = |c: Change| match c {
        Change::Changed => 0,
        Change::Added => 1,
        Change::Removed => 2,
        Change::Identical => 3,
    };
    rows.sort_by(|x, y| {
        order(x.change)
            .cmp(&order(y.change))
            .then(x.similarity.total_cmp(&y.similarity))
            .then(x.name.cmp(&y.name))
    });

    let set = |v: Vec<String>| v.into_iter().collect::<BTreeSet<_>>();
    let ia = set(ba.import_names());
    let ib = set(bb.import_names());
    let s_a: BTreeSet<&String> = sa.iter().collect();
    let s_b: BTreeSet<&String> = sb.iter().collect();
    let mut sections = Vec::new();
    for s in &bb.sections {
        if let Some(o) = ba.sections.iter().find(|x| x.name == s.name) {
            if o.size != s.size {
                sections.push((s.name.clone(), o.size, s.size));
            }
        } else {
            sections.push((s.name.clone(), 0, s.size));
        }
    }
    for s in &ba.sections {
        if !bb.sections.iter().any(|x| x.name == s.name) {
            sections.push((s.name.clone(), s.size, 0));
        }
    }
    BinDiff {
        functions: rows,
        imports_added: ib.difference(&ia).cloned().collect(),
        imports_removed: ia.difference(&ib).cloned().collect(),
        strings_added: s_b
            .difference(&s_a)
            .map(|s| s.to_string())
            .take(200)
            .collect(),
        strings_removed: s_a
            .difference(&s_b)
            .map(|s| s.to_string())
            .take(200)
            .collect(),
        sections,
    }
}
