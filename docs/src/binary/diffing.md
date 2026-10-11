# Binary diffing and patch analysis

## Why diff binaries?

When a vendor ships a security update, the fix is in the diff. Find the function that
changed a little (a new bounds check), and you've found the vulnerability, often before
details are public. This is called **patch diffing** ("1-day" research).

## Analogy: two editions of a book

Match chapters by **title** first (symbol names), then by **identical wording**
(instruction-sequence hash) for chapters that were renamed, and finally by
**resemblance** (overlap of instruction trigrams) for chapters that were edited.
Whatever's left was added or removed.

```sh
rex diff app-1.0.bin app-1.1.bin
```

rex reports, least-similar first:

- **changed** functions with similarity, Δinstructions, Δbasic blocks and how they were matched,
- **added / removed** functions, import changes and interesting string changes,
- a **"surgical change"** finding for small edits in otherwise similar functions.

Similarity uses mnemonic trigrams, so register allocation and address shifts don't
register as changes, but an added `cmp`/`ja` pair does.

## Workflow

1. `rex diff old new` → shortlist of surgical changes.
2. `rex disasm new -F <function>` and `rex disasm old -F <function>` side by side
   (or `diff <(rex disasm old -F f) <(rex disasm new -F f)`).
3. Look for new comparisons against lengths, new calls to `__stack_chk_fail`-like paths,
   or removed `strcpy`.

## Classic tools

BinDiff and Diaphora (IDA/Ghidra plugins) do graph-level matching; Ghidra's Version Tracking
handles large programs. rex gives you the fast first pass from the command line.

## Exercise

Add a length check to `check_password` in the crackme, rebuild to `crackme2`, and confirm
`rex diff` flags exactly that function as a surgical change.
