#!/usr/bin/env python3
"""Build the rex demo page from real `rex` runs.

Every number, finding, listing and graph on the page is captured from the rex binary run against
files in this repository. Nothing is typed in by hand. The page itself is a static template
(docs/demo/template.html) with the captured data embedded.

    cargo build -p rex-cli --features multiarch
    python3 scripts/build-demo.py [--rex target/debug/rex] [--out demo.html]
"""
import argparse
import html
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FX = "crates/rex-binary/tests/fixtures"

p = argparse.ArgumentParser()
p.add_argument("--rex", default=os.path.join(ROOT, "target/debug/rex"))
p.add_argument("--out", default=os.path.join(ROOT, "demo.html"))
p.add_argument("--site-data", help="also write the website's data file (real output for the landing page)")
args = p.parse_args()

ENV = dict(os.environ, NO_COLOR="1")


def run(*argv, ok=(0, 3), env=None):
    r = subprocess.run([args.rex, *argv], cwd=ROOT, env=env or ENV, capture_output=True, text=True)
    if r.returncode not in ok:
        sys.exit(f"rex {' '.join(argv)} failed ({r.returncode}):\n{r.stderr}")
    return r.stdout


def analyze(path):
    return json.loads(run("analyze", "-f", "json", path))[0]


def text_view(label, *argv):
    return {"type": "text", "label": label, "command": "rex " + " ".join(argv), "text": run(*argv).rstrip()}


def cfg_view(label, path, fn):
    mm = run("cfg", path, fn)
    nodes, edges = {}, []
    for line in mm.splitlines():
        m = re.match(r'^\s+(b[0-9a-f]+)\["(.*)"\]\s*$', line)
        if m:
            parts = html.unescape(m.group(2)).split("<br/>")
            nodes[m.group(1)] = {"id": m.group(1), "addr": parts[0], "lines": parts[1:]}
            continue
        m = re.match(r"^\s+(b[0-9a-f]+) (-- (T|F) -->|-->|==>) (b[0-9a-f]+)\s*$", line)
        if m:
            kind = {"T": "true", "F": "false"}.get(m.group(3)) or ("jump" if m.group(2) == "==>" else "fall")
            edges.append({"from": m.group(1), "to": m.group(4), "kind": kind})
    if not nodes:
        sys.exit(f"could not parse CFG for {fn} in {path}:\n{mm}")
    return {
        "type": "cfg",
        "label": label,
        "command": f"rex cfg {path} {fn}",
        "nodes": list(nodes.values()),
        "edges": edges,
    }


def sample(id, title, blurb, path, kind, views=(), gate="high", skip_sections=()):
    rep = analyze(path)
    sections = [s for s in rep["sections"] if s["id"] not in skip_sections]
    for s in sections:
        s.pop("data", None)  # raw machine data is large and not shown
    return {
        "id": id,
        "title": title,
        "blurb": blurb,
        "kind": kind,
        "path": path,
        "command": f"rex analyze {path} --fail-on {gate}",
        "artifact": rep["artifact"],
        "duration_ms": rep["duration_ms"],
        "findings": rep["findings"],
        "sections": sections,
        "views": list(views),
        "gate": gate,
    }


def read_prompts():
    src = open(os.path.join(ROOT, "crates/rex-mcp/src/lib.rs"), encoding="utf-8").read()
    block = src[src.index("pub static PROMPTS"):src.index("fn prompts_list")]
    out = re.findall(r'\(\s*"([a-z_]+)",\s*"([^"]+)",\s*&\[', block)
    if not out:
        sys.exit("could not read MCP prompts from rex-mcp")
    return out


PROMPTS = read_prompts()
tmp = tempfile.mkdtemp()
fw = os.path.join(tmp, "firmware.bin")
subprocess.run([sys.executable, os.path.join(ROOT, "labs/firmware/make_firmware.py"), fw], check=True, capture_output=True)

samples = [
    sample(
        "crackme", "Hardened crackme", "A small x86-64 PIE with canary, RELRO and FORTIFY. Where is the password check?",
        f"{FX}/crackme.elf", "ELF · x86-64",
        views=[
            text_view("check_password", "disasm", f"{FX}/crackme.elf", "-F", "check_password"),
            cfg_view("check_password CFG", f"{FX}/crackme.elf", "check_password"),
            text_view("who calls strlen?", "xrefs", f"{FX}/crackme.elf", "strlen"),
        ],
        skip_sections=("binary.disasm.root", "binary.cfg.root", "binary.callgraph"),
    ),
    sample(
        "vuln", "Binary with no mitigations", "Built the way you should not build anything: no NX, no PIE, no canary, gets() and strcpy().",
        f"{FX}/vuln.elf", "ELF · x86-64",
        views=[
            text_view("main", "disasm", f"{FX}/vuln.elf", "-F", "main"),
            text_view("greet (strcpy overflow)", "disasm", f"{FX}/vuln.elf", "-F", "greet"),
            text_view("who calls system?", "xrefs", f"{FX}/vuln.elf", "system"),
        ],
        skip_sections=("binary.disasm.root", "binary.cfg.root", "binary.callgraph"),
    ),
    sample(
        "winpe", "Windows PE with injection imports", "Imports that spell process injection, a Run-key persistence string and a hard-coded URL.",
        f"{FX}/sample.exe", "PE · x86-64",
        skip_sections=("binary.disasm.root", "binary.cfg.root", "binary.callgraph"),
    ),
    sample(
        "asar", "Electron app", "An app.asar with nodeIntegration on, no context isolation, an AWS key in config and a path-reading IPC channel.",
        "labs/electron/app.asar", "Electron ASAR",
    ),
    sample(
        "wasm", "WebAssembly module", "What can this .wasm do? The imports are its whole reach outside the sandbox.",
        "labs/wasm/sample.wasm", "WebAssembly",
        views=[
            text_view("run", "disasm", "labs/wasm/sample.wasm", "-F", "run"),
            text_view("decrypt_config", "disasm", "labs/wasm/sample.wasm", "-F", "decrypt_config"),
            text_view("who calls path_open?", "xrefs", "labs/wasm/sample.wasm", "path_open"),
        ],
        gate="medium",
        skip_sections=("binary.disasm.root",),
    ),
    sample(
        "arm64", "AArch64 binary", "Dynamic AArch64 ELF with a real PLT. Functions, CFGs and imports recovered on a non-x86 CPU.",
        f"{FX}/sample_a64.elf", "ELF · AArch64",
        views=[
            text_view("check", "disasm", f"{FX}/sample_a64.elf", "-F", "check"),
            cfg_view("check CFG", f"{FX}/sample_a64.elf", "check"),
            cfg_view("main CFG", f"{FX}/sample_a64.elf", "main"),
        ],
        skip_sections=("binary.disasm.root", "binary.cfg.root", "binary.callgraph"),
    ),
    sample(
        "har", "Browser traffic", "A HAR capture of a shopping app. No docs exist, so rex writes them.",
        "labs/web/sample.har", "HAR capture",
    ),
    sample(
        "firmware", "Firmware image", "A router-style blob: bootloader, kernel, SquashFS, and a private key someone forgot.",
        fw, "Firmware blob",
    ),
]
# The firmware path is a temp file; show the lab-relative name instead.
for s in samples:
    if s["id"] == "firmware":
        s["path"] = "labs/build/firmware.bin"
        s["command"] = "rex analyze labs/build/firmware.bin --fail-on high"
        s["artifact"]["path"] = s["path"]

# The HAR sample also shows the generated OpenAPI document (first lines of the YAML).
for s in samples:
    if s["id"] == "har":
        yaml = run("web", "har2openapi", "labs/web/sample.har").splitlines()
        s["views"].append({"type": "text", "label": "OpenAPI 3.1", "command": "rex web har2openapi labs/web/sample.har", "text": "\n".join(yaml[:70] + ["# … (truncated for the page)"] if len(yaml) > 70 else yaml)})

# Agent setup: a dry run against a throwaway home that has three agents "installed".
home = tempfile.mkdtemp()
for d in (".cursor", ".gemini", ".codex"):
    os.makedirs(os.path.join(home, d))
setup_env = dict(ENV, HOME=home, PATH="/usr/bin:/bin")
dry = run("setup", "--dry-run", "--command", "rex", env=setup_env).rstrip().replace(home, "~")
samples.append({
    "id": "agents",
    "title": "Use it from your AI agent",
    "blurb": "One command detects Cursor, Gemini CLI, Codex CLI, Claude Code and Claude Desktop and wires up the MCP server. A dry run changes nothing.",
    "kind": "Agent setup",
    "path": "",
    "command": "rex setup --dry-run",
    "artifact": None,
    "duration_ms": None,
    "findings": [],
    "sections": [],
    "views": [
        {"type": "text", "label": "rex setup --dry-run", "command": "rex setup --dry-run", "text": dry},
        {"type": "text", "label": "MCP prompts", "command": "prompts/list (MCP)", "text": "\n".join(
            f"{n:16} {d}" for n, d in PROMPTS)},
    ],
    "gate": "high",
})

version = run("--version").strip()
# The page is only worth publishing if every sample still produces something. Fail loudly instead of
# shipping a demo where a sample quietly went blank after a change in rex.
EXPECTED = {"crackme", "vuln", "winpe", "asar", "wasm", "arm64", "har", "firmware", "agents"}
problems = []
if {s["id"] for s in samples} != EXPECTED:
    problems.append(f"samples are {sorted(s['id'] for s in samples)}, expected {sorted(EXPECTED)}")
for s in samples:
    if not (s["findings"] or s["sections"] or s["views"]):
        problems.append(f"{s['id']}: no findings, sections or views")
    for v in s["views"]:
        if v["type"] == "text" and not v["text"].strip():
            problems.append(f"{s['id']}: view {v['label']!r} is empty")
        if v["type"] == "cfg" and (len(v["nodes"]) < 2 or not v["edges"]):
            problems.append(f"{s['id']}: CFG {v['label']!r} has {len(v['nodes'])} blocks and {len(v['edges'])} edges")
for sid in ("crackme", "arm64"):
    if not any(v["type"] == "cfg" for s in samples if s["id"] == sid for v in s["views"]):
        problems.append(f"{sid}: no CFG view")
if problems:
    sys.exit("demo check failed:\n  " + "\n  ".join(problems))

data = {"rex_version": version, "samples": samples}
with open(os.path.join(ROOT, "docs/demo/template.html"), encoding="utf-8") as f:
    page = f.read()
blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
if "/*__REX_DATA__*/null" not in page:
    sys.exit("docs/demo/template.html has no /*__REX_DATA__*/null placeholder")
page = page.replace("/*__REX_DATA__*/null", blob)
# The template is a page body; make it a complete standalone document for the website.
page = (
    '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
    '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
    '<meta name="description" content="Real rex output on nine lab samples: findings, disassembly and control-flow graphs.">\n'
    "</head>\n<body>\n" + page + "\n</body>\n</html>\n"
)
os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
with open(args.out, "w", encoding="utf-8") as f:
    f.write(page)
print(f"wrote {args.out} ({len(page)//1024} KiB) from {version}; {sum(len(s['findings']) for s in samples)} findings across {len(samples)} samples")


def section(text, title):
    """Lines of one `── title` section from rex's text output."""
    out, on = [], False
    for line in text.splitlines():
        if line.startswith("── "):
            on = line[3:].strip().startswith(title)
            continue
        if on:
            out.append(line)
    while out and not out[-1].strip():
        out.pop()
    return "\n".join(out)


def go_sample():
    """A stripped Go binary for linux/arm64, built on the fly when Go is installed."""
    import shutil

    if not shutil.which("go"):
        return None
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "main.go"), "w") as f:
        f.write('package main\n\nimport "os"\n\n//go:noinline\nfunc check(pw string) bool { return pw == "open-sesame" }\n\n'
                'func main() {\n\tif len(os.Args) > 1 && check(os.Args[1]) {\n\t\tprintln("granted")\n\t}\n}\n')
    with open(os.path.join(d, "go.mod"), "w") as f:
        f.write("module example.com/hello\n\ngo 1.21\n")
    out = os.path.join(d, "hello-arm64")
    env = dict(os.environ, GOOS="linux", GOARCH="arm64", CGO_ENABLED="0", GOFLAGS="-mod=mod", GOCACHE=os.path.join(d, "cache"))
    r = subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", out, "."], cwd=d, env=env, capture_output=True)
    if r.returncode != 0:
        return None
    info = run("info", out)
    funcs = run("functions", "--max-rows", "0", out)
    names = [l for l in funcs.splitlines() if " main." in l]
    return {
        "command": "rex info hello-arm64   # GOOS=linux GOARCH=arm64 go build -ldflags='-s -w'",
        "overview": "\n".join(l for l in section(info, "Binary overview").splitlines()
                              if any(k in l for k in ("Format", "Architecture", "Stripped", "Go ", "Symbols"))),
        "main": "\n".join(names),
        "disasm": "\n".join(run("disasm", out, "-F", "main.check").splitlines()[:9]),
    }


if args.site_data:
    vuln = run("analyze", f"{FX}/vuln.elf")
    good_json = run("analyze", "-f", "json", f"{FX}/crackme.elf")
    bad_json = run("analyze", "-f", "json", f"{FX}/vuln.elf")
    tmpd = tempfile.mkdtemp()
    for n, t in (("old.json", good_json), ("new.json", bad_json)):
        with open(os.path.join(tmpd, n), "w") as f:
            f.write(t)
    cmp = run("compare", "--fail-on", "high", os.path.join(tmpd, "old.json"), os.path.join(tmpd, "new.json"))
    site = {
        "version": version,
        "hero": {
            "command": f"rex analyze {FX}/vuln.elf".replace(FX + "/", ""),
            "findings": section(vuln, "Findings").strip("\n"),
            "mitigations": section(vuln, "Security mitigations"),
        },
        "compare": {
            "command": "rex compare crackme.json vuln.json --fail-on high",
            "text": section(cmp, "Findings that changed"),
        },
        "go": go_sample(),
        "agents": next(v for s_ in samples if s_["id"] == "agents" for v in s_["views"]),
        "prompts": [{"name": n, "description": d} for n, d in PROMPTS],
        "samples": [{"id": s_["id"], "title": s_["title"], "kind": s_["kind"], "findings": len(s_["findings"])}
                    for s_ in samples if s_["id"] != "agents"],
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.site_data)), exist_ok=True)
    with open(args.site_data, "w", encoding="utf-8") as f:
        json.dump(site, f, ensure_ascii=False, indent=1)
    print(f"wrote {args.site_data}" + ("" if site["go"] else " (no Go toolchain: Go sample skipped)"))

