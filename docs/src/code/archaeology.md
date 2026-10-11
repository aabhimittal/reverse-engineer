# Codebase archaeology

## Where do I start with 200 000 unfamiliar lines?

```sh
rex code map ~/src/project -o ATLAS.md
```

The atlas answers, in order:

1. **What is this?** Languages and line counts, technology stack from manifests and infra files.
2. **How does it start?** Entry points (`main`, CLI parsers, container commands) and
   **HTTP routes** for 11 frameworks.
3. **How is it organised?** A module graph from resolved imports (Python, JS/TS, Rust, Go,
   Java), dependency counts, and import cycles.
4. **What's central?** PageRank over the import graph: modules that important modules
   depend on rank highest, which are the ones to read first.
5. **Where are the bugs likely to be?** Hotspots, i.e. files that change often *and* are complex.
6. **Who knows what?** Contributors, bus factor, single-author hot files.
7. **What looks risky?** Security smells with `file:line`, and hard-coded secrets.

## Hotspots

Analogy: wear marks on a staircase. Steps that are worn (changed constantly) and steep
(complex) are where people trip. The score is
`(commits / max commits) x (complexity / max complexity)` over the last 24 months.

## How the structural analysis works

tree-sitter builds a syntax tree per file. Queries are structural greps: "every
`function_item` and its name". From that rex gets definitions with their containers
(`Struct::method`), the calls made inside each function, and cyclomatic complexity
(1 + decision points). Imports are resolved against the file tree, so edges point at real files.

## Dogfooding

```sh
rex code map . -o ATLAS.md   # rex analysing its own source
```

## Exercises

1. Run the atlas on a project you know. Is the suggested reading order the one you'd give a new hire?
2. Find an import cycle in a real project and decide which edge to cut.
