# JavaScript bundles and source maps

## Analogy: a city map with the street names removed

Minification renames every variable, but **string literals survive**: API paths, hostnames,
feature flags and, regrettably often, keys. And if the site ships a *source map*, you get the
street names back: the original, unminified source tree.

```sh
python3 labs/web/make_bundle.py                     # writes labs/web/bundle/app.min.js(.map)
rex analyze labs/web/bundle/app.min.js              # endpoints, secrets, sinks, frameworks
rex web sourcemap labs/web/bundle/app.min.js -d src # recover the original files
```

## What rex extracts

| Item | Notes |
|---|---|
| HTTP call sites | `fetch`/`axios`/`$.ajax` with the method, including `fetch(url, {method: "POST"})` |
| API-looking paths | string literals under `/api`, `/v1`, `/graphql`, `/auth`, … |
| GraphQL operations | `query Name {` / `mutation Name (` |
| Secrets | provider-specific key formats, plus generic `secret = "..."` with an entropy filter |
| Internal hosts | `localhost`, RFC 1918 ranges, `.internal`, `staging.` |
| Frameworks | React, Next.js, Vue, Angular, webpack, Firebase, Sentry, … |
| DOM sinks | `innerHTML`, `dangerouslySetInnerHTML`, `eval`, `document.write` |

Not every key in a client bundle is a leak. A browser-side maps or analytics key is meant to be
public but must be restricted by domain, so rex grades them *low*, while anything named
`secret`/`password`/`private` is *high*.

## Source maps

A source map's `sourcesContent` field embeds the original files. rex writes them under a
directory you choose and **sanitises every path**: `../../`, absolute roots and drive letters
cannot escape the output directory.

## Exercises

1. Which sink in the lab bundle is reachable from attacker-controlled input, and why does
   rex only call it "present"?
2. Rotate the leaked secret in the lab: what else must change besides the code?
