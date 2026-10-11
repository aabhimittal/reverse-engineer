# From traffic to API spec

## The problem

You have an application whose API nobody documented. Its traffic, however, is observable.
A HAR file (HTTP Archive) is a flight recorder of a browser session: every request and
response with headers and bodies. Export one from your browser's DevTools Network tab,
mitmproxy, Burp, Charles or Proxyman, then turn it into an OpenAPI specification.

> Only capture traffic from applications and accounts you are entitled to inspect, and
> sanitise HAR files before sharing them: they contain live tokens and cookies.

## Hands-on

```sh
python3 labs/web/make_har.py > labs/web/sample.har      # synthetic shop API capture
rex web har2openapi labs/web/sample.har -o api.yaml      # OpenAPI 3.1
rex analyze labs/web/sample.har                          # endpoints + traffic audit
```

## How path templating works

`/users/42`, `/users/97` and `/users/1003` are one endpoint, `/users/{userId}`. rex does it
in two passes:

1. **Per-segment heuristics**: integers, UUIDs, long hex strings, dates and mostly-numeric
   tokens (`ord-884213`) are identifiers. Parameter names come from the preceding word
   (`users` becomes `userId`).
2. **Sibling clustering**: under a shared prefix, a position with many distinct values that
   look like data (`rust-lang`, `v8.2`), or that co-vary one-to-one with their neighbours
   (`/repos/{owner}/{repo}`), is also a parameter. Resource names such as
   `/api/users`, `/api/orders` stay literal because they lack those signals.

## Schema inference

Each observed JSON body is a sighting. Merging sightings answers:

- **required**: present in every observation of the object
- **optional**: present in some
- **type**: integer, number (when integers and decimals mix), string, boolean, null (rendered
  as `type: [string, "null"]` in OpenAPI 3.1), arrays and nested objects
- **format**: `date-time`, `date`, `email`, `uuid`, `uri`, `ipv4`, only when every sample matches

The spec only reflects traffic you captured. Exercise more of the app, then re-run.

## Passive traffic audit

The same pass reports, without sending a single request: credentials sent over plain HTTP,
live credentials present in the capture (masked), JWT claims and lifetimes (decoded, never
verified), session cookies missing `Secure`/`HttpOnly`/`SameSite`, permissive CORS with
credentials, version disclosure, verbose server errors, and missing security headers.

## Classic tools

mitmproxy2swagger, Postman's capture, Burp's "Generate OpenAPI" extensions, `jq` for ad hoc work.

## Exercises

1. Add a request for `/api/v1/products/abc-slug` to the generator and see whether the
   parameter type changes from `integer` to `string`.
2. Which findings would remain if every request were HTTPS with proper cookie flags?
