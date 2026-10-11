#!/usr/bin/env python3
"""Generate a small "production" bundle plus its source map for the JS lab.

The original sources live inside the map (sourcesContent), exactly like many
real sites that forget to strip source maps. Run from this directory:
    python3 make_bundle.py
"""
import json, os

sources = {
    "webpack:///./src/api/client.ts": """import { config } from "../config";

export async function getProducts(page: number) {
  const r = await fetch(`/api/v1/products?page=${page}`);
  return r.json();
}

export async function createOrder(cartId: string) {
  return fetch("/api/v1/orders", { method: "POST", body: JSON.stringify({ cartId }) });
}

export async function adminStats() {
  // TODO: remove before launch
  return fetch(config.internalUrl + "/internal/admin/stats");
}
""",
    "webpack:///./src/config.ts": """export const config = {
  apiBase: "https://shop.example.com/api/v1",
  internalUrl: "http://admin.staging.example.internal:8080",
  client_secret: "Zq8r3TfL0pWm2xYb7Nc4Vd9Ke6Hj1Ga5",
  featureFlags: { newCheckout: process.env.REACT_APP_NEW_CHECKOUT === "1" },
};
""",
    "webpack:///./src/components/Review.tsx": """export function Review({ html }: { html: string }) {
  // Renders merchant-supplied HTML: DOM XSS sink
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
""",
}
bundle = (
    '!function(){"use strict";var __webpack_require__=function(e){return e};'
    'const c={apiBase:"https://shop.example.com/api/v1",internalUrl:"http://admin.staging.example.internal:8080",'
    'client_secret:"Zq8r3TfL0pWm2xYb7Nc4Vd9Ke6Hj1Ga5",featureFlags:{newCheckout:"1"===process.env.REACT_APP_NEW_CHECKOUT}};'
    'async function p(e){return(await fetch(`/api/v1/products?page=${e}`)).json()}'
    'async function o(e){return fetch("/api/v1/orders",{method:"POST",body:JSON.stringify({cartId:e})})}'
    'async function a(){return fetch(c.internalUrl+"/internal/admin/stats")}'
    'function r({html:e}){return React.createElement("div",{dangerouslySetInnerHTML:{__html:e}})}'
    'window.shop={p:p,o:o,a:a,r:r}}();\n//# sourceMappingURL=app.min.js.map\n'
)
smap = {"version": 3, "file": "app.min.js", "sources": list(sources), "sourcesContent": list(sources.values()), "names": [], "mappings": "AAAA"}
os.makedirs("bundle", exist_ok=True)
open("bundle/app.min.js", "w").write(bundle)
open("bundle/app.min.js.map", "w").write(json.dumps(smap, indent=1))
print("wrote bundle/app.min.js and bundle/app.min.js.map")
