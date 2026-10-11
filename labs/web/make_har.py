#!/usr/bin/env python3
"""Generate labs/web/sample.har: a synthetic capture of a fictional shop API.

Everything here is fake (example.com domains, made-up tokens) but shaped like
real traffic, including a few deliberate security smells for the audit to find.
Run:  python3 make_har.py > sample.har
"""
import base64, json

def b64url(obj):
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()

JWT = ".".join([b64url({"alg": "HS256", "typ": "JWT"}),
                b64url({"sub": "user-1842", "role": "customer", "iat": 1700000000, "exp": 1700000000 + 90 * 86400}),
                "c2lnbmF0dXJlLW5vdC1yZWFs"])
API = "https://shop.example.com"

def entry(method, url, status=200, req_body=None, resp_body=None, req_headers=None, resp_headers=None, mime="application/json"):
    headers = [{"name": "Authorization", "value": "Bearer " + JWT}] if url.startswith(API + "/api") else []
    headers += [{"name": k, "value": v} for k, v in (req_headers or {}).items()]
    qs = []
    if "?" in url:
        for kv in url.split("?", 1)[1].split("&"):
            k, _, v = kv.partition("=")
            qs.append({"name": k, "value": v})
    e = {
        "startedDateTime": "2024-11-14T22:13:20.000Z", "time": 42,
        "request": {"method": method, "url": url, "httpVersion": "HTTP/2", "headers": headers,
                    "queryString": qs, "cookies": [], "headersSize": -1, "bodySize": 0},
        "response": {"status": status, "statusText": "", "httpVersion": "HTTP/2",
                     "headers": [{"name": "Content-Type", "value": mime}, {"name": "Server", "value": "nginx/1.18.0"}]
                                + [{"name": k, "value": v} for k, v in (resp_headers or {}).items()],
                     "cookies": [], "content": {"size": 0, "mimeType": mime}, "redirectURL": "", "headersSize": -1, "bodySize": -1},
        "cache": {}, "timings": {"send": 0, "wait": 40, "receive": 2},
    }
    if req_body is not None:
        e["request"]["postData"] = {"mimeType": "application/json", "text": json.dumps(req_body)}
    if resp_body is not None:
        text = resp_body if isinstance(resp_body, str) else json.dumps(resp_body)
        e["response"]["content"]["text"] = text
        e["response"]["content"]["size"] = len(text)
    return e

def product(pid, name, price, tags):
    return {"id": pid, "name": name, "price": price, "currency": "EUR", "tags": tags,
            "created_at": "2024-03-0%dT10:00:00Z" % (pid % 9 + 1), "image": f"https://cdn.example.com/p/{pid}.webp"}

entries = [
    entry("GET", "https://shop.example.com/", mime="text/html", resp_body="<html>...</html>"),
    entry("GET", "https://shop.example.com/static/js/app.4f9c2.js", mime="application/javascript", resp_body="console.log(1)"),
    entry("GET", API + "/api/v1/products?page=1&limit=20", resp_body={"items": [product(101, "Lamp", 19.5, ["home"]), product(102, "Desk", 129, [])], "page": 1, "total": 57}),
    entry("GET", API + "/api/v1/products?page=2&limit=20&sort=price", resp_body={"items": [product(103, "Chair", 49.99, ["home", "office"])], "page": 2, "total": 57}),
    entry("GET", API + "/api/v1/products/101", resp_body=product(101, "Lamp", 19.5, ["home"])),
    entry("GET", API + "/api/v1/products/102", resp_body=product(102, "Desk", 129, [])),
    entry("GET", API + "/api/v1/products/103", resp_body=product(103, "Chair", 49.99, ["home", "office"])),
    entry("GET", API + "/api/v1/products/999", status=404, resp_body={"error": "not_found", "message": "Product 999 does not exist"}),
    entry("GET", API + "/api/v1/users/me", resp_body={"id": "user-1842", "email": "ada@example.com", "name": "Ada", "newsletter": True, "address": None}),
    entry("PATCH", API + "/api/v1/users/me", req_body={"newsletter": False}, resp_body={"id": "user-1842", "email": "ada@example.com", "name": "Ada", "newsletter": False, "address": None}),
    entry("POST", API + "/api/v1/cart/items", status=201, req_body={"product_id": 101, "quantity": 2}, resp_body={"cart_id": "c5d2e7a0-3b1f-4c2e-9d6a-1f2e3d4c5b6a", "items": 2}),
    entry("POST", API + "/api/v1/cart/items", status=201, req_body={"product_id": 103, "quantity": 1, "gift": True}, resp_body={"cart_id": "c5d2e7a0-3b1f-4c2e-9d6a-1f2e3d4c5b6a", "items": 3}),
    entry("POST", API + "/api/v1/orders", status=201, req_body={"cart_id": "c5d2e7a0-3b1f-4c2e-9d6a-1f2e3d4c5b6a", "payment_method": "card", "coupon": "WELCOME10"},
          resp_body={"order_id": "ord-884213", "status": "pending", "total": 88.99, "created_at": "2024-11-14T22:14:01Z"}),
    entry("GET", API + "/api/v1/orders/ord-884213", resp_body={"order_id": "ord-884213", "status": "paid", "total": 88.99, "created_at": "2024-11-14T22:14:01Z"}),
    entry("GET", API + "/api/v1/orders/ord-771020", resp_body={"order_id": "ord-771020", "status": "shipped", "total": 12.0, "created_at": "2024-10-01T08:00:00Z"}),
    entry("GET", API + "/api/v1/orders/ord-650001/invoice", mime="application/pdf"),
    entry("GET", API + "/api/v1/search?q=lamp&email=ada@example.com", resp_body={"results": [101], "took_ms": 3}),
    entry("POST", API + "/api/v1/reviews", status=500, req_body={"product_id": 102, "rating": 5, "text": "great"},
          resp_body="Traceback (most recent call last):\n  File \"/srv/app/reviews.py\", line 42, in create\nKeyError: 'user'", mime="text/plain"),
    entry("POST", "https://shop.example.com/auth/login", req_body={"email": "ada@example.com", "password": "correct horse battery staple"},
          resp_body={"token": JWT}, resp_headers={"Set-Cookie": "session_id=9f8e7d6c5b4a; Path=/; Secure"}),
    entry("GET", "http://legacy.example.com/account/export?format=csv", mime="text/csv", req_headers={"Cookie": "session_id=9f8e7d6c5b4a"}),
    entry("GET", "https://maps.example.net/v3/geocode?key=demo-maps-key-NOT-REAL-7f3a9c&address=Berlin", resp_body={"lat": 52.52, "lng": 13.405}),
    entry("OPTIONS", API + "/api/v1/orders", status=204),
]
har = {"log": {"version": "1.2", "creator": {"name": "rex-lab-generator", "version": "1.0"}, "pages": [], "entries": entries}}
print(json.dumps(har, indent=2))
