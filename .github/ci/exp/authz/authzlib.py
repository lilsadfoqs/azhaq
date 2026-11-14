"""Shared helpers of the access-control experiment: a no-redirect HTTP client,
route templates, session headers and HAR files. Python 3 stdlib only."""
import http.client
import json
import re
import urllib.parse


def split_url(url):
    u = urllib.parse.urlsplit(url)
    return u.scheme or "http", u.hostname, u.port or (443 if u.scheme == "https" else 80), (u.path or "/") + ("?" + u.query if u.query else "")


def call(method, url, headers=None, body=None, timeout=15):
    """One request, no redirect followed. headers: list of (name, value) or dict.
    Returns dict status, reason, headers (list), body (str)."""
    scheme, host, port, target = split_url(url)
    if isinstance(headers, dict):
        headers = list(headers.items())
    headers = list(headers or [])
    data = body.encode() if isinstance(body, str) else body
    conn = (http.client.HTTPSConnection if scheme == "https" else http.client.HTTPConnection)(host, port, timeout=timeout)
    try:
        conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
        names = {n.lower() for n, _ in headers}
        if "host" not in names:
            conn.putheader("Host", f"{host}:{port}" if port not in (80, 443) else host)
        if "accept-encoding" not in names:
            conn.putheader("Accept-Encoding", "identity")
        for n, v in headers:
            conn.putheader(n, v)
        if data is not None and "content-length" not in names:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        r = conn.getresponse()
        raw = r.read()
        return {"status": r.status, "reason": r.reason, "headers": r.getheaders(),
                "body": raw.decode("utf-8", "replace")}
    finally:
        conn.close()


def jcall(method, url, headers=None, obj=None, timeout=15):
    hs = list(headers.items()) if isinstance(headers, dict) else list(headers or [])
    body = None
    if obj is not None:
        body = json.dumps(obj)
        hs.append(("Content-Type", "application/json"))
    return call(method, url, hs, body, timeout)


def try_json(text):
    try:
        return json.loads(text)
    except ValueError:
        return None


# --- route templates -------------------------------------------------------

def template_re(template):
    parts = re.split(r"(\{[^}]+\})", template)
    return re.compile("^" + "".join("[^/]+" if p.startswith("{") else re.escape(p) for p in parts) + "/?$")


def specificity(template):
    segs = [s for s in template.split("/") if s]
    lit = sum(1 for s in segs if not s.startswith("{"))
    return (lit, -len(segs) + lit)


class Matcher:
    """Concrete (method, path) -> key route, the most specific template wins."""

    def __init__(self, routes):
        self.routes = [(r, template_re(r["template"]), specificity(r["template"])) for r in routes]

    def find(self, method, path, any_method=False):
        path = urllib.parse.urlsplit(path).path or "/"
        best = None
        for r, rx, spec in self.routes:
            if (any_method or r["method"] == method) and rx.match(path):
                if best is None or spec > best[1]:
                    best = (r, spec)
        return best[0] if best else None

    def methods_for(self, path):
        path = urllib.parse.urlsplit(path).path or "/"
        return [r for r, rx, _ in self.routes if rx.match(path)]


# --- sessions --------------------------------------------------------------

def parse_header(line):
    n, v = line.split(":", 1)
    return n.strip(), v.strip()


def load_sessions(path):
    """sessions.json: role -> 'Name: value' (the header that carries the session)."""
    with open(path) as f:
        return json.load(f)


# --- HAR -------------------------------------------------------------------

def har_entry(method, url, req_headers, req_body, resp, started, ms):
    _, _, _, target = split_url(url)
    q = urllib.parse.urlsplit(url).query
    ctype = next((v for n, v in resp["headers"] if n.lower() == "content-type"), "")
    entry = {
        "startedDateTime": started, "time": ms, "_resourceType": "fetch",
        "request": {"method": method, "url": url, "httpVersion": "HTTP/1.1", "cookies": [],
                    "headers": [{"name": n, "value": v} for n, v in req_headers],
                    "queryString": [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(q)],
                    "headersSize": -1, "bodySize": len(req_body or "")},
        "response": {"status": resp["status"], "statusText": resp["reason"], "httpVersion": "HTTP/1.1", "cookies": [],
                     "headers": [{"name": n, "value": v} for n, v in resp["headers"]],
                     "content": {"size": len(resp["body"]), "mimeType": ctype, "text": resp["body"]},
                     "redirectURL": next((v for n, v in resp["headers"] if n.lower() == "location"), ""),
                     "headersSize": -1, "bodySize": len(resp["body"])},
        "cache": {}, "timings": {"send": 0, "wait": ms, "receive": 0},
    }
    if req_body:
        entry["request"]["postData"] = {"mimeType": next((v for n, v in req_headers if n.lower() == "content-type"), ""),
                                        "text": req_body}
    return entry


def har_doc(entries):
    return {"log": {"version": "1.2", "creator": {"name": "browser-devtools", "version": "1"}, "pages": [],
                    "entries": entries}}


def read_har(path):
    with open(path) as f:
        return json.load(f)["log"]["entries"]


# --- signing in -------------------------------------------------------------

def login(app, url, user, password):
    """Signs in as the app's own SPA does; returns the 'Name: value' header that carries the session."""
    r = jcall("POST", url.rstrip("/") + app["auth"]["login"], obj={"username": user, "password": password})
    d = try_json(r["body"]) or {}
    s = app["auth"]["style"]
    if r["status"] != 200:
        raise RuntimeError("login failed for a role (status %d)" % r["status"])
    if s == "cookie":
        for n, v in r["headers"]:
            if n.lower() == "set-cookie":
                return "Cookie: " + v.split(";")[0]
        raise RuntimeError("no session cookie")
    if s == "header":
        return "%s: %s" % (app["auth"]["header"], d["api_key"])
    return "Authorization: Bearer " + (d["token"] if s == "bearer" else d["access_token"])


def item_path(template, item):
    p = template
    if "{org}" in p:
        p = p.replace("{org}", item["key"][0])
    return p.replace("{id}", item["key"][-1])


def read_count(path):
    try:
        return int(open(path).read().strip() or 0)
    except (OSError, ValueError):
        return 0
