#!/usr/bin/env python3
"""server.py DIR --port P [--host H]: serves the application DIR/app.json
describes. State is in memory and starts fresh at every start; session tokens
and new object ids are derived from the app's secret, so a restart gives the
same sessions and the same ids. Stdlib only."""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import sys
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib  # noqa: E402

JWT_HEAD = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class App:
    def __init__(self, spec, count_file=None):
        self.spec = spec
        self.lock = threading.Lock()
        self.count, self.count_file = 0, count_file
        self.f = spec["fields"]
        self.auth = spec["auth"]
        self.accounts = {a["user"]: dict(a) for a in spec["accounts"]}
        self.tokens = {}
        for a in self.accounts.values():
            a["token"] = self.make_token(a["user"])
            self.tokens[a["token"]] = a["user"]
        self.items = {p: [json.loads(json.dumps(i)) for i in its] for p, its in spec["items"].items()}
        # one stream per resource: a create elsewhere cannot shift the ids a resource hands out
        self.rng = {p: random.Random("%s:new:%s" % (spec["secret"], p)) for p in spec["items"]}
        self.index = {p: {tuple(i["key"]): i for i in its} for p, its in self.items.items()}
        self.routes = [(r, authzlib.template_re(r["path"]), authzlib.specificity(r["path"])) for r in spec["routes"]]
        self.routes.sort(key=lambda t: t[2], reverse=True)
        self.static = {"/": self.page_spa(), "/login": self.page_login(),
                       spec["static"]["bundle"]: spec["bundle"], spec["static"]["openapi"]: spec["openapi"]}

    # --- sessions ---------------------------------------------------------------
    def sig(self, text, n=40):
        return hmac.new(self.spec["secret"].encode(), text.encode(), hashlib.sha256).hexdigest()[:n]

    def make_token(self, user):
        s = self.auth["style"]
        if s == "jwt":
            payload = b64(json.dumps({"sub": user, "iss": self.spec["domain"], "iat": 1767225600}).encode())
            return "%s.%s.%s" % (JWT_HEAD, payload, b64(bytes.fromhex(self.sig(JWT_HEAD + "." + payload, 32))))
        if s == "header":
            return "ak_" + self.sig("key:" + user)
        return self.sig("tok:" + user)

    def actor(self, headers):
        s = self.auth["style"]
        tok = ""
        if s in ("bearer", "jwt"):
            h = headers.get("Authorization", "")
            tok = h[7:] if h.startswith("Bearer ") else ""
        elif s == "cookie":
            for part in headers.get("Cookie", "").split(";"):
                k, _, v = part.strip().partition("=")
                if k == self.auth["cookie"]:
                    tok = v
        else:
            tok = headers.get(self.auth["header"], "")
        u = self.tokens.get(tok)
        return self.accounts.get(u) if u else None

    # --- views ----------------------------------------------------------------------
    def idtext(self, item):
        return item["key"][-1]

    def view(self, res, item):
        st = self.spec["resources"][res]
        d = {self.f["id"]: self.idtext(item), self.f["owner"]: item["owner"], "title": item["title"],
             "status": item["status"], "amount": item["amount"], "notes": item["notes"], "approved": item["approved"]}
        if st["id_style"] == "nested":
            d["org"] = item["key"][0]
        if st["kind"] == "team":
            d["shared"] = item["shared"]
        return d

    def listed(self, rows):
        return rows if not self.f["list"] else {self.f["list"]: rows}

    def error(self, msg):
        return [{"error": msg}, {"status": "error", "message": msg}, {"success": False, "error": msg}][self.f["err"]]

    def refuse(self, style, rt, kind):
        msg = rt["umsg"] if kind == "unauth" else rt["msg"]
        if style == 401:
            return 401, {}, {"error": msg}
        if style == 403:
            return 403, {}, {"error": msg}
        if style == 404:
            return 404, {}, {"error": "not found"}
        if style == "200error":
            return 200, {}, self.error(msg)
        if style == "200empty":
            return 200, {}, self.listed([])
        return 302, {"Location": self.auth["form"]}, {}

    def not_found(self):
        return 404, {}, {"error": "not found"}

    def new_key(self, res, org):
        st = self.spec["resources"][res]["id_style"]
        used = {k[-1] for k in self.index[res]}
        if st == "int":
            m = max([int(k[-1]) for k in self.index[res]] or [100])
            return [str(m + 1)]
        if st == "uuid":
            return [str(uuid.UUID(int=self.rng[res].getrandbits(128), version=4))]
        if st == "slug":
            w = self.spec["words"]
            while True:
                s = "%s-%s-%d" % (self.rng[res].choice(w["adj"]), self.rng[res].choice(w["noun"]), self.rng[res].randint(10, 99))
                if s not in used:
                    return [s]
        m = max([int(k[-1]) for k in self.index[res] if k[0] == org] or [0])
        return [org, str(m + 1)]

    # --- the routes ---------------------------------------------------------------
    def match(self, method, path):
        allowed = []
        for rt, rx, _ in self.routes:
            m = rx.match(path)
            if m:
                if rt["method"] == method:
                    return rt, m
                allowed.append(rt["method"])
        return None, allowed

    def tick(self):
        with self.lock:
            self.count += 1
            if self.count_file:
                with open(self.count_file, "w") as f:
                    f.write(str(self.count))

    def handle(self, method, path, query, headers, body):
        self.tick()
        if method == "GET" and path in self.static:
            v = self.static[path]
            if path == "/" or path == "/login":
                return 200, {"Content-Type": "text/html; charset=utf-8"}, v
            if path == self.spec["static"]["bundle"]:
                return 200, {"Content-Type": "application/javascript"}, v
            return 200, {}, v
        rt, m = self.match(method, path)
        if rt is None:
            if m:
                return 405, {"Allow": ", ".join(sorted(set(m)))}, {"error": "method not allowed"}
            return self.not_found()
        params = self.params(rt["path"], path)
        actor = self.actor(headers)
        with self.lock:
            return self.dispatch(rt, params, query, body, actor)

    def params(self, template, path):
        out = {}
        for t, p in zip(template.strip("/").split("/"), path.strip("/").split("/")):
            if t.startswith("{"):
                out[t.strip("{}")] = p
        return out

    def dispatch(self, rt, params, q, body, actor):
        op = rt["op"]
        if op == "login":
            return self.op_login(rt, body)
        if rt["auth"] != "none" and actor is None:
            return self.refuse(rt["unauth"], rt, "unauth")
        if rt["auth"] == "admin" and actor["role"] != "admin":
            return self.refuse(rt["deny"], rt, "deny")
        return getattr(self, "op_" + op)(rt, params, q, body, actor)

    def op_login(self, rt, body):
        u = self.accounts.get(str(body.get("username", "")))
        if not u or u["password"] != body.get("password"):
            return 401, {}, {"error": "invalid credentials"}
        s = self.auth["style"]
        hdr = {}
        if s == "cookie":
            hdr["Set-Cookie"] = "%s=%s; Path=/; HttpOnly" % (self.auth["cookie"], u["token"])
            return 200, hdr, {"ok": True, "user": u["user"]}
        return 200, hdr, {"bearer": {"token": u["token"]}, "jwt": {"access_token": u["token"], "token_type": "bearer"},
                          "header": {"api_key": u["token"]}}[s]

    def profile(self, a):
        return {"user": a["user"], "display_name": a["display_name"], "email": a["email"], "phone": a["phone"],
                "org": a["org"], "role": a["role"], "is_admin": a["role"] == "admin", "credit": a["credit"],
                "theme": a.get("theme", "light")}

    def op_me(self, rt, params, q, body, actor):
        return 200, {}, self.profile(actor)

    def op_me_patch(self, rt, params, q, body, actor):
        for k in ["display_name", "phone"] + rt.get("mass", []):
            if k in body:
                if k == "is_admin":
                    actor["role"] = "admin" if body[k] else "user"
                else:
                    actor[k] = body[k]
        return 200, {}, self.profile(actor)

    def op_prefs(self, rt, params, q, body, actor):
        for k in ("theme", "locale"):
            if k in body:
                actor[k] = body[k]
        return 200, {}, self.profile(actor)

    def op_directory(self, rt, params, q, body, actor):
        rows = []
        for a in self.accounts.values():
            d = {"user": a["user"], "display_name": a["display_name"], "org": a["org"]}
            if rt.get("expose"):
                d.update({"email": a["email"], "phone": a["phone"], "address": a["address"], "api_token": a["api_token"]})
            rows.append(d)
        return 200, {}, self.listed(rows)

    def op_admin_users(self, rt, params, q, body, actor):
        rows = [{"user": a["user"], "role": a["role"], "email": a["email"], "phone": a["phone"],
                 "address": a["address"], "api_token": a["api_token"]} for a in self.accounts.values()]
        return 200, {}, self.listed(rows)

    def find(self, res, params):
        key = (params["org"], params["id"]) if "org" in params else (params["id"],)
        it = self.index[res].get(key)
        return it if it and not it["deleted"] else None

    def allowed(self, rt, item, actor):
        g = rt["guard"]
        if g in ("none", "public"):
            return True
        if actor is None:
            return False
        if g == "shared":
            return item["owner"] == actor["user"] or item["shared"]
        return item["owner"] == actor["user"]

    def op_list(self, rt, params, q, body, actor):
        res = rt["res"]
        rows = [i for i in self.items[res] if not i["deleted"]]
        if rt["guard"] == "public":
            rows = [i for i in rows if i["public"]]
        elif rt["guard"] == "shared":
            rows = [i for i in rows if i["owner"] == actor["user"] or i["shared"]]
        else:
            who = actor["user"]
            if rt.get("trust") and q.get(rt["trust"]):
                who = q[rt["trust"]][0]
            if "org" in params and params["org"] != actor["org"] and rt.get("trust") is None:
                return self.refuse(rt["deny"], rt, "deny")
            rows = [i for i in rows if i["owner"] == who]
            if "org" in params:
                rows = [i for i in rows if i["key"][0] == params["org"]]
        return 200, {}, self.listed([self.view(res, i) for i in rows])

    def op_feed(self, rt, params, q, body, actor):
        res = rt["res"]
        return 200, {}, self.listed([self.view(res, i) for i in self.items[res] if not i["deleted"]])

    def op_export(self, rt, params, q, body, actor):
        return self.op_feed(rt, params, q, body, actor)

    def op_get(self, rt, params, q, body, actor):
        it = self.find(rt["res"], params)
        if it is None:
            return self.not_found()
        if not self.allowed(rt, it, actor):
            return self.refuse(rt["deny"], rt, "deny")
        return 200, {}, self.view(rt["res"], it)

    def op_sublist(self, rt, params, q, body, actor):
        it = self.find(rt["res"], params)
        if it is None:
            return self.not_found()
        if not self.allowed(rt, it, actor):
            return self.refuse(rt["deny"], rt, "deny")
        return 200, {}, self.listed(it["children"])

    def op_create(self, rt, params, q, body, actor):
        res = rt["res"]
        org = params.get("org", actor["org"])
        if org != actor["org"]:
            return self.refuse(rt["deny"], rt, "deny")
        it = {"key": self.new_key(res, org), "owner": actor["user"], "org": org,
              "title": str(body.get("title", "untitled")), "status": str(body.get("status", "open")),
              "amount": body.get("amount", 0) if isinstance(body.get("amount", 0), int) else 0,
              "notes": str(body.get("notes", "")), "approved": False, "deleted": False, "shared": False,
              "public": False, "children": []}
        self.items[res].append(it)
        self.index[res][tuple(it["key"])] = it
        return 201, {}, self.view(res, it)

    def op_update(self, rt, params, q, body, actor):
        it = self.find(rt["res"], params)
        if it is None:
            return self.not_found()
        if not self.allowed(rt, it, actor):
            return self.refuse(rt["deny"], rt, "deny")
        for k in ("title", "status", "notes"):
            if k in body:
                it[k] = str(body[k])
        if isinstance(body.get("amount"), int):
            it["amount"] = body["amount"]
        return 200, {}, self.view(rt["res"], it)

    def op_delete(self, rt, params, q, body, actor):
        it = self.find(rt["res"], params)
        if it is None:
            return self.not_found()
        if not self.allowed(rt, it, actor):
            return self.refuse(rt["deny"], rt, "deny")
        it["deleted"] = True
        return 200, {}, {"deleted": True, self.f["id"]: self.idtext(it)}

    def op_approve(self, rt, params, q, body, actor):
        it = self.find(rt["res"], params)
        if it is None:
            return self.not_found()
        it["approved"] = True
        return 200, {}, self.view(rt["res"], it)

    # --- pages ----------------------------------------------------------------------
    def page_spa(self):
        return ('<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head><body>'
                '<div id="app"></div><a href="/login">Sign in</a><script src="%s"></script></body></html>'
                % (self.spec["domain"], self.spec["static"]["bundle"]))

    def page_login(self):
        s = self.auth["style"]
        store = {"bearer": 'localStorage.setItem("tok",d.token)', "jwt": 'localStorage.setItem("jwt",d.access_token)',
                 "cookie": "", "header": 'localStorage.setItem("key",d.api_key)'}[s]
        return ('<!doctype html><html><head><meta charset="utf-8"><title>Sign in</title></head><body>'
                '<form id="f"><input name="username"><input name="password" type="password"><button>Sign in</button></form>'
                '<script>document.getElementById("f").onsubmit=async e=>{e.preventDefault();const x=new FormData(e.target);'
                'const r=await fetch("%s",{method:"POST",headers:{"Content-Type":"application/json"},'
                'body:JSON.stringify({username:x.get("username"),password:x.get("password")})});const d=await r.json();%s;'
                'location="/"}</script></body></html>' % (self.auth["login"], store))


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def serve(self):
            u = urllib.parse.urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n).decode("utf-8", "replace") if n else ""
            body = {}
            if raw:
                if "json" in (self.headers.get("Content-Type") or "") or raw[:1] in "{[":
                    try:
                        body = json.loads(raw)
                    except ValueError:
                        body = {}
                else:
                    body = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
            if not isinstance(body, dict):
                body = {}
            status, hdr, out = app.handle(self.command, u.path, urllib.parse.parse_qs(u.query), self.headers, body)
            if isinstance(out, (dict, list)):
                data = json.dumps(out).encode()
                hdr.setdefault("Content-Type", "application/json")
            else:
                data = out.encode()
                hdr.setdefault("Content-Type", "text/plain")
            self.send_response(status)
            for k, v in hdr.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = serve

    return H


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dir")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--count-file", help="keep the number of requests served here (the arms' request counts)")
    a = ap.parse_args(argv)
    with open(os.path.join(a.dir, "app.json")) as f:
        app = App(json.load(f), a.count_file)
    srv = ThreadingHTTPServer((a.host, a.port), make_handler(app))
    srv.daemon_threads = True
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
