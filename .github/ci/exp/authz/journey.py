#!/usr/bin/env python3
"""journey.py DIR URL --out HARDIR: the tester browsed the app.

As the admin and as the first user (alice), drives what the SPA does after
sign-in: reads, opens, edits and creates own objects, deletes a throwaway it
created, and for the admin the admin functions. Only the app's `journey`
routes are called. The capture is what a devtools Fetch/XHR filter keeps and
starts after sign-in, so the sign-in request is not in it. Writes admin.har,
alice.har (HAR 1.2, requests carry the session) and sessions.json (alice, bob
and admin: the header that carries each session). DIR holds app.json and
vars.json."""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib as z  # noqa: E402

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
ADMIN_OPS = ("approve", "export", "admin_users")


class Browser:
    def __init__(self, app, url, user, password):
        self.app, self.url = app, url.rstrip("/")
        self.session = z.login(app, self.url, user, password)
        self.user = user
        self.entries = []
        self.mine = {}

    def fetch(self, method, path, obj=None):
        body = json.dumps(obj, separators=(",", ":")) if obj is not None else None
        hs = [("Accept", "application/json, text/plain, */*"), ("User-Agent", UA), ("Referer", self.url + "/")]
        if body is not None:
            hs.append(("Content-Type", "application/json"))
            hs.append(("Origin", self.url))
        hs.append(z.parse_header(self.session))
        t = time.time()
        r = z.call(method, self.url + path, hs, body)
        ms = int((time.time() - t) * 1000)
        started = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + ".000Z"
        self.entries.append(z.har_entry(method, self.url + path, hs, body, r, started, ms))
        return r


def own_items(app, res, user):
    return [i for i in app["items"][res] if i["owner"] == user]


def path_for(rt, item):
    return z.item_path(rt["path"], item)


def drive(app, url, user, password, admin):
    b = Browser(app, url, user, password)
    routes = [r for r in app["routes"] if r["vis"] == "journey"]
    by_op = lambda *ops: [r for r in routes if r["op"] in ops]
    for rt in by_op("me"):
        b.fetch("GET", rt["path"])
    for rt in by_op("directory"):
        b.fetch("GET", rt["path"])
    for rt in by_op("admin_users") if admin else []:
        b.fetch("GET", rt["path"])
    created = {}
    for rt in routes:
        op, res = rt["op"], rt["res"]
        if op in ADMIN_OPS and not admin:
            continue
        if op in ("list", "feed", "export", "get", "sublist"):
            mine = own_items(app, res, user)
            if not mine and op == "sublist":
                continue
            p = path_for(rt, (mine or app["items"][res])[0])
            if op == "list" and rt.get("trust"):
                p += "?%s=%s" % (rt["trust"], user)
            b.fetch("GET", p)
    if admin:
        for rt in by_op("approve"):
            mine = own_items(app, rt["res"], user)
            if mine:
                b.fetch("POST", path_for(rt, mine[0]))
        return b
    for rt in by_op("me_patch"):
        b.fetch("PATCH", rt["path"], {"display_name": user.capitalize() + " R", "phone": "+1-555-0100"})
    for rt in by_op("prefs"):
        b.fetch("PATCH", rt["path"], {"theme": "dark", "locale": "en"})
    for rt in by_op("create"):
        res = rt["res"]
        mine = own_items(app, res, user)
        org = mine[0]["org"] if mine else "x"
        r = b.fetch("POST", rt["path"].replace("{org}", org), {"title": "scratch %s" % res, "status": "open",
                                                                 "amount": 1, "notes": "journey scratch"})
        d = z.try_json(r["body"]) or {}
        if isinstance(d, dict) and app["fields"]["id"] in d:
            created[res] = {"key": ([d["org"]] if "org" in d else []) + [str(d[app["fields"]["id"]])]}
    for rt in by_op("update"):
        mine = own_items(app, rt["res"], user)
        if mine:
            b.fetch(rt["method"], path_for(rt, mine[0]), {"title": "edited %s" % mine[0]["title"], "status": "pending"})
    for rt in by_op("delete"):
        if rt["res"] in created:
            b.fetch("DELETE", path_for(rt, created[rt["res"]]))
    return b


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("url")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    app = json.load(open(os.path.join(a.dir, "app.json")))
    accts = json.load(open(os.path.join(a.dir, "vars.json")))["accounts"]
    os.makedirs(a.out, exist_ok=True)
    sessions = {}
    n = 0
    for label in ("admin", "alice"):
        acc = accts[label]
        b = drive(app, a.url, acc["user"], acc["password"], label == "admin")
        sessions[label] = b.session
        with open(os.path.join(a.out, label + ".har"), "w") as f:
            json.dump(z.har_doc(b.entries), f, indent=1)
        n += len(b.entries)
    sessions["bob"] = z.login(app, a.url.rstrip("/"), accts["bob"]["user"], accts["bob"]["password"])
    with open(os.path.join(a.out, "sessions.json"), "w") as f:
        json.dump({k: sessions[k] for k in ("alice", "bob", "admin")}, f, indent=1)
    print("journey: %d requests captured" % n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
