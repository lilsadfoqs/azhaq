#!/usr/bin/env python3
"""selfcheck.py DIR URL: reproduces every flaw of DIR/key.json and checks every
negative against the live app at URL, with fresh sign-ins. Exit 1 when any
flaw does not reproduce or any negative misbehaves. Prints counts and the
opaque route ids that failed. DIR holds app.json, key.json and vars.json."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib as z  # noqa: E402


def expect_ok(resp, exp):
    body = resp["body"]
    st = resp["status"]
    if "status" in exp and st not in exp["status"]:
        return False
    if "status_class" in exp and st // 100 != exp["status_class"]:
        return False
    if "contains" in exp and exp["contains"] not in body:
        return False
    if "not_contains" in exp and exp["not_contains"] in body:
        return False
    if "json_eq" in exp:
        d = z.try_json(body)
        k, v = exp["json_eq"]
        if not isinstance(d, dict) or d.get(k) != v:
            return False
    return True


def run_steps(app, url, accts, steps):
    sess = {"anon": None}
    for label, a in accts.items():
        sess[label] = z.login(app, url, a["user"], a["password"])
    for s in steps:
        hs = []
        if sess[s["as"]]:
            hs.append(z.parse_header(sess[s["as"]]))
        r = z.jcall(s["method"], url.rstrip("/") + s["path"], hs, s.get("body"))
        if not expect_ok(r, s["expect"]):
            return False
    return True


def main(argv):
    d, url = argv[1], argv[2]
    app = json.load(open(os.path.join(d, "app.json")))
    key = json.load(open(os.path.join(d, "key.json")))
    accts = json.load(open(os.path.join(d, "vars.json")))["accounts"]
    flaws = [r for r in key["routes"] if r["class"] not in ("plain", "negative")]
    negs = [r for r in key["routes"] if r["class"] == "negative"]
    # the mass-assignment proof changes a session's role: last
    flaws.sort(key=lambda r: r["class"] == "mass-assignment")
    bad = []
    ok_n = ok_f = 0
    for r in negs:
        if run_steps(app, url, accts, r["proof"]):
            ok_n += 1
        else:
            bad.append(r["id"])
    for r in flaws:
        if run_steps(app, url, accts, r["proof"]):
            ok_f += 1
        else:
            bad.append(r["id"])
    print("selfcheck: %d/%d flaws reproduce, %d/%d negatives behave%s" % (
        ok_f, len(flaws), ok_n, len(negs), ("; failed: " + " ".join(bad)) if bad else ""))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
