#!/usr/bin/env python3
"""autorize.py --url URL --sessions sessions.json --har FILE=ROLE ... --out OUT.jsonl [--meta META.json]
(arm B2) The logic of PortSwigger's Autorize, without Burp, over HAR files.

Followed, from github.com/PortSwigger/autorize (master):
  Autorize.py, gui/configuration_tab.py   the three verdict strings; "Ignore 304/204 responses" on
  gui/interception_filters.py             the default filters: URL Not Contains (regex) for static
                                          extensions, ignore spider requests, ignore OPTIONS
  authorization/authorization.py          checkAuthorizationAllUsers: every captured request is replayed
                                          once with the user's headers in place of the original session
                                          headers and once with them removed; makeUserMessage removes the
                                          headers the replacement text names, then appends the text;
                                          checkBypass: a different status line is Enforced!; the same
                                          status line is Enforced! when an enforcement detector matches
                                          (auth_enforced_via_enforcement_detectors), else Bypassed! when
                                          the bodies are equal, else Is enforced???
  helpers/http.py                         makeMessage

The detector is the one a tester sets (Or of): status code 401, 403; body regex
unauthorized|forbidden|denied|login, case-insensitive. Writes are replayed as Autorize does.

One difference from Burp, forced by replaying a file: Autorize sees each response live, while a HAR
has them as of the capture. Each captured request is therefore sent first as recorded, on an app
restarted in the state the capture started from, in the capture's order, and that answer is the
original the variants are compared with. Static files are not in the HAR (devtools Fetch/XHR)."""
import argparse
import json
import re
import sys
import time
import os
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib as z  # noqa: E402

BYPASSED = "Bypassed!"
IS_ENFORCED = "Is enforced???"
ENFORCED = "Enforced!"
# interception_filters.py line 69
STATIC = re.compile(r"(\.js|\.css|\.png|\.jpg|\.svg|\.jpeg|\.gif|\.woff|\.map|\.bmp|\.ico)(?![a-z]+)[?]*[\S]*$", re.I)
BODY_DETECT = re.compile(r"unauthorized|forbidden|denied|login", re.I)
STATUS_DETECT = ("401", "403")
SKIP_HEADERS = {"host", "content-length", "connection", "accept-encoding"}


def status_line(r):
    return "HTTP/1.1 %d %s" % (r["status"], r["reason"])


def detector_matches(line, body):
    # Autorize tests "Status code equals" as a substring of the status line (isStatusCodesReturned)
    return any(c in line for c in STATUS_DETECT) or bool(BODY_DETECT.search(body))


def check_bypass(old_line, new_line, old_body, new_body):
    """authorization.py checkBypass."""
    if old_line == new_line:
        if detector_matches(new_line, new_body):
            return ENFORCED
        return BYPASSED if old_body == new_body else IS_ENFORCED
    return ENFORCED


def make_headers(recorded, drop_names, add_header=None):
    """makeUserMessage / makeMessage: remove the headers the text names, then append it."""
    drop = {n.lower() for n in drop_names}
    hs = [(h["name"], h["value"]) for h in recorded if h["name"].lower() not in SKIP_HEADERS and h["name"].lower() not in drop]
    if add_header:
        hs.append(z.parse_header(add_header))
    return hs


def passes_filters(entry):
    url, method = entry["request"]["url"], entry["request"]["method"]
    return not STATIC.search(url) and method != "OPTIONS"


def run(base, sessions, hars, meta=None):
    names = {z.parse_header(v)[0] for v in sessions.values()}
    rows, n = [], 0
    base = base.rstrip("/")
    t0 = time.time()
    for har, role in hars:
        for e in z.read_har(har):
            if not passes_filters(e):
                continue
            q = e["request"]
            u = urllib.parse.urlsplit(q["url"])
            url = base + u.path + ("?" + u.query if u.query else "")
            body = q.get("postData", {}).get("text")

            def send(headers):
                nonlocal n
                n += 1
                try:
                    return z.call(q["method"], url, headers, body)
                except OSError:
                    return None

            orig = send(make_headers(q["headers"], []))
            if orig is None or orig["status"] in (304, 204):
                continue  # ignore304
            variants = (("user", make_headers(q["headers"], [z.parse_header(sessions[role])[0]], sessions[role])),
                        ("unauth", make_headers(q["headers"], names)))
            for name, hs in variants:
                r = send(hs)
                if r is None:
                    continue
                rows.append({"har": os.path.basename(har), "role": role, "variant": name, "method": q["method"],
                             "url": url, "original": status_line(orig), "status": status_line(r),
                             "verdict": check_bypass(status_line(orig), status_line(r), orig["body"], r["body"])})
    if meta is not None:
        meta.update({"requests": n, "wall_seconds": round(time.time() - t0, 2)})
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", required=True)
    ap.add_argument("--sessions", required=True)
    ap.add_argument("--har", action="append", required=True, help="FILE=ROLE: replay FILE with ROLE's session")
    ap.add_argument("--out", required=True)
    ap.add_argument("--meta")
    ap.add_argument("--count-file", help="the app's request counter (server.py --count-file)")
    a = ap.parse_args(argv)
    sessions = z.load_sessions(a.sessions)
    hars = [tuple(x.rsplit("=", 1)) for x in a.har]
    meta = {}
    c0 = z.read_count(a.count_file) if a.count_file else 0
    rows = run(a.url, sessions, hars, meta)
    if a.count_file:
        meta["server_requests"] = z.read_count(a.count_file) - c0
    with open(a.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    if a.meta:
        json.dump(meta, open(a.meta, "w"))
    c = {}
    for r in rows:
        c[r["verdict"]] = c.get(r["verdict"], 0) + 1
    print("autorize: %d rows, %d requests, %s" % (len(rows), meta["requests"], c))
    return 0


if __name__ == "__main__":
    sys.exit(main())
