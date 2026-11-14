#!/usr/bin/env python3
"""settle.py EST OUT: waits until the estate has settled, before any arm of an
epoch runs. Over every environment that is up now (direct or behind the proxy)
and the deploy app:
  1. every TCP port the key lists for the host accepts a connection (a proxied
     name: the proxy's port 80);
  2. its front page (GET /, direct, or through the proxy with the Host header)
     gives the same status and the same <title> on two fetches at least 30 s
     apart.
All are polled at once; the whole step is capped (default 6 minutes). One that
does not settle does not fail anything: OUT/settle.json holds counts only
(environments, settled, the reasons of the others, seconds) and so does the log.
The grader does not read it; summary.py shows settled/total as context.
"""
import concurrent.futures
import http.client
import os
import re
import socket
import ssl
import sys
import time

import driftlib as dl
import rangelib

GAP = 30
CAP = 360
TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def settle_env(ports_ok, fetch, clock, sleep, deadline, gap=GAP, poll=3):
    """(settled, reason). ports_ok() -> bool; fetch() -> (status, title) or None, or
    fetch is None for an environment with no front page. Reasons: port, front, unstable."""
    reason = "port"
    prev = prev_at = None
    while True:
        if not ports_ok():
            reason, prev = "port", None
        elif fetch is None:
            return True, ""
        else:
            cur = fetch()
            if cur is None:
                reason, prev = "front", None
            elif prev is not None and cur == prev and clock() - prev_at >= gap:
                return True, ""
            elif prev is not None and cur != prev:
                reason, prev, prev_at = "unstable", cur, clock()
            elif prev is None:
                prev, prev_at = cur, clock()
        now = clock()
        if now >= deadline:
            return False, reason
        # Between two fetches wait out the gap; otherwise poll.
        step = max(poll, prev_at + gap - now) if prev is not None else poll
        sleep(min(step, max(deadline - now, 0.1)))


def tcp_ok(addr, port, timeout=3):
    try:
        socket.create_connection((addr, port), timeout=timeout).close()
        return True
    except OSError:
        return False


def front(addr, port, scheme="http", host=None, timeout=5):
    """(status, title) of GET /, no redirect followed; None when nothing answers."""
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            c = http.client.HTTPSConnection(addr, port, timeout=timeout, context=ctx)
        else:
            c = http.client.HTTPConnection(addr, port, timeout=timeout)
        c.request("GET", "/", headers={"Host": host or addr, "User-Agent": "range-probe", "Accept": "*/*"})
        r = c.getresponse()
        body = r.read(65536)
        c.close()
        m = TITLE.search(body)
        return r.status, re.sub(r"\s+", " ", m.group(1).decode("utf-8", "replace")).strip() if m else ""
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return None


def targets(est):
    """One target per thing that must answer: (label, [(addr, port)], fetch spec or None)."""
    live = dl.load_json(os.path.join(est, "live.json"))["model"]
    key = dl.load_json(os.path.join(est, "key.json"))
    ents = dl.by_id(rangelib.load_catalog())
    down = {h["env"] for h in key["estates"][0]["hosts"] if h.get("env") and h.get("up") is False}
    proxy = live["proxy"]["address"]
    out = []
    for eid, e in live["envs"].items():
        if eid in down:
            continue
        ent = ents[eid]
        remap = {int(k): v for k, v in e["remap"].items()}
        prim = dl.primary(ent)
        if e.get("backend"):
            host = next((r[0] for r in live["routes"] if r[2] == e["address"]), None)
            out.append((eid, [(proxy, 80)], ("http", proxy, 80, host) if host else None))
            continue
        ports = [(e["address"], remap.get(p["host_port"], p["host_port"])) for p in ent["ports"] if p["transport"] == "tcp"]
        pport = remap.get(prim["host_port"], prim["host_port"])
        spec = (prim["protocol"], e["address"], pport, None) if prim["protocol"] in ("http", "https") else None
        out.append((eid, ports, spec))
    d = live["deploy"]
    out.append(("deploy", [(d["address"], d["port"])], ("http", d["address"], d["port"], None)))
    return out


def run(est, out, cap=CAP, gap=GAP, clock=time.time, sleep=time.sleep, tcp=tcp_ok, fetcher=front):
    t0 = clock()
    deadline = t0 + cap
    tg = targets(est)

    def one(t):
        _, ports, spec = t
        fetch = None if spec is None else (lambda s=spec: fetcher(s[1], s[2], s[0], s[3]))
        return settle_env(lambda: all(tcp(a, p) for a, p in ports), fetch, clock, sleep, deadline, gap)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(tg))) as ex:
        res = list(ex.map(one, tg))
    reasons = {}
    for ok, why in res:
        if not ok:
            reasons[why] = reasons.get(why, 0) + 1
    doc = {"envs": len(res), "settled": sum(1 for ok, _ in res if ok), "not_settled": reasons, "seconds": round(clock() - t0, 1)}
    os.makedirs(out, exist_ok=True)
    dl.save_json(os.path.join(out, "settle.json"), doc)
    print("settle: %d of %d settled%s in %ss" % (doc["settled"], doc["envs"], (", not: " + ", ".join("%s %d" % kv for kv in sorted(reasons.items()))) if reasons else "", doc["seconds"]))
    return doc


if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2])
