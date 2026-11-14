#!/usr/bin/env python3
"""b1.py --azhaq BIN --url URL --har-dir DIR --out OUT (arm B1): the documented azhaq roles command,
no agent. Roles anon, alice, bob and admin with the session header of each (sessions.json), the two
captures with -har, the writes replayed (docs/commands/roles.md: post,put,patch; delete is named too,
as that page says to delete objects), JSON lines out, and the run option -url after --. Every other
flag is left at its default. Writes OUT/b1.jsonl, OUT/b1.stderr.txt and OUT/meta.json (wall time,
requests as the summary counts them, exit code)."""
import argparse
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib as z  # noqa: E402


def command(azhaq, url, har_dir, sessions, canary=False):
    cmd = [azhaq, "roles", "-role", "anon"]
    for label in ("alice", "bob", "admin"):
        cmd += ["-role", "%s=%s" % (label, sessions[label])]
    cmd += ["-har", "alice=" + os.path.join(har_dir, "alice.har"), "-har", "admin=" + os.path.join(har_dir, "admin.har"),
            "-replay-writes", "post,put,patch,delete"]
    # B1c: the documented fix for a replay that writes back a value already there (roles.md, Canary values)
    if canary:
        cmd += ["-replay-writes-canary"]
    cmd += ["-jsonl", "--", "-url", url]
    return cmd


def summary_requests(stderr):
    """The summary is JSON on stderr under -json/-jsonl; take `requests` from it."""
    for chunk in [stderr] + stderr.strip().splitlines()[::-1]:
        try:
            d = json.loads(chunk)
        except ValueError:
            continue
        if isinstance(d, dict):
            r = d.get("requests")
            if isinstance(r, dict):
                r = r.get("sent", r.get("total"))
            if isinstance(r, int):
                return r
    return None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--azhaq", required=True)
    ap.add_argument("--url", required=True)
    ap.add_argument("--har-dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--count-file", help="the app's request counter (server.py --count-file)")
    ap.add_argument("--canary", action="store_true", help="arm B1c: add -replay-writes-canary")
    a = ap.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    sessions = z.load_sessions(os.path.join(a.har_dir, "sessions.json"))
    cmd = command(os.path.abspath(a.azhaq), a.url, os.path.abspath(a.har_dir), sessions, a.canary)
    c0 = z.read_count(a.count_file) if a.count_file else 0
    t0 = time.time()
    p = subprocess.run(cmd, cwd=a.out, capture_output=True, text=True)
    wall = round(time.time() - t0, 2)
    open(os.path.join(a.out, "b1.jsonl"), "w").write(p.stdout)
    open(os.path.join(a.out, "b1.stderr.txt"), "w").write(p.stderr)
    meta = {"wall_seconds": wall, "requests": summary_requests(p.stderr), "exit": p.returncode}
    if a.count_file:
        meta["server_requests"] = z.read_count(a.count_file) - c0
    json.dump(meta, open(os.path.join(a.out, "meta.json"), "w"))
    rows = [ln for ln in p.stdout.splitlines() if ln.strip()]
    print("b1%s: exit %d, %d rows, %.1fs" % ("c" if a.canary else "", p.returncode, len(rows), wall))
    return 0


if __name__ == "__main__":
    sys.exit(main())
