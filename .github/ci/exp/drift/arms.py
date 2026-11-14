#!/usr/bin/env python3
"""arms.py a1|a2 VARS OUT EPOCH --work DIR ...: the two agent-free arms of
experiment A, one run each per epoch, on the live estate, read-only.

  a1  azhaq watch -db DB -json -- <the run flags of parity/replay.sh>
      The workspace DB is kept in WORK/a1, so each epoch is compared with the
      one before; E0 is the baseline. stdout (the change set) -> OUT/a1.json,
      stderr (with the run's summary) -> OUT/a1.err.
  a2  the cron pipe hunters run, each stage's output through anew:
        dnsx -> naabu (the names, and the /24) -> httpx -> nuclei (tech)
      Every tool is given the estate's resolver (-r), as a hunter's config would.
      OUT/a2/full/STAGE.txt is the whole output, OUT/a2/alerts/STAGE.txt what
      anew printed as new (the alert), OUT/a2/diff/STAGE.new|.gone the whole
      outputs diffed against the epoch before (A2-diff: no extra requests).
Both write OUT/aN.meta.json: wall seconds, exit codes, what the kernel counted
on the wire (driftlib.counters) and, for a1, the run summary's requests.
VARS is range/vars.json (DOMAIN1, NET1, DNS1). Nothing is printed but counts.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

import driftlib as dl

# The run flags of .github/ci/parity/replay.sh, as the documented flow gives them (test_drift.py keeps them equal).
A1_FLAGS = ["-domain", "{domain}", "-cidr", "{net}", "-allow", "{domain}", "-allow", "{net}", "-resolvers", "{dns}", "-ports", "default", "-verify"]
STAGES = ["dnsx", "naabu", "httpx", "nuclei"]


def read_counters():
    return dl.counters_read()


def summary_requests(err_text):
    """The run's summary on stderr (JSON lines with -json): its requests and seconds."""
    best = None
    for line in err_text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if o.get("type") == "summary" and o.get("command") == "run":
            best = {"requests": o.get("requests"), "seconds": o.get("seconds"), "exit": o.get("exit")}
    return best


def a1(vars_, out, epoch, work, azhaq, minutes=25, run=subprocess.run):
    os.makedirs(out, exist_ok=True)
    wd = os.path.join(work, "a1")
    os.makedirs(wd, exist_ok=True)
    flags = [f.format(domain=vars_["DOMAIN1"], net=vars_["NET1"], dns=vars_["DNS1"]) for f in A1_FLAGS]
    cap = minutes * 60
    cmd = [azhaq, "watch", "-db", os.path.join(wd, "watch.db"), "-json", "--"] + flags + ["-max-time", "%ds" % cap]
    c0, t0 = read_counters(), time.monotonic()
    with open(os.path.join(out, "a1.json"), "w") as so, open(os.path.join(out, "a1.err"), "w") as se:
        try:
            rc = run(cmd, cwd=wd, stdout=so, stderr=se, stdin=subprocess.DEVNULL, timeout=cap + 180).returncode
        except subprocess.TimeoutExpired:
            rc = 124
    secs = round(time.monotonic() - t0, 1)
    c1 = read_counters()
    with open(os.path.join(out, "a1.err")) as f:
        s = summary_requests(f.read())
    meta = {"arm": "a1", "epoch": epoch, "seconds": secs, "exit": rc, "wire": dl.counters_delta(c0, c1), "summary": s}
    dl.save_json(os.path.join(out, "a1.meta.json"), meta)
    print("a1 epoch %d: exit %d" % (epoch, rc))
    return 0 if rc in (0, 4) else 1


def stage_cmd(stage, vars_, wordlist, full, resolvers):
    d, net, dns = vars_["DOMAIN1"], vars_["NET1"], vars_["DNS1"]
    if stage == "dnsx":
        return "dnsx -d %s -w %s -r %s -silent" % (d, wordlist, dns)
    if stage == "naabu":
        # The names found, and the /24 itself.
        hosts = os.path.join(full, "dnsx.txt")
        named = "naabu -list %s -top-ports 1000 -silent -r %s; " % (hosts, dns) if os.path.getsize(hosts) else ""
        return "{ %snaabu -host %s -top-ports 1000 -silent; }" % (named, net)
    if stage == "httpx":
        return "httpx -l %s -sc -title -td -silent -nc -r %s" % (os.path.join(full, "naabu.txt"), resolvers)
    if stage == "nuclei":
        return "nuclei -l %s -tags tech -silent -nc -duc -r %s" % (os.path.join(full, "urls.txt"), resolvers)
    raise ValueError(stage)


def lines(path):
    try:
        with open(path, errors="replace") as f:
            return [x.rstrip("\n") for x in f if x.strip()]
    except OSError:
        return []


def a2(vars_, out, epoch, work, tools, wordlist, prev=None, run=subprocess.run):
    a2d = os.path.join(out, "a2")
    full, alerts, diff = (os.path.join(a2d, x) for x in ("full", "alerts", "diff"))
    state = os.path.join(work, "a2", "state")
    for p in (full, alerts, diff, state):
        os.makedirs(p, exist_ok=True)
    env = dict(os.environ, PATH=tools + os.pathsep + os.environ.get("PATH", ""))
    # The estate's names exist only in its resolver: each tool is told it (as a hunter's config would).
    resolvers = os.path.join(a2d, "resolvers.txt")
    with open(resolvers, "w") as f:
        f.write(vars_["DNS1"] + "\n")
    rcs, stage_s = {}, {}
    c0, t0 = read_counters(), time.monotonic()
    for st in STAGES:
        if st == "nuclei":
            urls = sorted({x.split()[0] for x in lines(os.path.join(full, "httpx.txt"))})
            with open(os.path.join(full, "urls.txt"), "w") as f:
                f.write("".join(u + "\n" for u in urls))
            if not urls:
                open(os.path.join(full, "nuclei.txt"), "w").close()
                open(os.path.join(alerts, "nuclei.txt"), "w").close()
                rcs[st] = 0
                continue
        # Each stage's whole output is kept (the next stage reads it); anew prints only what is new.
        pipe = "set -o pipefail; %s 2> %s | sort -u | tee %s | anew %s > %s" % (
            stage_cmd(st, vars_, wordlist, full, resolvers), os.path.join(a2d, st + ".err"), os.path.join(full, st + ".txt"),
            os.path.join(state, st + ".txt"), os.path.join(alerts, st + ".txt"))
        ts = time.monotonic()
        rcs[st] = run(["bash", "-c", pipe], env=env, stdin=subprocess.DEVNULL, timeout=3600).returncode
        stage_s[st] = round(time.monotonic() - ts, 1)
    secs = round(time.monotonic() - t0, 1)
    c1 = read_counters()
    for st in STAGES:
        now = set(lines(os.path.join(full, st + ".txt")))
        if prev:
            before = set(lines(os.path.join(prev, "a2", "full", st + ".txt")))
            for ext, vals in (("new", now - before), ("gone", before - now)):
                with open(os.path.join(diff, "%s.%s" % (st, ext)), "w") as f:
                    f.write("".join(v + "\n" for v in sorted(vals)))
    meta = {"arm": "a2", "epoch": epoch, "seconds": secs, "stage_seconds": stage_s, "exit": rcs, "words": len(lines(wordlist)),
            "wire": dl.counters_delta(c0, c1)}
    dl.save_json(os.path.join(out, "a2.meta.json"), meta)
    print("a2 epoch %d: stages exit %s" % (epoch, ",".join(str(rcs[s]) for s in STAGES)))
    return 0 if all(rcs[s] == 0 for s in STAGES) else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("arm", choices=("a1", "a2"))
    ap.add_argument("vars")
    ap.add_argument("out")
    ap.add_argument("epoch", type=int)
    ap.add_argument("--work", required=True)
    ap.add_argument("--azhaq", default="azhaq")
    ap.add_argument("--minutes", type=int, default=25)
    ap.add_argument("--tools", default="/opt/tools/bin")
    ap.add_argument("--wordlist", default=os.path.join(dl.REPO, "internal", "collectors", "brutecol", "words", "subdomains-top1million-5000.txt"))
    ap.add_argument("--prev", help="the previous epoch's OUT (a2: the diff)")
    a = ap.parse_args(argv)
    v = dl.load_json(a.vars)
    if a.arm == "a1":
        return a1(v, a.out, a.epoch, a.work, a.azhaq, a.minutes)
    return a2(v, a.out, a.epoch, a.work, a.tools, a.wordlist, a.prev)


if __name__ == "__main__":
    sys.exit(main())
