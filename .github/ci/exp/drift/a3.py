#!/usr/bin/env python3
"""a3.py VARS OUT EPOCH: one Codex session of arm A3 (an agent re-checking the
estate with the usual stack), run as the isolated user (agent-user.sh).

The session runs gpt-6-luna at xhigh effort in the user's own folder, whose
./notes carries over from check to check. E0 gets 60 minutes, later checks 30.
The brief is BRIEF.md with the estate's domain, range and resolver, plus the
number of the check and its budget; it names no experiment, key or count.
Afterwards the folder (notes, the checks' files) is copied to OUT/a3/ and
OUT/a3.meta.json holds the wall seconds, the stream's tokens and the wire
counts. The timestamped stream is OUT/a3/stream.ts.jsonl.gz.
Prints nothing of the session.
"""
import argparse
import gzip
import json
import os
import shutil
import subprocess
import sys
import time

import driftlib as dl

USER = "analyst"
HOME = "/home/" + USER
WORK = HOME + "/trial"
MINUTES = {0: 60}


def minutes_for(epoch):
    return MINUTES.get(epoch, 30)


def render(vars_):
    text = open(os.path.join(dl.HERE, "BRIEF.md"), encoding="utf-8").read()
    for k, v in (("DOMAIN", vars_["DOMAIN1"]), ("NET", vars_["NET1"]), ("DNS", vars_["DNS1"])):
        text = text.replace("{{%s}}" % k, v)
    return text


def prompt(vars_, epoch):
    first = "This is the first check (E0): build the baseline." if epoch == 0 else \
        "This check is E%d: write ./changes-E%d.jsonl. Your notes are in ./notes." % (epoch, epoch)
    return "%s\n\n## This check\n\n%s Budget: %d minutes; the check ends then." % (render(vars_), first, minutes_for(epoch))


def tokens_of(stream_lines):
    """Input, cached input, output and reasoning tokens summed over the stream's turn.completed events."""
    tot = {"input": 0, "cached": 0, "output": 0, "reasoning": 0, "turns": 0}
    for line in stream_lines:
        i = line.find("{")
        if i < 0:
            continue
        try:
            o = json.loads(line[i:])
        except ValueError:
            continue
        if o.get("type") != "turn.completed":
            continue
        u = o.get("usage") or {}
        tot["turns"] += 1
        tot["input"] += int(u.get("input_tokens") or 0)
        tot["cached"] += int(u.get("cached_input_tokens") or 0)
        tot["output"] += int(u.get("output_tokens") or 0)
        tot["reasoning"] += int(u.get("reasoning_output_tokens") or 0)
    return tot


def clean_path():
    home = os.path.expanduser("~")
    keep = [p for p in os.environ.get("PATH", "").split(os.pathsep) if p and not p.startswith(home)]
    return os.pathsep.join(["/opt/tools/bin"] + keep)


def sudo(cmd, **kw):
    return subprocess.run(["sudo", "-n"] + cmd, **kw)


def run(vars_, out, epoch, popen=subprocess.Popen):
    a3d = os.path.join(out, "a3")
    os.makedirs(a3d, exist_ok=True)
    mins = minutes_for(epoch)
    codex = shutil.which("codex")
    if not codex:
        raise SystemExit("codex is not installed")
    cmd = ["sudo", "-n", "-u", USER, "env", "HOME=" + HOME, "CODEX_HOME=" + HOME + "/.codex", "PATH=" + clean_path(),
           "timeout", "-k", "30", "%dm" % (mins + 3), codex, "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check",
           "-C", WORK, "-m", "gpt-6-luna", "-c", "model_reasoning_effort=xhigh", "--json", prompt(vars_, epoch)]
    c0, t0 = dl.counters_read(), time.monotonic()
    # Readable by the heartbeat (which reads as the user), writable by no one but this process.
    live = HOME + "/ci/stream.ts.jsonl"
    lines = []
    with open(os.path.join(out, "a3.stderr"), "w") as se, open(live, "a") as lf:
        p = popen(cmd, cwd="/", stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=se, text=True, errors="replace")
        for line in p.stdout:
            row = "%d %s" % (int(time.time()), line.rstrip("\n"))
            lines.append(row)
            lf.write(row + "\n")
            lf.flush()
        rc = p.wait()
    secs = round(time.monotonic() - t0, 1)
    c1 = dl.counters_read()
    with gzip.open(os.path.join(a3d, "stream.ts.jsonl.gz"), "wt") as f:
        f.write("".join(l + "\n" for l in lines))
    # The folder: as root (the user's home is its own), then handed to this user.
    tgz = os.path.join(a3d, "trial.tgz")
    sudo(["tar", "-C", WORK, "-czf", tgz, "--exclude=./bin", "."], stderr=subprocess.DEVNULL)
    sudo(["chown", "%d:%d" % (os.getuid(), os.getgid()), tgz])
    for name in ("changes-E%d.jsonl" % epoch, "notes/inventory.jsonl"):
        r = sudo(["cat", WORK + "/" + name], capture_output=True, text=True)
        if r.returncode == 0:
            with open(os.path.join(a3d, os.path.basename(name).replace("inventory", "inventory-E%d" % epoch)), "w") as f:
                f.write(r.stdout)
    meta = {"arm": "a3", "epoch": epoch, "seconds": secs, "budget_minutes": mins, "exit": rc, "tokens": tokens_of(lines),
            "stream_lines": len(lines), "wire": dl.counters_delta(c0, c1)}
    dl.save_json(os.path.join(out, "a3.meta.json"), meta)
    print("a3 epoch %d: codex exit %d, %d stream lines" % (epoch, rc, len(lines)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("vars")
    ap.add_argument("out")
    ap.add_argument("epoch", type=int, choices=(0, 1, 2, 3))
    a = ap.parse_args(argv)
    return run(dl.load_json(a.vars), a.out, a.epoch)


if __name__ == "__main__":
    sys.exit(main())
