#!/usr/bin/env python3
"""drive.py EST OUT --mode dryrun|full --vulhub DIR --azhaq BIN [--work DIR]:
runs the four epochs on the live estate, each in this order and with nothing
restarted between the arms: apply.py, A1, A2 and (full only) A3.

OUT/eN/ gets each arm's files (arms.py, a3.py) and apply.log (the exit code of
apply.py; its own output holds counts only). Nothing here is a result: the
grader reads OUT afterwards.
"""
import argparse
import os
import subprocess
import sys

import driftlib as dl

HERE = dl.HERE


def py(script, *args):
    return subprocess.run([sys.executable, os.path.join(HERE, script)] + list(args)).returncode


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("est")
    ap.add_argument("out")
    ap.add_argument("--mode", choices=("dryrun", "full"), required=True)
    ap.add_argument("--vulhub", required=True)
    ap.add_argument("--azhaq", required=True)
    ap.add_argument("--labdns", default="/usr/local/sbin/dnsd")
    ap.add_argument("--work")
    ap.add_argument("--epochs", default="0,1,2,3")
    ap.add_argument("--minutes", type=int, default=25, help="cap of one azhaq watch run")
    ap.add_argument("--skip-apply", default="", help="epochs whose apply.py already ran (the job applies E0 before it checks the agent's user)")
    a = ap.parse_args(argv)
    est, out = os.path.abspath(a.est), os.path.abspath(a.out)
    work = os.path.abspath(a.work or os.path.join(out, "..", "work"))
    os.makedirs(work, exist_ok=True)
    vars_ = os.path.join(est, "vars.json")
    rc = 0
    for e in (int(x) for x in a.epochs.split(",")):
        d = os.path.join(out, "e%d" % e)
        os.makedirs(d, exist_ok=True)
        r = 0 if str(e) in a.skip_apply.split(",") else py("apply.py", est, str(e), "--vulhub", a.vulhub, "--labdns", a.labdns)
        with open(os.path.join(d, "apply.exit"), "w") as f:
            f.write("%d\n" % r)
        prev = os.path.join(out, "e%d" % (e - 1)) if e else None
        rc |= py("arms.py", "a1", vars_, d, str(e), "--work", work, "--azhaq", a.azhaq, "--minutes", str(a.minutes))
        rc |= py("arms.py", "a2", vars_, d, str(e), "--work", work, *(["--prev", prev] if prev else []))
        if a.mode == "full":
            rc |= py("a3.py", vars_, d, str(e))
    # An arm that exited non-zero is data (the grader reads what it left), not a failed job.
    print("arm runs with a non-zero exit: %s" % ("some" if rc else "none"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
