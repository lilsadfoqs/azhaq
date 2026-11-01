#!/usr/bin/env python3
"""shard.py: splits `go test -race` over N runners by measured test time.

  shard.py --shards N --index I [--fresh]   run shard I (writes times-I.json)
  shard.py --shards N [--plan]              print the plan: load per shard
  shard.py --shards N --check               every test lands in exactly one shard
  shard.py --refresh DIR                    rewrite test-times.json from the
                                            times-*.json of a run:
    gh run download RUN -p 'times-*' -D DIR && shard.py --refresh DIR

Refresh from a run with fresh=true (the nightly one): a run that kept results
reports a kept test's time from the run that made it. Commit the new file.

The packages come from `go list ./...`, each package's top-level tests from
its *_test.go files (nothing is compiled to list them). test-times.json holds
{package: {test: seconds}}. A package whose tests sum to more than THRESHOLD
is split by test, the others are whole units; a package or test missing from
the file counts as 1 s (a package) or the package's median (a test). Units go,
longest first, to the least loaded shard, so the same inputs give the same plan.
A shard runs a split package's tests in batches of about BATCH seconds, in name
order: go test keeps a result per run, so a changed file that one test reads
runs again only that test's batch.
"""
import argparse
import glob
import json
import os
import re
import statistics
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TIMES = os.path.join(HERE, "test-times.json")
THRESHOLD = 20.0
BATCH = 20.0
TEST_RE = re.compile(r"^func ((?:Test|Example|Fuzz)(?:[^\sa-z(]\w*)?)\(", re.M)


def list_tests(src):
    return TEST_RE.findall(src)


def go_packages():
    """[(path relative to the module, directory, [test files])], root is '.'."""
    mod = subprocess.check_output(["go", "list", "-m"], text=True).strip()
    out = subprocess.check_output(
        ["go", "list", "-f", '{{.ImportPath}}\t{{.Dir}}\t{{join .TestGoFiles ","}},{{join .XTestGoFiles ","}}', "./..."],
        text=True,
    )
    pkgs = []
    for line in out.splitlines():
        imp, d, files = line.split("\t")
        pkgs.append((relpath(imp, mod), d, [f for f in files.split(",") if f]))
    return pkgs


def relpath(imp, mod):
    if imp == mod:
        return "."
    return imp[len(mod) + 1:] if imp.startswith(mod + "/") else imp


def package_tests(d, files):
    names = []
    for f in sorted(files):
        with open(os.path.join(d, f), encoding="utf-8", errors="replace") as fh:
            names += list_tests(fh.read())
    return sorted(set(names))


def load_inventory(pkgs=None):
    """{package: [tests]} for the packages that have any."""
    inv = {}
    for rel, d, files in pkgs if pkgs is not None else go_packages():
        names = package_tests(d, files)
        if names:
            inv[rel] = names
    return inv


def load_times(path=TIMES):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def test_cost(pkg, test, times):
    known = times.get(pkg, {})
    if test in known:
        return float(known[test])
    return float(statistics.median(known.values())) if known else 1.0


def plan(inv, times, shards, threshold=THRESHOLD):
    """Returns [{'load': s, 'whole': [pkg], 'split': {pkg: [tests]}}] per shard."""
    units = []  # (cost, name, pkg, tests or None)
    for pkg, tests in inv.items():
        costs = {t: test_cost(pkg, t, times) for t in tests}
        if pkg not in times:
            units.append((1.0, pkg, pkg, None))
        elif sum(costs.values()) > threshold:
            units += [(c, pkg + "." + t, pkg, [t]) for t, c in costs.items()]
        else:
            units.append((sum(costs.values()), pkg, pkg, None))
    units.sort(key=lambda u: (-u[0], u[1]))
    out = [{"load": 0.0, "whole": [], "split": {}} for _ in range(shards)]
    for cost, _, pkg, tests in units:
        s = min(out, key=lambda x: x["load"])  # ties: the lowest index
        s["load"] += cost
        if tests is None:
            s["whole"].append(pkg)
        else:
            s["split"].setdefault(pkg, []).extend(tests)
    for s in out:
        s["whole"].sort()
        for t in s["split"].values():
            t.sort()
    return out


def check(inv, p):
    """Problems: a test in no shard or in two."""
    seen = {}
    for i, s in enumerate(p):
        for pkg in s["whole"]:
            for t in inv[pkg]:
                seen.setdefault((pkg, t), []).append(i)
        for pkg, tests in s["split"].items():
            for t in tests:
                seen.setdefault((pkg, t), []).append(i)
    bad = []
    for pkg, tests in inv.items():
        for t in tests:
            n = seen.get((pkg, t), [])
            if len(n) != 1:
                bad.append("%s %s is in %d shards %s" % (pkg, t, len(n), n))
    return bad


def batches(pkg, tests, times, limit=BATCH):
    """Tests in name order, cut into runs of at most limit seconds (or one test)."""
    out, cur, load = [], [], 0.0
    for t in sorted(tests):
        c = test_cost(pkg, t, times)
        if cur and load + c > limit:
            out.append(cur)
            cur, load = [], 0.0
        cur.append(t)
        load += c
    if cur:
        out.append(cur)
    return out


def pkg_arg(rel):
    return "./" + rel if rel != "." else "."


def run_args(pkgs, tests=None, fresh=False):
    a = ["go", "test", "-race", "-json"]
    if fresh:
        a.append("-count=1")
    if tests:
        a += ["-run", "^(" + "|".join(tests) + ")$"]
    return a + [pkg_arg(p) for p in pkgs]


def annotations(log):
    """The ::error:: lines of a failed run: a race's own frames first (a step
    shows ten annotations), then the FAIL and panic lines."""
    lines = log.splitlines()
    race = []
    for i, l in enumerate(lines):
        if "WARNING: DATA RACE" in l:
            race = [x for x in lines[i:i + 40] if re.search(r"(Write|Read) at|azhaq/[a-z]", x)][:6]
            break
    fail = [l for l in lines if re.search(
        r"--- FAIL|panic:|_test\.go:[0-9]+:|^FAIL|signal: |\[build failed\]|^# ", l)][:20]
    return ["::error::" + x.replace("%", "%25").replace("\r", "%0D") for x in race + fail]


class Run:
    """The state of one shard's `go test -json` runs."""

    def __init__(self, mod, out):
        self.mod, self.out = mod, out
        self.log = []
        self.failed = False
        self.tests = {}
        self.packages = {}

    def event(self, e):
        text = e.get("Output")
        if text:
            self.out.write(text)
            self.log.append(text)
        act = e.get("Action")
        pkg = e.get("Package")
        if act in ("pass", "fail", "skip") and pkg:
            rel = relpath(pkg, self.mod)
            test = e.get("Test")
            if test is None:
                if act != "skip":  # a split package runs in batches
                    self.packages[rel] = self.packages.get(rel, 0) + e.get("Elapsed", 0)
            elif "/" not in test:
                self.tests.setdefault(rel, {})[test] = e.get("Elapsed", 0)
        if act == "fail" or act == "build-fail":
            self.failed = True

    def line(self, raw):
        raw = raw.rstrip("\n")
        try:
            e = json.loads(raw)
            if not isinstance(e, dict):
                raise ValueError
        except ValueError:
            self.out.write(raw + "\n")
            self.log.append(raw + "\n")
            return
        self.event(e)

    def go(self, args):
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                             encoding="utf-8", errors="replace")
        for raw in p.stdout:
            self.line(raw)
        if p.wait() != 0:
            self.failed = True
        self.out.flush()


def run_shard(inv, p, index, fresh, mod, times):
    s = p[index]
    run = Run(mod, sys.stdout)
    if s["whole"]:
        run.go(run_args(s["whole"], fresh=fresh))
    for pkg, tests in sorted(s["split"].items()):
        for b in batches(pkg, tests, times):
            run.go(run_args([pkg], b, fresh))
    with open("times-%d.json" % index, "w") as f:
        json.dump({"shard": index, "packages": run.packages, "tests": run.tests}, f, indent=1, sort_keys=True)
        f.write("\n")
    if run.failed:
        for a in annotations("".join(run.log)):
            print(a)
        return 1
    return 0


def print_plan(inv, times, p):
    for i, s in enumerate(p):
        split = ", ".join("%s (%d tests)" % (k, len(v)) for k, v in sorted(s["split"].items()))
        print("shard %d: %6.1f s  whole: %d packages  split: %s" % (i, s["load"], len(s["whole"]), split or "-"))
        for pkg in s["whole"]:
            c = sum(test_cost(pkg, t, times) for t in inv[pkg])
            if c >= 5:
                print("    %-40s %6.1f s" % (pkg, c))
        for pkg, tests in sorted(s["split"].items()):
            print("    %-40s %6.1f s  %s" % (pkg, sum(test_cost(pkg, t, times) for t in tests),
                                             ", ".join(tests[:3]) + (", ..." if len(tests) > 3 else "")))


def refresh(d, path=TIMES):
    merged = {}
    files = sorted(glob.glob(os.path.join(d, "**", "times-*.json"), recursive=True))
    if not files:
        print("no times-*.json under %s" % d, file=sys.stderr)
        return 1
    for f in files:
        with open(f) as fh:
            for pkg, tests in json.load(fh).get("tests", {}).items():
                merged.setdefault(pkg, {}).update(tests)
    times = load_times(path)
    times.update({pkg: {t: round(v, 2) for t, v in sorted(tests.items())} for pkg, tests in merged.items()})
    with open(path, "w") as f:
        json.dump(times, f, indent=1, sort_keys=True)
        f.write("\n")
    print("%s: %d packages from %d files" % (path, len(merged), len(files)))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1], add_help=True)
    ap.add_argument("--shards", type=int)
    ap.add_argument("--index", type=int)
    ap.add_argument("--fresh", action="store_true", help="ignore kept test results (-count=1)")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--plan", action="store_true")
    ap.add_argument("--refresh", metavar="DIR")
    ap.add_argument("--threshold", type=float, default=THRESHOLD)
    a = ap.parse_args(argv)
    if a.refresh:
        return refresh(a.refresh)
    if not a.shards or a.shards < 1:
        ap.error("--shards N is needed")
    pkgs = go_packages()
    inv = load_inventory(pkgs)
    times = load_times()
    p = plan(inv, times, a.shards, a.threshold)
    if a.check:
        bad = check(inv, p)
        for pkg in times:
            if pkg not in inv:
                print("warning: test-times.json has %s, which has no tests" % pkg, file=sys.stderr)
        for pkg, tests in inv.items():
            gone = sorted(set(times.get(pkg, {})) - set(tests))
            if gone:
                print("warning: test-times.json has %s tests that no longer exist: %s" % (pkg, ", ".join(gone)),
                      file=sys.stderr)
        if bad:
            print("\n".join(bad), file=sys.stderr)
            return 1
        print("ok: %d tests in %d packages, each in exactly one of %d shards"
              % (sum(len(t) for t in inv.values()), len(inv), a.shards))
        return 0
    if a.index is None:
        print_plan(inv, times, p)
        return 0
    if not 0 <= a.index < a.shards:
        ap.error("--index must be in 0..%d" % (a.shards - 1))
    mod = subprocess.check_output(["go", "list", "-m"], text=True).strip()
    return run_shard(inv, p, a.index, a.fresh, mod, times)


if __name__ == "__main__":
    sys.exit(main())
