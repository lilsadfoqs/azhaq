#!/usr/bin/env python3
"""bench_times.py LOG [--base OLD.json]: unit -> seconds from a bench log.

Reads the lines the bench writes for each unit ("bench: default: apps took
345s", "bench: once: dropin took 30s", "bench: claims: case 5 took 194s") and
prints the times as JSON, for .github/ci/bench-times.json. A unit the log
does not time keeps its time from --base, and is left out when the base has
none (the plan counts it as 60 s). Refresh it from a run's log:

    git show origin/ci-results:bench/<tag>/bench.log > bench.log
    .github/ci/bench_times.py bench.log --base .github/ci/bench-times.json > new.json
"""
import json
import re
import sys

LINE = re.compile(r"^bench: (?:(default|polite|once): ([\w.-]+(?:/[\w.-]+)?)|claims: case (\d+)) took (\d+)s\s*$")


def parse(text):
    """The seconds of every unit the log times; a unit logged twice keeps its last."""
    out = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        group, section, case, secs = m.groups()
        name = "claims:" + case if case else group + ":" + section
        out[name] = int(secs)
    return out


def main(argv):
    base = None
    args = list(argv)
    if "--base" in args:
        i = args.index("--base")
        base = args[i + 1]
        del args[i : i + 2]
    if len(args) != 1:
        sys.exit(__doc__)
    with open(args[0], encoding="utf-8", errors="replace") as f:
        times = parse(f.read())
    if base:
        with open(base, encoding="utf-8") as f:
            old = json.load(f)
        times = {**old, **times}
    json.dump(dict(sorted(times.items())), sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main(sys.argv[1:])
