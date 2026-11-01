#!/usr/bin/env python3
"""bench_plan.py: pack the bench's units into jobs by their measured times.

Reads the unit names from stdin (one a line, as `go run ./bench -list-units`
prints them) and the times from bench-times.json (unit -> seconds; a unit
the file lacks counts 60 s). Longest unit first, each to the job with the
least total so far (longest processing time first), into at most MAXPARTS
jobs. Prints the jobs as a JSON array for the workflow's matrix:
[{"name": "p1", "units": "default:apps,once:docs", "seconds": 405}, ...]
and a table of them on stderr.

    go run ./bench -list-units | .github/ci/bench_plan.py --times .github/ci/bench-times.json --max-parts 18
"""
import argparse
import json
import sys

UNKNOWN = 60  # seconds for a unit nobody timed


def pack(units, times, max_parts):
    """Jobs as [(total seconds, [units])], the longest first."""
    if max_parts < 1:
        raise ValueError("max-parts must be at least 1")
    units = list(dict.fromkeys(units))
    secs = {u: times.get(u, UNKNOWN) for u in units}
    n = min(max_parts, len(units))
    jobs = [[0, []] for _ in range(n)]
    for u in sorted(units, key=lambda u: (-secs[u], u)):
        job = min(jobs, key=lambda j: j[0])  # the first of equals: stable
        job[0] += secs[u]
        job[1].append(u)
    return sorted(([t, us] for t, us in jobs), key=lambda j: -j[0])


def matrix(jobs):
    return [{"name": f"p{i}", "units": ",".join(us), "seconds": t} for i, (t, us) in enumerate(jobs, 1)]


def table(jobs, times, units):
    lines = []
    for i, (t, us) in enumerate(jobs, 1):
        lines.append(f"p{i}  {t:5d}s  {', '.join(f'{u} {times.get(u, UNKNOWN)}' for u in us)}")
    guessed = [u for u in dict.fromkeys(units) if u not in times]
    if guessed:
        lines.append(f"not timed, counted as {UNKNOWN}s: {', '.join(guessed)}")
    return "\n".join(lines)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--times", required=True, help="bench-times.json")
    ap.add_argument("--max-parts", type=int, default=18)
    args = ap.parse_args(argv)
    with open(args.times, encoding="utf-8") as f:
        times = json.load(f)
    units = [l.strip() for l in sys.stdin if l.strip()]
    if not units:
        sys.exit("bench_plan: no units on stdin (the tag message's flags select none)")
    jobs = pack(units, times, args.max_parts)
    print(table(jobs, times, units), file=sys.stderr)
    print(json.dumps(matrix(jobs), separators=(",", ":")))


if __name__ == "__main__":
    main(sys.argv[1:])
