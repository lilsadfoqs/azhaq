#!/usr/bin/env python3
"""summary.py DIR: the table of experiment B and the protocol's three rules.

DIR is what fetch.sh brought back: DIR/sN/{b1,b1c,b2,usual,azhaq}/grade.json (arms B1, B1c, B2, B3, B4). Prints,
for each seed, each arm's recall (found of planted), false positives (fp), items left to triage (tri)
and time to the first true flaw, then the rules, each "holds in >= 3 of 4" seeds:

  1  B1 recall >= 70% and <= 1 false positive
  2  B1 recall >= 2x B2's, or B2 leaves >= 5x more items to triage
  3  B4 recall >= B3's, and B4's time to first true flaw <= half of B3's

With fewer than 4 seeds a rule's count is printed and its verdict is "n/a (fewer than 4 seeds)".
Writes DIR/summary.json."""
import glob
import json
import os
import sys

ARMS = [("B1", "b1"), ("B1c", "b1c"), ("B2", "b2"), ("B3", "usual"), ("B4", "azhaq")]


def load(d):
    seeds = {}
    for sd in sorted(glob.glob(os.path.join(d, "s[0-9]*"))):
        name = os.path.basename(sd)
        arms = {}
        for label, folder in ARMS:
            p = os.path.join(sd, folder, "grade.json")
            if os.path.exists(p):
                arms[label] = json.load(open(p))
        if arms:
            seeds[name] = arms
    return seeds


def fmt_t(s):
    if s is None:
        return "-"
    return "%dm%02ds" % (s // 60, s % 60) if s >= 60 else "%ds" % s


def rule1(a, arm="B1"):
    b1 = a.get(arm)
    return None if b1 is None else (b1["recall"] is not None and b1["recall"] >= 0.7 and b1["false_positives"] <= 1)


def rule2(a, arm="B1"):
    b1, b2 = a.get(arm), a.get("B2")
    if b1 is None or b2 is None:
        return None
    return b1["recall"] >= 2 * b2["recall"] or (b2["triage"] > 0 and b2["triage"] >= 5 * b1["triage"])


def rule3(a):
    b3, b4 = a.get("B3"), a.get("B4")
    if b3 is None or b4 is None:
        return None
    if b4["recall"] < b3["recall"]:
        return False
    t3, t4 = b3.get("first_true_seconds"), b4.get("first_true_seconds")
    if t4 is None:
        return False
    return True if t3 is None else t4 <= t3 / 2


def main(argv):
    d = argv[1]
    seeds = load(d)
    if not seeds:
        print("summary.py: no grade.json under %s" % d, file=sys.stderr)
        return 1
    rows = ["seed  " + "  ".join("%-27s" % ("%s %s" % (lab, "recall fp tri first")) for lab, _ in ARMS)]
    for name, arms in seeds.items():
        cells = []
        for lab, _ in ARMS:
            g = arms.get(lab)
            cells.append("%-27s" % ("-" if g is None else "%d/%d  %d  %d  %s" % (g["found"], g["flaws"], g["false_positives"],
                                                                                g["triage"], fmt_t(g.get("first_true_seconds")))))
        rows.append("%-5s " % name + "  ".join(cells))
    print("\n".join(rows))
    out = {"seeds": list(seeds), "rules": {}}
    desc = {"1": "B1 recall >= 70% and <= 1 false positive per seed",
            "2": "B1 recall >= 2x B2's, or B2 leaves >= 5x more items to triage",
            "3": "B4 recall >= B3's and B4 time to first true flaw <= 1/2 of B3's",
            "1c": "rule 1 with B1c (B1 plus -replay-writes-canary)", "2c": "rule 2 with B1c"}
    print()
    for n, fn in (("1", rule1), ("2", rule2), ("3", rule3), ("1c", lambda a: rule1(a, "B1c")),
                  ("2c", lambda a: rule2(a, "B1c"))):
        res = {s: fn(a) for s, a in seeds.items()}
        known = [v for v in res.values() if v is not None]
        k = sum(1 for v in known if v)
        if len(seeds) < 4 or len(known) < len(seeds):
            verdict = "n/a (fewer than 4 seeds)" if len(known) == len(seeds) else "n/a (an arm is missing)"
        else:
            verdict = "holds" if k >= 3 else "does not hold"
        out["rules"][n] = {"description": desc[n], "per_seed": res, "count": k, "of": len(seeds), "verdict": verdict}
        print("rule %s: %s\n        holds in %d of %d seeds: %s" % (n, desc[n], k, len(seeds), verdict))
    def passes(names):
        allv = [out["rules"][n]["verdict"] for n in names]
        return "yes" if all(v == "holds" for v in allv) else ("no" if all(v in ("holds", "does not hold") for v in allv) else "undecided")
    # Both B1 variants are reported side by side; neither is picked after the fact.
    out["B_passes"] = passes(["1", "2", "3"])
    out["B_passes_with_canary"] = passes(["1c", "2c", "3"])
    print("\nB passes (B1 as documented by default): %s" % out["B_passes"])
    print("B passes (B1c, with the write canary): %s" % out["B_passes_with_canary"])
    json.dump(out, open(os.path.join(d, "summary.json"), "w"), indent=1)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
