#!/usr/bin/env python3
"""summary.py DIR [--json]: the samples of experiment A side by side, and the
protocol's three A rules.

DIR holds sN/grade.json (fetch.sh brings them back). Prints, per sample and
arm: recall of the planted changes (E1 and E3), the product named on new
surfaces, false changes (E1, E3), false alarms (E2), wall minutes, requests
(azhaq's own count for a1, the kernel's connection attempts for all) and tokens;
then recall by class over the samples; then the rules:

  1  A1 recall >= 80%, product named on >= 70% of new surfaces, 0 false alarms on E2
  2  A1 recall >= A2's, and A1's false changes <= 1/5 of A2's
  3  A1 recall >= A3's, at <= 1/10 of A3's wall time
Each holds when it does in >= 3 of 4 samples; with fewer samples the counts are
printed and no verdict is. Counts and shares only.
"""
import argparse
import json
import os
import re
import sys


def load_settle(root):
    """Per sample, 'settled/total' of each epoch's settle step (context only; the grader ignores it)."""
    out = {}
    for name in sorted(os.listdir(root)):
        cells = []
        for e in range(4):
            p = os.path.join(root, name, "e%d" % e, "settle.json")
            if os.path.exists(p):
                with open(p) as f:
                    d = json.load(f)
                cells.append("E%d %d/%d" % (e, d["settled"], d["envs"]))
        if cells:
            out[name] = " ".join(cells)
    return out


def load(root):
    out = {}
    for name in sorted(os.listdir(root)):
        p = os.path.join(root, name, "grade.json")
        if re.fullmatch(r"s\d+", name) and os.path.exists(p):
            with open(p) as f:
                out[name] = json.load(f)
    return out


def share(a, b):
    return a / b if b else None


def pct(x):
    return "-" if x is None else "%d%%" % round(100 * x)


def wire(a):
    n = 0
    for ent in a["epochs"].values():
        w = ent.get("wire") or {}
        n += (w.get("tcp_syn") or 0) + (w.get("udp") or 0) + (w.get("dns_resolver") or 0)
    return n


def row(name, arm, a):
    t = a["totals"]
    i = t["ident"]
    return {"sample": name, "arm": arm, "recall": share(t["hit"], t["of"]), "hit": t["hit"], "of": t["of"], "seen": t["seen"],
            "product": share(i["product"], i["of"]), "version": share(i["version"], i["of"]), "ident_of": i["of"],
            "false_changes": t["false_changes"], "false_alarms": t["false_alarms"], "wall_min": round(t["wall_s"] / 60, 1),
            "requests": t["requests"], "wire": wire(a), "tokens": t["tokens"], "missing": t["missing"]}


def ge(a, b):
    return a is not None and b is not None and a >= b


def rules(rows):
    """Per sample: does each rule hold? None when it cannot be told (no A3)."""
    out = {}
    for s, arms in rows.items():
        a1, a2, a3 = arms.get("a1"), arms.get("a2"), arms.get("a3")
        r1 = bool(a1 and ge(a1["recall"], 0.8) and ge(a1["product"], 0.7) and a1["false_alarms"] == 0)
        r2 = bool(a1 and a2 and ge(a1["recall"], a2["recall"]) and a1["false_changes"] <= a2["false_changes"] / 5)
        r3 = None
        if a1 and a3 and a3["wall_min"] > 0:
            r3 = bool(ge(a1["recall"], a3["recall"]) and a1["wall_min"] <= a3["wall_min"] / 10)
        out[s] = {"1": r1, "2": r2, "3": r3}
    return out


def verdict(held, n):
    return "holds" if n == 4 and held >= 3 else "fails" if n == 4 else "no verdict (%d of 4 samples)" % n


def render(samples, settle=None):
    rows = {s: {arm: row(s, arm, a) for arm, a in g["arms"].items()} for s, g in samples.items()}
    out = []
    head = "%-4s %-7s %-12s %-8s %-8s %-6s %-6s %-6s %-9s %-9s %s" % ("", "arm", "recall", "product", "version", "falseC", "falseA", "min", "requests", "wire", "tokens")
    out += [head, "-" * len(head)]
    for s, arms in rows.items():
        for arm, r in arms.items():
            out.append("%-4s %-7s %-12s %-8s %-8s %-6d %-6d %-6s %-9s %-9d %s%s" % (
                s, arm, "%d/%d %s" % (r["hit"], r["of"], pct(r["recall"])), pct(r["product"]), pct(r["version"]), r["false_changes"],
                r["false_alarms"], r["wall_min"], r["requests"] or "-", r["wire"], r["tokens"] or "-", "  (data missing for %d epochs)" % r["missing"] if r["missing"] else ""))
    out.append("")
    if settle:
        out.append("settled before the arms ran (context): " + "; ".join("%s: %s" % kv for kv in settle.items()))
        out.append("")
    out.append("recall by class over all samples (hit/of, seen)")
    classes = sorted({c for g in samples.values() for a in g["arms"].values() for c in a["totals"]["classes"]})
    arms = sorted({arm for g in samples.values() for arm in g["arms"]})
    out.append("%-10s " % "" + " ".join("%-14s" % a for a in arms))
    for c in classes:
        cells = []
        for arm in arms:
            h = o = sn = 0
            for g in samples.values():
                v = g["arms"].get(arm, {}).get("totals", {}).get("classes", {}).get(c)
                if v:
                    h, o, sn = h + v["hit"], o + v["of"], sn + v["seen"]
            cells.append("%-14s" % ("%d/%d (%d)" % (h, o, sn)))
        out.append("%-10s " % c + " ".join(cells))
    out.append("")
    r = rules(rows)
    n = len(r)
    verdicts = {}
    for k, label in (("1", "A1 recall >= 80%, product on >= 70% of new surfaces, 0 false alarms on E2"),
                     ("2", "A1 recall >= A2's, A1 false changes <= 1/5 of A2's"),
                     ("3", "A1 recall >= A3's at <= 1/10 of A3's wall time")):
        vals = [v[k] for v in r.values()]
        if all(v is None for v in vals):
            out.append("rule %s: not evaluated (no A3 in these samples)   %s" % (k, label))
            verdicts[k] = None
            continue
        held = sum(1 for v in vals if v)
        verdicts[k] = verdict(held, n)
        out.append("rule %s: holds in %d of %d samples: %s   %s" % (k, held, n, verdicts[k], label))
    if n == 4 and all(v == "holds" for v in verdicts.values()):
        out.append("A passes (10x on continuous recon).")
    elif n == 4 and all(v is not None for v in verdicts.values()):
        out.append("A does not pass: %s." % ", ".join("rule %s %s" % (k, v) for k, v in verdicts.items() if v != "holds"))
    return "\n".join(out), {"rows": rows, "rules": r, "verdicts": verdicts}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    samples = load(a.dir)
    if not samples:
        print("summary.py: no sN/grade.json under %s" % a.dir, file=sys.stderr)
        return 1
    text, data = render(samples, load_settle(a.dir))
    print(json.dumps(data, indent=1) if a.json else text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
