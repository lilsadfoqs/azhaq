#!/usr/bin/env python3
"""summary.py sample KEY.json GRADE.json LEADS.jsonl [--cap-seconds N] [--out FILE]
summary.py agg SUMMARY.json... [--json]

`sample` reduces one replay (grade.py's grade.json, the leads and the answer
key) to numbers: key vulnerabilities identified at 5, 15 and 30 minutes and at
the end (count and share of the key), seconds to the first match, precision
(matched leads over all leads), surface recall (hosts, ports, services), and
the leads and matches by kind. `agg` puts the samples side by side: the mean
and the minimum of each number across them.

The output holds counts and shares only. No product, CVE, host, address, port
or path of the key may appear in it: `sample` checks its own result against the
key and refuses to write it when one does.
"""
import argparse
import json
import statistics
import sys
from collections import Counter

WINDOWS = (("5m", 300), ("15m", 900), ("30m", 1800))


def frac(a, b):
    return round(a / b, 3) if b else None


def key_vulns(key):
    """The key's vulnerable hosts that were up, as grade.py counts them."""
    est = key["estates"][0]
    return [h for h in est["hosts"] if h.get("up", True) and h.get("vulnerable")]


def secrets_of(key):
    """Every string of the key that a summary must not repeat."""
    out = set()
    for est in key["estates"]:
        out.update(x for x in (est.get("domain"), est.get("net")) if x)
        for h in est["hosts"]:
            for k in ("host", "address", "target", "product", "version"):
                if h.get(k):
                    out.add(str(h[k]))
            out.update(c for c in h.get("cve", []) if c)
            out.update(str(p["port"]) for p in h.get("ports", []))
    return {s.lower() for s in out if len(s) >= 3}


def walk(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield str(k)
            yield from walk(v)
    elif isinstance(x, list):
        for v in x:
            yield from walk(v)
    elif isinstance(x, str):
        yield x


def check_clean(obj, key):
    """Raises when a string of obj contains a product, CVE, host, address or port of the key."""
    bad = secrets_of(key)
    for s in walk(obj):
        low = s.lower()
        for b in bad:
            if b.isdigit():
                hit = low == b
            else:
                hit = b in low
            if hit:
                raise ValueError("the summary would repeat a string of the answer key")


def sample(key, grade, leads, cap_s=None):
    ph = grade["phases"][0]
    found = ph["vulns"]["found"]
    total = ph["vulns"]["of"]
    secs = sorted(v["seconds"] for v in found if v["seconds"] is not None)
    ident = {name: {"count": sum(1 for s in secs if s <= limit)} for name, limit in WINDOWS}
    ident["end"] = {"count": ph["vulns"]["identified"]}
    for v in ident.values():
        v["fraction"] = frac(v["count"], total)
    # A lead that is neither unmatched nor place-only matched a key entry (a repeat of one included).
    unmatched = Counter((l.get("title"), l.get("host"), l.get("port")) for l in ph["leads"]["unmatched"] + ph["leads"]["place_only"])
    by_kind = {}
    for l in leads:
        k = (l.get("title"), l.get("host"), l.get("port"))
        row = by_kind.setdefault(l.get("kind") or "other", {"leads": 0, "matched": 0})
        row["leads"] += 1
        if unmatched[k] > 0:
            unmatched[k] -= 1
        else:
            row["matched"] += 1
    n_leads = ph["leads"]["total"]
    matched = n_leads - len(ph["leads"]["unmatched"]) - len(ph["leads"]["place_only"])
    cats = Counter(h["category"] for h in key_vulns(key))
    by_cat = {c: {"identified": ph["vulns"]["by_category"].get(c, 0), "of": n} for c, n in sorted(cats.items())}
    sf = ph["surface"]
    out = {
        "version": 1,
        "cap_seconds": cap_s,
        "key_vulns": total,
        "identified": ident,
        "first_match_seconds": ph["time"]["first_match_s"],
        "precision": {"matched": matched, "leads": n_leads, "value": frac(matched, n_leads)},
        "surface": {k: {"found": sf[k][0], "of": sf[k][1], "recall": frac(sf[k][0], sf[k][1])} for k in ("hosts", "ports", "services")},
        "by_kind": dict(sorted(by_kind.items())),
        "by_category": by_cat,
    }
    check_clean(out, key)
    return out


# The numbers `agg` reports: id, label, path into a sample's summary.
METRICS = [
    ("identified_5m", "identified at 5 min", ("identified", "5m", "count")),
    ("identified_5m_share", "  share of the key", ("identified", "5m", "fraction")),
    ("identified_15m", "identified at 15 min", ("identified", "15m", "count")),
    ("identified_15m_share", "  share of the key", ("identified", "15m", "fraction")),
    ("identified_30m", "identified at 30 min", ("identified", "30m", "count")),
    ("identified_30m_share", "  share of the key", ("identified", "30m", "fraction")),
    ("identified_end", "identified at the end", ("identified", "end", "count")),
    ("identified_end_share", "  share of the key", ("identified", "end", "fraction")),
    ("first_match_seconds", "seconds to the first match", ("first_match_seconds",)),
    ("precision", "precision (matched / leads)", ("precision", "value")),
    ("surface_hosts", "surface: hosts recall", ("surface", "hosts", "recall")),
    ("surface_ports", "surface: ports recall", ("surface", "ports", "recall")),
    ("leads", "leads", ("precision", "leads")),
    ("key_vulns", "key vulnerabilities", ("key_vulns",)),
]


def dig(d, path):
    for p in path:
        if not isinstance(d, dict):
            return None
        d = d.get(p)
    return d


def agg(samples):
    rows = {}
    for mid, label, path in METRICS:
        vals = [v for v in (dig(s, path) for s in samples) if v is not None]
        rows[mid] = {"label": label, "n": len(vals), "mean": round(statistics.mean(vals), 3) if vals else None,
                     "min": min(vals) if vals else None}
    kinds, matched = Counter(), Counter()
    for s in samples:
        for k, v in s.get("by_kind", {}).items():
            kinds[k] += v["leads"]
            matched[k] += v["matched"]
    return {"samples": len(samples), "metrics": rows,
            "by_kind": {k: {"leads": kinds[k], "matched": matched[k]} for k in sorted(kinds)}}


def table(a):
    num = lambda v: "-" if v is None else ("%.3g" % v)
    o = ["%d sample%s; mean and minimum over the samples that have each number" % (a["samples"], "" if a["samples"] == 1 else "s"),
         "%-30s %9s %9s %3s" % ("", "mean", "min", "n")]
    for r in a["metrics"].values():
        o.append("%-30s %9s %9s %3d" % (r["label"], num(r["mean"]), num(r["min"]), r["n"]))
    if a["by_kind"]:
        o += ["", "leads by kind, all samples: leads / matched"]
        o += ["  %-24s %5d / %d" % (k, v["leads"], v["matched"]) for k, v in a["by_kind"].items()]
    return "\n".join(o) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("key")
    s.add_argument("grade")
    s.add_argument("leads")
    s.add_argument("--cap-seconds", type=int)
    s.add_argument("--out")
    g = sub.add_parser("agg")
    g.add_argument("files", nargs="+")
    g.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "sample":
        with open(a.key, encoding="utf-8") as f:
            key = json.load(f)
        with open(a.grade, encoding="utf-8") as f:
            grade = json.load(f)
        leads = []
        try:
            with open(a.leads, encoding="utf-8") as f:
                leads = [json.loads(l) for l in f if l.strip()]
        except OSError:
            pass
        try:
            out = sample(key, grade, leads, a.cap_seconds)
        except ValueError as e:
            print("summary.py: %s" % e, file=sys.stderr)
            return 1
        text = json.dumps(out, indent=1) + "\n"
        if a.out:
            with open(a.out, "w", encoding="utf-8") as f:
                f.write(text)
        else:
            sys.stdout.write(text)
        return 0
    samples = []
    for p in a.files:
        with open(p, encoding="utf-8") as f:
            samples.append(json.load(f))
    r = agg(samples)
    sys.stdout.write(json.dumps(r, indent=1) + "\n" if a.json else table(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())
