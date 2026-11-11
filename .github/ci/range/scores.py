#!/usr/bin/env python3
"""scores.py: the private history of review scores.

  scores.py extract REPORT.md --kind gate-a|gate-b|baseline|switch|control-a|control-b --tag TAG
            [--part a1] [--version V] [--run ID] --out scores.json
      reads the scorecard of a review's REPORT.md (the rows merge_gate.py
      reads) into one small JSON record: each item's score, the overall.
      The workflow encrypts it to the maintainer's age key and publishes it
      beside the review's results (trial/TAG/PART/scores.json.age).

  scores.py history DIR... [--last N] [--json] [--with-control]
      DIR is a folder of such records (scores.json) or of fetched reviews
      (their REPORT.md is read when there is no record): prints each item
      across the reviews, newest last, with every sample of a review
      (up to four) and the spread between them, and the spread across the
      reviews (the range of their means). Records of kinds control-a and
      control-b are left out unless --with-control is given (README.md).

Nothing here is public: the record is only ever written encrypted.
"""
import argparse
import importlib.util
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("merge_gate", os.path.join(HERE, "merge_gate.py"))
merge_gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(merge_gate)

# What a kind's scorecard is asked for (GATE.md, BRIEF.md): None means every row.
KIND_ITEMS = {
    "gate-a": merge_gate.PART_A_ITEMS,
    "gate-b": merge_gate.PART_B_ITEMS,
    "baseline": merge_gate.PART_A_ITEMS,
    "switch": None,
    "control-a": merge_gate.PART_A_ITEMS,
    "control-b": merge_gate.PART_B_ITEMS,
}


def is_control(record):
    return record["kind"].startswith("control")


def extract(report_text, kind, tag, part="", version="", run="", now=None):
    """The record of one review part: {items: {label: score}, overall, ...}."""
    rows, _ = merge_gate.parse_scorecard(report_text or "")
    items, missing = {}, []
    wanted = KIND_ITEMS[kind]
    if wanted is None:
        for label, (score, _) in rows.items():
            if "overall" not in label:
                items[label] = score
    else:
        matched, _ = merge_gate.match_items(rows, wanted)
        for label, score, _ in matched:
            if score is None:
                missing.append(label)
            else:
                items[label] = score
    overall = None
    for label, (score, _) in rows.items():
        if label.startswith("overall"):
            overall = score
            break
    return {
        "format": 1,
        "tag": tag,
        "kind": kind,
        "part": part,
        "version": version,
        "run": run,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now if now is not None else time.time())),
        "items": items,
        "overall": overall,
        "missing": missing,
    }


def load(dirs):
    """Every record under the folders: scores.json, else the REPORT.md of a part."""
    records = []
    for top in dirs:
        for root, _, files in sorted(os.walk(top)):
            path = os.path.join(root, "scores.json")
            if "scores.json" in files:
                with open(path, encoding="utf-8") as f:
                    records.append(json.load(f))
            elif "REPORT.md" in files:
                rel = os.path.relpath(root, top)
                part = "" if rel == "." else rel.split(os.sep)[-1]
                letters = part.rstrip("0123456789")
                kind = {"a": "gate-a", "b": "gate-b"}.get(letters, "switch")
                tag = os.path.basename(os.path.abspath(top))
                mtime = os.path.getmtime(os.path.join(root, "REPORT.md"))
                with open(os.path.join(root, "REPORT.md"), encoding="utf-8", errors="replace") as f:
                    records.append(extract(f.read(), kind, tag, part, now=mtime))
    return records


def build(records, last=0):
    """Reviews in time order, each with its items' scores per sample."""
    reviews = {}
    for r in records:
        rv = reviews.setdefault(r["tag"], {"tag": r["tag"], "time": r["time"], "version": r.get("version", ""), "items": {}})
        rv["time"] = min(rv["time"], r["time"])
        rv["version"] = rv["version"] or r.get("version", "")
        for label, score in r["items"].items():
            rv["items"].setdefault((r["kind"], label), []).append((r["part"], score))
    ordered = sorted(reviews.values(), key=lambda v: (v["time"], v["tag"]))
    return ordered[-last:] if last else ordered


def spread(values):
    return max(values) - min(values) if values else 0


def table(reviews):
    labels = []
    for rv in reviews:
        for k in rv["items"]:
            if k not in labels:
                labels.append(k)
    out = []
    head = ["item"] + [rv["tag"] + (" " + rv["version"] if rv["version"] else "") for rv in reviews] + ["spread across"]
    out.append(head)
    for kind, label in labels:
        row = [("%s: %s" % (kind, label)) if kind != "switch" else label]
        means = []
        for rv in reviews:
            samples = rv["items"].get((kind, label))
            if not samples:
                row.append("-")
                continue
            scores = [s for _, s in sorted(samples)]
            row.append("/".join(str(s) for s in scores) + (" (spread %d)" % spread(scores) if len(scores) > 1 else ""))
            means.append(sum(scores) / len(scores))
        row.append("%.1f" % spread(means) if len(means) > 1 else "-")
        out.append(row)
    return out


def render(reviews):
    rows = table(reviews)
    if len(rows) == 1:
        return "no scores yet\n"
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]))]
    lines = ["  ".join(c.ljust(widths[i]) for i, c in enumerate(r)).rstrip() for r in rows]
    lines.insert(1, "  ".join("-" * w for w in widths))
    lines.append("")
    lines.append("Cells list every sample of one review (a1..a4, b1..b4) as score/score/... with their spread (highest minus lowest); \"spread across\" is the range of the reviews' means.")
    lines.append("Read a change in an item against the spread between samples of one build (same review): a move inside it is no trend.")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("extract")
    e.add_argument("report")
    e.add_argument("--kind", required=True, choices=sorted(KIND_ITEMS))
    e.add_argument("--tag", required=True)
    e.add_argument("--part", default="")
    e.add_argument("--version", default="")
    e.add_argument("--run", default="")
    e.add_argument("--out", required=True)
    h = sub.add_parser("history")
    h.add_argument("dirs", nargs="+")
    h.add_argument("--last", type=int, default=0)
    h.add_argument("--json", action="store_true")
    h.add_argument("--with-control", action="store_true", help="also show the control's records (left out by default)")
    a = ap.parse_args(argv)
    if a.cmd == "extract":
        try:
            with open(a.report, encoding="utf-8", errors="replace") as f:
                text = f.read()
        except OSError as err:
            print("scores.py: %s" % err, file=sys.stderr)
            return 1
        rec = extract(text, a.kind, a.tag, a.part, a.version, a.run)
        if not rec["items"]:
            print("scores.py: no scorecard row in %s" % a.report, file=sys.stderr)
            return 1
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(rec, f, indent=1, sort_keys=True)
            f.write("\n")
        return 0
    reviews = build([r for r in load(a.dirs) if a.with_control or not is_control(r)], a.last)
    if a.json:
        out = [{"tag": r["tag"], "time": r["time"], "version": r["version"],
                "items": {"%s: %s" % k: sorted(v) for k, v in r["items"].items()}} for r in reviews]
        json.dump(out, sys.stdout, indent=1)
        print()
    else:
        sys.stdout.write(render(reviews))
    return 0


if __name__ == "__main__":
    sys.exit(main())
