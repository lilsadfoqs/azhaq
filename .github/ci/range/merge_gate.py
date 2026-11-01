#!/usr/bin/env python3
"""merge_gate.py DIR [--out OUT.md]: merges the gate's two scorecards into
one table. DIR is what `fetch.sh trial NAME DIR` wrote: DIR/a (part A,
REPORT.md and, when graded, grade.json) and DIR/b (part B, REPORT.md).

For `samples=2`, DIR holds two pairs: DIR/a1+DIR/b1 and DIR/a2+DIR/b2 (fall
back to DIR/a+DIR/b when there is only one sample).

Each scorecard row (a Markdown table `| Item | Score | Reasoning |` in
REPORT.md, as GATE.md asks for) is read beside the anchor line its score
falls into, part B's switch areas first, then part A's, then one overall
(the lowest of every score read: the gate needs all of them at 9 or more).
Part A's grade.json, when it holds a `baseline_comparison` (grade.py
--baseline), is summarised beside the scorecard.

Rows GATE.md did not ask for, or a REPORT.md with no parseable table, are
listed for a person to judge instead of guessed at.
"""
import argparse
import json
import os
import re
import sys

ANCHORS = [
    (10, 10, "you would hand the job to it without a second look."),
    (9, 9, "at least as good as your usual tools on everything you measured, and nothing you found would stop you relying on it; what is left is minor or rare."),
    (7, 8, "as good or better on most of it, with gaps you can name and work around."),
    (5, 6, "useful, but you would keep your usual tools beside it for this job."),
    (3, 4, "here it costs you more than it gives."),
    (1, 2, "it fails or misleads at this job."),
]

# GATE.md's row labels, in the order its deliverable section lists them (the
# overall of each part is read but not carried into the merged table: the
# merge computes one overall of its own).
PART_A_ITEMS = ["findings against the key and the baseline", "time to the first finding",
                "signal versus noise", "trust", "would use on the next engagement"]
PART_B_ITEMS = ["install and first run", "docs", "subdomain recon", "host and port discovery",
                "web and api mapping", "signed-in and multi-role testing",
                "output and integration (including assistants)",
                "reliability (crashes, hangs, wrong data, silent failures)",
                "performance (time, memory and cpu, and the requests it sends to the target for the same result)"]

ROW_RE = re.compile(r"^\|\s*(?P<item>[^|]+?)\s*\|\s*(?P<score>\d{1,2})\s*(?:/\s*10)?\s*\|\s*(?P<reason>.*?)\s*\|\s*$")


def normalize(label):
    label = re.sub(r"\*+", "", label)
    label = re.sub(r"[^a-z0-9 ]+", " ", label.lower())
    return re.sub(r"\s+", " ", label).strip()


def anchor_for(score):
    for lo, hi, text in ANCHORS:
        if lo <= score <= hi:
            return text
    return "out of the 1-10 range"


def parse_scorecard(text):
    """{normalized item: (score, reasoning)} from every `| item | score |
    reasoning |` row of a REPORT.md; the first table of that shape wins a
    repeated item."""
    rows = {}
    order = []
    for line in (text or "").splitlines():
        m = ROW_RE.match(line.strip())
        if not m:
            continue
        item = normalize(m.group("item"))
        if item in ("item", "---", ""):
            continue
        try:
            score = int(m.group("score"))
        except ValueError:
            continue
        if not 1 <= score <= 10:
            continue
        if item not in rows:
            rows[item] = (score, m.group("reason").strip())
            order.append(item)
    return rows, order


def match_items(rows, wanted):
    """(matched rows in WANTED's order, leftover rows GATE.md did not ask for)."""
    matched, used = [], set()
    for w in wanted:
        key = normalize(w)
        hit = rows.get(key)
        if hit is None:
            # loose match: the wanted label is a word-for-word prefix of a row's.
            for item, val in rows.items():
                if item not in used and (item.startswith(key) or key.startswith(item)):
                    hit, key = val, item
                    break
        if hit is not None:
            used.add(key)
            matched.append((w, hit[0], hit[1]))
        else:
            matched.append((w, None, None))
    leftover = [(item, rows[item][0], rows[item][1]) for item in rows if item not in used
                and normalize("overall") not in item]
    return matched, leftover


def read(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def load_grade(a_dir):
    p = os.path.join(a_dir, "grade.json")
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def one_pair(a_dir, b_dir, label=""):
    a_text = read(os.path.join(a_dir, "REPORT.md"))
    b_text = read(os.path.join(b_dir, "REPORT.md"))
    a_rows, _ = parse_scorecard(a_text or "")
    b_rows, _ = parse_scorecard(b_text or "")
    a_matched, a_left = match_items(a_rows, PART_A_ITEMS)
    b_matched, b_left = match_items(b_rows, PART_B_ITEMS)
    all_matched = b_matched + a_matched
    scores = [s for _, s, _ in all_matched if s is not None]
    overall = min(scores) if scores else None
    grade = load_grade(a_dir)
    o = []
    title = "## Scorecard" + (" (%s)" % label if label else "")
    o += [title, "", "| Item | Score | Anchor | Reasoning |", "|---|---|---|---|"]
    for item, score, reason in all_matched:
        if score is None:
            o.append("| %s | not scored | - | REPORT.md has no parseable row for this item |" % item)
        else:
            o.append("| %s | %d | %s | %s |" % (item, score, anchor_for(score), reason or ""))
    if overall is not None:
        o.append("| **overall** | **%d** | %s | the lowest of the rows above: the gate needs every one at 9 or more |"
                  % (overall, anchor_for(overall)))
    else:
        o.append("| **overall** | not scored | - | no scorecard row parsed from either REPORT.md |")
    leftover = a_left + b_left
    if leftover:
        o += ["", "Rows found in a REPORT.md but not asked for by GATE.md (for a person to judge):"]
        for item, score, reason in leftover:
            o.append("- %s: %d, %s" % (item, score, reason or ""))
    if a_text is None:
        o += ["", "No %sREPORT.md for part A." % (label + " " if label else "")]
    if b_text is None:
        o += ["", "No %sREPORT.md for part B." % (label + " " if label else "")]
    if grade and grade.get("baseline_comparison"):
        o += ["", "### Part A's grade beside its baseline", ""]
        o += ["| Phase | Vulns identified | Leads | Time to first match | Commands | Same seed |",
              "|---|---|---|---|---|---|"]
        for c in grade["baseline_comparison"]:
            o.append("| %d | %d vs %d (of %s) | %d vs %d | %s vs %s | %d vs %d | %s |" % (
                c["phase"], c["vulns_identified"][0], c["vulns_identified"][1],
                " and ".join(str(x) for x in c["vulns_of"]), c["leads_total"][0], c["leads_total"][1],
                c["first_match_s"][0], c["first_match_s"][1], c["commands_total"][0], c["commands_total"][1],
                "yes" if c["same_seed"] else "NO, not a fair comparison"))
        o.append("")
        o.append("Each column reads \"azhaq vs baseline\".")
    elif grade:
        o += ["", "Part A was graded, but with no --baseline: run grade.py again with the pool estate's baseline grade.json to compare."]
    return "\n".join(o) + "\n", overall


def find_pairs(d):
    """[(a_dir, b_dir, label)], samples=2 first (a1/b1, a2/b2), else a/b."""
    s1a, s1b = os.path.join(d, "a1"), os.path.join(d, "b1")
    if os.path.isdir(s1a) and os.path.isdir(s1b):
        pairs = [(s1a, s1b, "sample 1")]
        s2a, s2b = os.path.join(d, "a2"), os.path.join(d, "b2")
        if os.path.isdir(s2a) and os.path.isdir(s2b):
            pairs.append((s2a, s2b, "sample 2"))
        return pairs
    return [(os.path.join(d, "a"), os.path.join(d, "b"), "")]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--out", help="where to write the Markdown (default: stdout)")
    a = ap.parse_args(argv)
    pairs = find_pairs(a.dir)
    sections, overalls = [], []
    for a_dir, b_dir, label in pairs:
        text, overall = one_pair(a_dir, b_dir, label)
        sections.append(text)
        overalls.append(overall)
    passed = overalls and all(o is not None and o >= 9 for o in overalls)
    verdict = "PASS: every sample scored every item at 9 or more" if passed else \
        "not a pass: a sample is missing a score, or scored below 9"
    out = "# Gate scorecard\n\n%s\n\n" % verdict + "\n".join(sections)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
