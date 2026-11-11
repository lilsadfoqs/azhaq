#!/usr/bin/env python3
"""merge_gate.py DIR [--samples N] [--control] [--out OUT.md]: merges the gate's
scorecards into one table. DIR is what `fetch.sh trial NAME DIR` wrote:
DIR/a (part A, REPORT.md and, when graded, grade.json) and DIR/b (part B,
REPORT.md).

For `samples=N` (N up to 4), DIR holds N pairs: DIR/a1+DIR/b1 ...
DIR/aN+DIR/bN (DIR/a+DIR/b when there is only one sample). Every sample's
scorecard is printed, after a table of each item's scores, median and
spread across the samples. The verdict is not made from the medians: it is
the lowest score of every sample. A sample that is missing (a gap in the
numbers, one part only, or fewer than --samples N) is named and is not a pass.

Each scorecard row (a Markdown table `| Item | Score | Reasoning |` in
REPORT.md, as GATE.md asks for) is read beside the anchor line its score
falls into, part B's switch areas first, then part A's, then one overall
(the lowest of every score read: the gate needs all of them at 9 or more).
Part A's grade.json, when it holds a `baseline_comparison` (grade.py
--baseline), is summarised beside the scorecard.

A control's folder (a `control` trial: the same brief, another candidate;
.github/ci/trial/README.md) is merged the same way. It is found by the kind
in its scores.json records, or forced with --control. Its title says
"Control scorecard" and it has no gate verdict: the per-item medians are what
is read, against 9 in the areas where the control is the usual tools.

Rows GATE.md did not ask for, or a REPORT.md with no parseable table, are
listed for a person to judge instead of guessed at.
"""
import argparse
import json
import os
import re
import statistics
import sys

MAX_SAMPLES = 4

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
PART_A_ITEMS = ["findings", "time to the first finding",
                "signal versus noise", "trust", "would use on the next engagement"]
PART_B_ITEMS = ["install and first run", "docs", "subdomain recon", "host and port discovery",
                "web and api mapping", "signed-in and multi-role testing",
                "output and integration (including assistants)",
                "reliability (crashes, hangs, wrong data, silent failures)",
                "performance (time, memory and cpu, and the requests it sends to the target for the same result)"]

CONTROL_NAME = "orvel"

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


def baseline_table(entries, candidate="azhaq"):
    """Part A's grade beside its baseline: a table of (sample, comparison)
    entries, one row per sample and phase; the Sample column is left out when
    no entry has a sample label."""
    labelled = any(label for label, _ in entries)
    head = (["Sample"] if labelled else []) + ["Phase", "Vulns identified", "Leads", "Time to first match", "Commands", "Same seed"]
    o = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for label, c in entries:
        row = "%d | %d vs %d (of %s) | %d vs %d | %s vs %s | %d vs %d | %s" % (
            c["phase"], c["vulns_identified"][0], c["vulns_identified"][1],
            " and ".join(str(x) for x in c["vulns_of"]), c["leads_total"][0], c["leads_total"][1],
            c["first_match_s"][0], c["first_match_s"][1], c["commands_total"][0], c["commands_total"][1],
            "yes" if c["same_seed"] else "NO, not a fair comparison")
        o.append("| " + (label + " | " if labelled else "") + row + " |")
    o += ["", "Each column reads \"%s vs baseline\"." % candidate]
    return o


NO_BASELINE = "Part A was graded, but with no --baseline: run grade.py again with the pool estate's baseline grade.json to compare."


def one_pair(a_dir, b_dir, label="", with_grade=True, control=False):
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
        o.append("| **overall** | **%d** | %s | the lowest of the rows above%s |"
                  % (overall, anchor_for(overall), "" if control else ": the gate needs every one at 9 or more"))
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
    if with_grade and grade and grade.get("baseline_comparison"):
        o += ["", "### Part A's grade beside its baseline", ""]
        o += baseline_table([("", c) for c in grade["baseline_comparison"]], CONTROL_NAME if control else "azhaq")
    elif with_grade and grade:
        o += ["", NO_BASELINE]
    return "\n".join(o) + "\n", overall


def find_pairs(d):
    """[(a_dir, b_dir, label)] for every sample K (1..MAX_SAMPLES) with both
    DIR/aK and DIR/bK, else the one flat DIR/a + DIR/b."""
    pairs = []
    for k in range(1, MAX_SAMPLES + 1):
        ak, bk = os.path.join(d, "a%d" % k), os.path.join(d, "b%d" % k)
        if os.path.isdir(ak) and os.path.isdir(bk):
            pairs.append((ak, bk, "sample %d" % k))
    return pairs or [(os.path.join(d, "a"), os.path.join(d, "b"), "")]


def is_control_dir(pairs):
    """True when a sample's scores.json (fetch.sh decrypts it beside REPORT.md) says kind control-a or control-b."""
    for a_dir, b_dir, _ in pairs:
        for d in (a_dir, b_dir):
            try:
                with open(os.path.join(d, "scores.json"), encoding="utf-8") as f:
                    if str(json.load(f).get("kind", "")).startswith("control"):
                        return True
            except (OSError, ValueError, AttributeError):
                continue
    return False


def missing_samples(d, pairs, expected=0):
    """What is wrong with the samples found: a sample with one part only, a gap
    in the numbers, or fewer than EXPECTED. A flat a/b has none."""
    found = {int(label.split()[1]) for _, _, label in pairs if label}
    if not found:
        return []
    notes = []
    for k in range(1, MAX_SAMPLES + 1):
        if k in found:
            continue
        has_a, has_b = os.path.isdir(os.path.join(d, "a%d" % k)), os.path.isdir(os.path.join(d, "b%d" % k))
        if has_a != has_b:
            notes.append("sample %d has part %s only" % (k, "A" if has_a else "B"))
        elif k < max(found) or k <= expected:
            notes.append("sample %d is missing" % k)
    return notes


def item_scores(a_dir, b_dir):
    """[(item, score or None)] of one sample, part B's items first as in the scorecard."""
    a_rows, _ = parse_scorecard(read(os.path.join(a_dir, "REPORT.md")) or "")
    b_rows, _ = parse_scorecard(read(os.path.join(b_dir, "REPORT.md")) or "")
    matched = match_items(b_rows, PART_B_ITEMS)[0] + match_items(a_rows, PART_A_ITEMS)[0]
    return [(item, score) for item, score, _ in matched]


def num(x):
    return "%g" % x


def medians_section(per_sample, control=False):
    """The per-item table over PER_SAMPLE, a list of item_scores lists (one per
    sample); returns its lines. Medians and spreads use the scored cells only."""
    n = len(per_sample)
    why = ("The gate verdict is not made from these: it is still the lowest score of every sample "
           "(9 or more to pass); the medians are reported, not used for it.")
    if control:
        why = ("There is no gate verdict. Read each median against 9 in the areas where the control is identical "
               "to the usual tools (.github/ci/trial/README.md).")
    o = ["## Per-item medians", "",
         "Across %d samples. %s" % (n, why), "",
         "| Item | Scores (sample 1 to %d) | Median | Spread |" % n, "|---|---|---|---|"]
    medians = []
    for i, (item, _) in enumerate(per_sample[0]):
        cells = [s[i][1] for s in per_sample]
        got = [c for c in cells if c is not None]
        shown = "/".join("-" if c is None else str(c) for c in cells)
        if got:
            med = statistics.median(got)
            medians.append((med, item))
            o.append("| %s | %s | %s | %d |" % (item, shown, num(med), max(got) - min(got)))
        else:
            o.append("| %s | %s | - | - |" % (item, shown))
    if medians:
        low = min(m for m, _ in medians)
        o += ["", "Lowest per-item median: %s (%s)." % (num(low), ", ".join(i for m, i in medians if m == low))]
    else:
        o += ["", "Lowest per-item median: none, no score was parsed."]
    return o


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--samples", type=int, default=0, help="how many samples the review ran: fewer found is not a pass")
    ap.add_argument("--control", action="store_true", help="a control's folder (found by its scores.json records when not given)")
    ap.add_argument("--out", help="where to write the Markdown (default: stdout)")
    a = ap.parse_args(argv)
    pairs = find_pairs(a.dir)
    control = a.control or is_control_dir(pairs)
    many = len(pairs) > 1
    sections, overalls, per_sample, grades = [], [], [], []
    for a_dir, b_dir, label in pairs:
        text, overall = one_pair(a_dir, b_dir, label, with_grade=not many, control=control)
        sections.append(text)
        overalls.append(overall)
        per_sample.append(item_scores(a_dir, b_dir))
        grades.append((label.replace("sample ", ""), load_grade(a_dir)))
    notes = missing_samples(a.dir, pairs, a.samples)
    passed = overalls and not notes and all(o is not None and o >= 9 for o in overalls)
    if notes:
        verdict = "not a pass: %s" % "; ".join(notes)
    elif passed:
        verdict = "PASS: every sample scored every item at 9 or more"
    else:
        verdict = "not a pass: a sample is missing a score, or scored below 9"
    if control:
        verdict = ("a measurement of the scale, not a gate or a review of azhaq: %s" % ("every sample scored every item at 9 or more" if passed
                   else "not every sample scored every item at 9 or more"))
        if notes:
            verdict += "; " + "; ".join(notes)
    head = []
    if many:
        head += medians_section(per_sample, control) + [""]
        graded = [(label, g) for label, g in grades if g]
        if graded:
            head += ["## Part A's grade beside its baseline", ""]
            entries = [(label, c) for label, g in graded for c in g.get("baseline_comparison") or []]
            if entries:
                head += baseline_table(entries, CONTROL_NAME if control else "azhaq")
            ungraded = [label for label, g in graded if not g.get("baseline_comparison")]
            if ungraded:
                head += ["", "Sample %s: %s" % (", ".join(ungraded), NO_BASELINE)]
            head.append("")
    out = ("# %s scorecard\n\n%s\n\n" % ("Control" if control else "Gate", verdict)
           + ("\n".join(head) + "\n" if head else "") + "\n".join(sections))
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(out)
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
