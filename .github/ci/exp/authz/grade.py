#!/usr/bin/env python3
"""grade.py KEY.json ARM_DIR --arm b1|b2|agent [--out grade.json]: grades one arm against the answer key.

A report is normalised to (method, route template): a concrete path matches the key template with
{param} -> [^/]+, the most specific wins; a read with no method is GET. Every flaw counts once. A
report on a route the key calls negative or plain, or on no route of the app, is a false positive.

ARM_DIR holds
  b1     b1.jsonl (azhaq roles -jsonl) and meta.json
  b2     b2.jsonl (autorize.py rows) and meta.json
  agent  findings.jsonl; optionally watch.jsonl (first time each findings line was seen), start.epoch,
         end.epoch, stream.ts.jsonl or .gz (codex --json lines, each led by its epoch second)
meta.json may hold wall_seconds, requests (the arm's own count), server_requests (the app's count).
"""
import argparse
import gzip
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import authzlib as z  # noqa: E402

FLAWS = ["bola-read", "bola-write", "bola-delete", "nested-bola", "idor-query", "bfla", "mass-assignment",
         "data-exposure", "no-auth"]

# The verdicts of `azhaq roles` (docs/commands/roles.md, Verdicts and Write verdicts) that assert a flaw:
# a role reads or writes another role's object, or reads sensitive fields it should not. A report whatever
# its confidence. Every other verdict (signed-in only, only one role reads it, some roles refused,
# every signed-in role reads the same object, same answer for a session that did not find it, different
# fields per role, status differs, create accepted..., the 2xx-but-changed-nothing and the refusal and
# method-not-allowed rows) states a difference or a refusal and is left for a human: a triage item.
B1_ASSERTS = (
    "anyone reads sensitive fields",
    "reads another role's object",
    "answers any identifier",
    "roles read the same sensitive fields",
    "anyone writes another role's object",
    "writes another role's object",  # also its ": accepted; the change cannot be read back to confirm" form
    "creates in another role's collection",
)
B1_NOT_LISTED = ("only its owner writes it", "the owner's own write was refused", "the other roles were refused",
                 "answered 2xx but changed nothing of the owner's", "would be sent (-dry-writes)",
                 "canary rejected")

KIND_CLASSES = {"read-other-object": ["bola-read", "idor-query", "nested-bola"], "write-other-object": ["bola-write"],
                "delete-other-object": ["bola-delete"], "admin-function": ["bfla"],
                "mass-assignment": ["mass-assignment"], "data-exposure": ["data-exposure"], "no-auth": ["no-auth"]}


def b1_asserts(verdict):
    return any(verdict == a or verdict.startswith(a + ":") for a in B1_ASSERTS)


def read_jsonl(path):
    out = []
    try:
        for ln in open(path, errors="replace"):
            ln = ln.strip()
            if ln:
                try:
                    out.append(json.loads(ln))
                except ValueError:
                    pass
    except OSError:
        pass
    return out


def norm_path(text):
    """A concrete or templated path: placeholders in {x}, :x, <x>, [x] become one token."""
    text = re.sub(r"^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+", "", text.strip())
    p = urllib.parse.urlsplit(text).path or text
    p = re.sub(r"\{[^}]*\}|<[^>]*>|\[[^\]]*\]", "X", p)
    p = re.sub(r"/:[A-Za-z_]\w*", "/X", p)
    return p


class Grader:
    def __init__(self, key):
        self.key = key
        self.routes = key["routes"]
        self.m = z.Matcher(self.routes)
        self.by_id = {r["id"]: r for r in self.routes}

    def resolve(self, method, *paths, kind=None):
        """The key route a report names, or None."""
        for text in paths:
            if not text:
                continue
            p = norm_path(text)
            if method:
                r = self.m.find(method.upper(), p)
                if r:
                    return r
            else:
                c = self.m.methods_for(p)
                want = KIND_CLASSES.get(kind, [])
                for r in c:
                    if r["class"] in want:
                        return r
                for r in c:
                    if r["method"] == "GET":
                        return r
        return None

    def grade(self, reports):
        """reports: list of dicts {method, paths, kind, tag}. Returns the shared part of the grade."""
        found, fps, matched_tags = {}, {}, {}
        for rep in reports:
            r = self.resolve(rep.get("method"), *rep["paths"], kind=rep.get("kind"))
            if r is None:
                fps.setdefault(("unmatched", (rep.get("method") or "GET").upper() + " " + norm_path(next((p for p in rep["paths"] if p), ""))), []).append(rep)
            elif r["class"] in FLAWS:
                found.setdefault(r["id"], []).append(rep)
            else:
                fps.setdefault((r["class"], r["id"]), []).append(rep)
        flaws = [r for r in self.routes if r["class"] in FLAWS]
        by_class = {c: {"total": 0, "found": 0} for c in FLAWS}
        by_vis = {v: {"total": 0, "found": 0} for v in ("journey", "js-only", "unlinked")}
        for r in flaws:
            by_class[r["class"]]["total"] += 1
            by_vis[r["visibility"]]["total"] += 1
            if r["id"] in found:
                by_class[r["class"]]["found"] += 1
                by_vis[r["visibility"]]["found"] += 1
        fp_trap = {}
        for (cls, rid), _ in fps.items():
            if cls == "negative":
                t = self.by_id[rid]["trap"]
                fp_trap[t] = fp_trap.get(t, 0) + 1
        g = {
            "flaws": len(flaws), "found": len(found), "recall": round(len(found) / len(flaws), 3) if flaws else None,
            "by_class": by_class, "by_visibility": by_vis,
            "false_positives": len(fps),
            "fp_negative": sum(1 for (c, _) in fps if c == "negative"),
            "fp_plain": sum(1 for (c, _) in fps if c == "plain"),
            "fp_unmatched": sum(1 for (c, _) in fps if c == "unmatched"),
            "fp_by_trap": fp_trap,
            "found_ids": sorted(found), "missed_ids": sorted(r["id"] for r in flaws if r["id"] not in found),
            "reports": sum(len(v) for v in found.values()) + sum(len(v) for v in fps.values()),
        }
        return g, found


def usage_tokens(path):
    """Sums the usage of codex --json's turn.completed events; None when there is no stream."""
    opener = gzip.open if path.endswith(".gz") else open
    tot, seen = {}, False
    try:
        with opener(path, "rt", errors="replace") as f:
            for ln in f:
                _, _, js = ln.partition(" ")
                if '"turn.completed"' not in js:
                    continue
                try:
                    u = json.loads(js).get("usage") or {}
                except ValueError:
                    continue
                seen = True
                for k, v in u.items():
                    if isinstance(v, int):
                        tot[k] = tot.get(k, 0) + v
    except OSError:
        return None
    return tot if seen else None


def first_last_epoch(path):
    opener = gzip.open if path.endswith(".gz") else open
    first = last = None
    try:
        with opener(path, "rt", errors="replace") as f:
            for ln in f:
                w = ln.split(" ", 1)[0]
                if w.isdigit():
                    first = first if first is not None else int(w)
                    last = int(w)
    except OSError:
        pass
    return first, last


def meta_of(d):
    for name in ("meta.json",):
        try:
            return json.load(open(os.path.join(d, name)))
        except (OSError, ValueError):
            pass
    return {}


def key_of(gr, method, *paths):
    rt = gr.resolve(method, *paths)
    return (rt["method"], rt["template"]) if rt else (method, norm_path(paths[0] if paths and paths[0] else ""))


def pending(gr, reports, doubtful):
    """Triage items: routes some row left to a human and no report names."""
    reported = {key_of(gr, r["method"], *r["paths"]) for r in reports}
    return len({key_of(gr, m, p) for (m, p) in doubtful} - reported)


def grade_b1(gr, d):
    rows = read_jsonl(os.path.join(d, "b1.jsonl"))
    reports, doubtful = [], []
    for row in rows:
        v = row.get("verdict", "")
        method = (row.get("method") or "GET").upper()
        paths = [p for p in (row.get("template"), row.get("url")) if p]
        if b1_asserts(v):
            reports.append({"method": method, "paths": paths, "conf": row.get("confidence", "none")})
        elif not any(v.startswith(x) for x in B1_NOT_LISTED):
            doubtful.append((method, paths[-1] if paths else ""))
    g, found = gr.grade(reports)
    conf_all, conf_true = {}, {}
    for rep in reports:
        conf_all[rep["conf"]] = conf_all.get(rep["conf"], 0) + 1
    for reps in found.values():
        for c in {r["conf"] for r in reps}:
            conf_true[c] = conf_true.get(c, 0) + 1
    g["triage"] = pending(gr, reports, doubtful)
    g["confidence_all_reports"] = conf_all
    g["confidence_of_true_flaws"] = conf_true
    g["rows"] = len(rows)
    return g


def grade_b2(gr, d):
    rows = read_jsonl(os.path.join(d, "b2.jsonl"))
    reports, doubtful = [], []
    for row in rows:
        method = row["method"].upper()
        if row["verdict"] == "Bypassed!":
            reports.append({"method": method, "paths": [row["url"]]})
        elif row["verdict"].startswith("Is enforced"):
            doubtful.append((method, row["url"]))
    g, _ = gr.grade(reports)
    g["triage"] = pending(gr, reports, doubtful)
    g["rows"] = len(rows)
    return g


def grade_agent(gr, d):
    reports, n = [], 0
    try:
        raw_lines = [ln.strip() for ln in open(os.path.join(d, "findings.jsonl"), errors="replace") if ln.strip()]
    except OSError:
        raw_lines = []
    for raw in raw_lines:
        try:
            ln = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(ln, dict):
            continue
        n += 1
        kind, method = ln.get("kind"), ln.get("method")
        if not method and kind in ("read-other-object", "data-exposure", "no-auth"):
            method = "GET"
        reports.append({"method": method, "paths": [ln.get("route"), ln.get("url")], "kind": kind, "raw": raw})
    g, found = gr.grade(reports)
    g["triage"] = 0
    g["rows"] = n
    g["kind_mismatch"] = 0
    for rid, reps in found.items():
        want = {c for c, cl in KIND_CLASSES.items() if gr.by_id[rid]["class"] in cl}
        if want and not any(r.get("kind") in want for r in reps):
            g["kind_mismatch"] += 1
    # time to first true flaw: when the earliest findings line that names a flaw was first seen
    start = None
    try:
        start = int(open(os.path.join(d, "start.epoch")).read().strip())
    except (OSError, ValueError):
        pass
    watch = {}
    for w in read_jsonl(os.path.join(d, "watch.jsonl")):
        watch.setdefault((w.get("line") or "").strip(), w.get("t"))
    times = [t for reps in found.values() for t in (watch.get(r["raw"]) for r in reps) if t is not None]
    g["first_true_seconds"] = (min(times) - start) if (times and start is not None) else None
    return g


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("key")
    ap.add_argument("arm_dir")
    ap.add_argument("--arm", required=True, choices=["b1", "b2", "agent"])
    ap.add_argument("--out")
    a = ap.parse_args(argv)
    gr = Grader(json.load(open(a.key)))
    d = a.arm_dir
    g = {"b1": grade_b1, "b2": grade_b2, "agent": grade_agent}[a.arm](gr, d)
    g["arm"] = a.arm
    meta = meta_of(d)
    if a.arm in ("b1", "b2"):
        g["wall_seconds"] = meta.get("wall_seconds")
        g["first_true_seconds"] = meta.get("wall_seconds") if g["found"] else None
        g["requests"] = meta.get("server_requests", meta.get("requests"))
        g["tokens"] = None
    else:
        stream = next((os.path.join(d, n) for n in ("stream.ts.jsonl", "stream.ts.jsonl.gz")
                       if os.path.exists(os.path.join(d, n))), None)
        g["tokens"] = usage_tokens(stream) if stream else None
        f, l = first_last_epoch(stream) if stream else (None, None)
        try:
            e = int(open(os.path.join(d, "end.epoch")).read().strip())
            s = int(open(os.path.join(d, "start.epoch")).read().strip())
            g["wall_seconds"] = e - s
        except (OSError, ValueError):
            g["wall_seconds"] = (l - f) if f is not None else None
        g["requests"] = meta.get("server_requests")
    out = a.out or os.path.join(d, "grade.json")
    json.dump(g, open(out, "w"), indent=1, sort_keys=True)
    print("grade %s: %d/%d flaws, %d false positives, %d to triage" % (a.arm, g["found"], g["flaws"],
                                                                      g["false_positives"], g["triage"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
