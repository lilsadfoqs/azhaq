#!/usr/bin/env python3
"""grade.py DIR [--json FILE] [--md FILE]: grades experiment A's arms against the answer key.

DIR holds key.json (range's, after up.py), drift-key.json (plan.py's, after
apply.py dropped what did not come up), and eN/ with each arm's output of epoch
N (arms.py, a3.py). Arms: a1 (azhaq watch's change set), a2 (the lines anew
printed as new), a2diff (the same pipe's whole outputs diffed both ways) and a3
(the agent's changes-EN.jsonl). Every arm becomes one list of change records
{kind: new|changed|gone|route, asset, text, ...}; the key's changes are matched
to them:

  new-host   a new record naming the host or its own address
  new-port   a record naming the host (or its address) and the new port
  swap       a record naming the host (or its address) and the new product
  new-vhost  a new record naming the name (its address is the proxy's: no use)
  dangling   a record naming the name and flagging it dangling/takeover
  gone       a gone record naming the name or its address
  deploy     each of the four route lines: the route with its method (a new
             route: POST; a method added: DELETE; a field: role) or, for the
             removed route, the route in a gone record
`hit` is that rule; `seen` is the looser one (any record about the place), and
`by_name` counts hits that name the host (not only its address).
Identification: on a new or swapped surface, the product named (all its
distinctive words in a matched record) and the version (its string).
False changes (E1, E3): distinct records that name no changed place; false
alarms (E2): distinct records of any kind. Also: E0's inventory (context), wall
seconds, wire counts, requests (a1's summary) and tokens (a3's stream).
"""
import argparse
import gzip
import importlib.util
import json
import os
import re
import sys
from urllib.parse import urlparse

import driftlib as dl
import rangelib

ARMS = ["a1", "a2", "a2diff", "a3"]
NEW_SURFACE = ("new-host", "new-port", "swap", "new-vhost")
GENERIC = {"apache", "server", "console", "database", "spring", "framework", "web", "application", "with", "from", "remote",
           "service", "services", "panel", "admin", "project", "platform", "management", "manager", "registry", "app"}
DANGLE = re.compile(r"dangl|take-?over|nxdomain|(does not|doesn.t|not|no longer|never) resolv|unregistered|orphan|unclaimed", re.I)
REMOVED = re.compile(r"\b(gone|removed|no longer|deleted|disappear\w*|dropped|retired)\b", re.I)


def load_json(path, default=None):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def lines(path):
    try:
        with open(path, errors="replace") as f:
            return [x.rstrip("\n") for x in f if x.strip()]
    except OSError:
        return []


# --- records ------------------------------------------------------------------

def parse_asset(s):
    """(host, port) of a URL, host:port or bare name; lower case."""
    s = (s or "").strip()
    if "://" in s:
        u = urlparse(s.split()[0])
        return (u.hostname or "").lower(), u.port or {"http": 80, "https": 443}.get(u.scheme)
    m = re.match(r"^([A-Za-z0-9*._-]+)(?::(\d+))?", s)
    if not m:
        return "", None
    return m.group(1).lower().rstrip("."), int(m.group(2)) if m.group(2) else None


def rec(kind, asset, text="", **kw):
    host, port = parse_asset(asset)
    r = {"kind": kind, "asset": str(asset).strip(), "host": host, "port": port, "ports": [], "text": (str(asset) + " " + text).lower()}
    r.update(kw)
    return r


def last_json(path):
    for line in reversed(lines(path)):
        if line.lstrip().startswith("{"):
            try:
                return json.loads(line)
            except ValueError:
                continue
    return None


def a1_records(d):
    """The change set of azhaq watch -json (docs/commands/watch.md)."""
    o = last_json(os.path.join(d, "a1.json"))
    if o is None:
        return None
    out = []
    for h in o.get("hosts") or []:
        out.append(rec("new", h.split(" (")[0], h, field="hosts"))
    for s in o.get("services") or []:
        out.append(rec("new", s.split(" [")[0], s, field="services"))
    for u in o.get("urls") or []:
        out.append(rec("new", u, field="urls"))
    for p in o.get("ports") or []:
        host, _, ports = p.partition(": ")
        r = rec("changed", host, p, field="ports")
        r["ports"] = [int(x) for x in re.findall(r"\d+", ports)]
        out.append(r)
    for c in o.get("changed") or []:
        out.append(rec("changed", c.split(": [")[0], c, field="changed"))
    for key in ("gone_hosts", "gone_services", "gone_urls"):
        for x in o.get(key) or []:
            out.append(rec("gone", x, field=key))
    for r in o.get("routes") or []:
        out.append(rec("gone" if r.get("kind") == "gone" else "route", r.get("host") or r.get("route", ""), json.dumps(r), route=r.get("route", ""), field="routes"))
    return out


def a2_records(d, diff=False):
    """Lines anew printed as new (the alert); with diff, whole outputs diffed both ways."""
    base = os.path.join(d, "a2")
    if not os.path.isdir(base):
        return None
    out = []
    for st in ("dnsx", "naabu", "httpx", "nuclei"):
        if diff:
            new, gone = lines(os.path.join(base, "diff", st + ".new")), lines(os.path.join(base, "diff", st + ".gone"))
        else:
            new, gone = lines(os.path.join(base, "alerts", st + ".txt")), []
        for kind, ls in (("new", new), ("gone", gone)):
            for line in ls:
                m = re.search(r"https?://\S+", line)
                out.append(rec(kind, m.group(0) if m else line.split()[0], line, stage=st, field=st))
    return out


def a3_records(d, epoch):
    p = os.path.join(d, "a3", "changes-E%d.jsonl" % epoch)
    if not os.path.exists(p):
        return None
    out = []
    for line in lines(p):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if not isinstance(o, dict):
            continue
        kind = str(o.get("kind", "changed")).lower()
        kind = kind if kind in ("new", "changed", "gone") else "changed"
        text = " ".join(str(o.get(k, "")) for k in ("product", "version", "detail"))
        out.append(rec(kind, o.get("asset", ""), text, product=str(o.get("product", "")), version=str(o.get("version", "")), priority=o.get("priority")))
    return out


def inventory_a3(d):
    out = []
    for line in lines(os.path.join(d, "a3", "inventory-E0.jsonl")):
        try:
            o = json.loads(line)
        except ValueError:
            continue
        if isinstance(o, dict):
            out.append(rec("new", o.get("asset", ""), " ".join(str(o.get(k, "")) for k in ("product", "version", "detail"))))
    return out


def inventory_records(arm, d):
    if arm == "a1":
        return a1_records(d)
    if arm == "a2":
        base = os.path.join(d, "a2", "full")
        if not os.path.isdir(base):
            return None
        out = []
        for st in ("dnsx", "naabu", "httpx", "nuclei"):
            for line in lines(os.path.join(base, st + ".txt")):
                m = re.search(r"https?://\S+", line)
                out.append(rec("new", m.group(0) if m else line.split()[0], line, stage=st))
        return out
    if arm == "a3":
        return inventory_a3(d) if os.path.exists(os.path.join(d, "a3", "inventory-E0.jsonl")) else None
    return None


# --- matching -------------------------------------------------------------------

def mentions(r, token):
    return bool(token) and bool(dl.mention_re(token).search(r["text"]))


def has_port(r, port):
    if r.get("port") == port or port in r.get("ports", []):
        return True
    return bool(re.search(r"(:|\bports?\s+)%d(?!\d)" % port, r["text"]))


def norm(s):
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


def product_words(product):
    """The product's name without what it runs behind or beside, and its distinctive words."""
    head = re.split(r"\s+(?:behind|with|via|on)\s+|\(", product or "")[0]
    return norm(head), [w for w in norm(head).split() if len(w) >= 2 and w not in GENERIC]


def names_product(r, product, family=""):
    head, words = product_words(product)
    t = " " + norm(r["text"]) + " "
    if head and (" " + head + " ") in t:
        return True
    if words and all((" " + w + " ") in t for w in words):
        return True
    return bool(family) and (" " + norm(family) + " ") in t


def names_version(r, version):
    return bool(version) and bool(re.search(r"(?<![\d.])" + re.escape(version.lower()) + r"(?!\d)", r["text"]))


def route_re(route):
    parts = re.split(r"\{[^}/]*\}", route)
    ph = r"(?:\{[^}/]*\}|:[A-Za-z_]\w*|<[^>/]*>|\*|\d+|\$\{[^}]*\})"
    return re.compile(ph.join(re.escape(p) for p in parts) + r"(?![\w/-])", re.I)


def match_route(line, recs):
    """(hit, seen) of one deploy route line among the records."""
    rx = route_re(line["route"])
    hit = seen = False
    for r in recs:
        if not rx.search(r["text"]):
            continue
        seen = True
        k = line["kind"]
        if k == "gone":
            ok = r["kind"] == "gone" or bool(REMOVED.search(r["text"]))
        elif r["kind"] == "gone":
            ok = False
        elif k == "new":
            ok = bool(re.search(r"\bpost\b", r["text"]))
        elif k == "methods":
            ok = bool(re.search(r"\bdelete\b", r["text"]))
        else:
            ok = bool(re.search(r"\brole\b", r["text"]))
        hit = hit or ok
    return hit, seen


def place(k, recs, use_addr=True, port=None, kinds=("new", "changed", "route")):
    out = []
    for r in recs:
        if r["kind"] not in kinds:
            continue
        ok = mentions(r, k["name"]) or (use_addr and mentions(r, k.get("address", "")))
        if ok and (port is None or has_port(r, port)):
            out.append(r)
    return out


def match(k, recs, ents):
    """For one key change: {hit, seen, by_name, product, version} (deploy: per line)."""
    c = k["class"]
    ent = ents.get(k.get("env"), {})
    fam = ent.get("family", "")
    res = {"hit": False, "seen": False, "by_name": False, "product": False, "version": False}
    matched = []
    if c == "new-host":
        matched = place(k, recs)
        res["hit"] = res["seen"] = bool(matched)
        res["by_name"] = bool(place(k, recs, use_addr=False))
    elif c == "new-port":
        matched = place(k, recs, port=k["port"])
        res["hit"] = res["seen"] = bool(matched)
        res["by_name"] = bool(place(k, recs, use_addr=False, port=k["port"]))
    elif c == "swap":
        matched = place(k, recs)
        res["seen"] = bool(matched)
        res["hit"] = any(names_product(r, k["product"], fam) for r in matched)
        res["by_name"] = res["hit"] and any(names_product(r, k["product"], fam) for r in place(k, recs, use_addr=False))
    elif c == "new-vhost":
        matched = place(k, recs, use_addr=False)
        res["hit"] = res["seen"] = res["by_name"] = bool(matched)
    elif c == "dangling":
        every = [r for r in recs if mentions(r, k["name"])]
        res["seen"] = bool(every)
        res["hit"] = any(DANGLE.search(r["text"]) for r in every)
        res["by_name"] = res["hit"]
    elif c == "gone":
        every = [r for r in recs if mentions(r, k["name"]) or mentions(r, k.get("address", ""))]
        res["seen"] = bool(every)
        res["hit"] = any(r["kind"] == "gone" for r in every)
        res["by_name"] = any(r["kind"] == "gone" and mentions(r, k["name"]) for r in every)
    if c in NEW_SURFACE:
        res["product"] = any(names_product(r, k["product"], fam) for r in matched)
        res["version"] = any(names_version(r, k["version"]) for r in matched)
    return res


def explained(r, changes):
    for k in changes:
        if k["class"] == "deploy":
            if any(route_re(l["route"]).search(r["text"]) for l in k["routes"]) or mentions(r, k["name"]) or mentions(r, k.get("address", "")):
                return True
        elif mentions(r, k["name"]) or (k["class"] != "new-vhost" and mentions(r, k.get("address", ""))):
            return True
    return False


def distinct(recs):
    return len({(r["kind"], r["asset"].lower()) for r in recs})


def by_field(recs):
    """Distinct records per field of the arm's output (a1's change set field, a2's stage)."""
    out = {}
    for r in recs:
        out.setdefault(r.get("field", "-"), set()).add((r["kind"], r["asset"].lower()))
    return {k: len(v) for k, v in sorted(out.items())}


def grade_epoch(recs, changes, ents):
    """Classes, identification and false changes of one epoch (1 or 3)."""
    classes = {}
    ident = {"of": 0, "product": 0, "version": 0}
    for k in changes:
        c = classes.setdefault(k["class"], {"of": 0, "hit": 0, "seen": 0, "by_name": 0})
        if k["class"] == "deploy":
            for line in k["routes"]:
                hit, seen = match_route(line, recs)
                c["of"] += 1
                c["hit"] += hit
                c["seen"] += seen
                c["by_name"] += hit
            continue
        m = match(k, recs, ents)
        c["of"] += 1
        for f in ("hit", "seen", "by_name"):
            c[f] += m[f]
        if k["class"] in NEW_SURFACE:
            ident["of"] += 1
            ident["product"] += m["product"]
            ident["version"] += m["version"]
    false = [r for r in recs if not explained(r, changes)]
    return {"classes": classes, "identification": ident, "records": len(recs), "false_changes": distinct(false), "false_by_field": by_field(false), "false_list": sorted({r["asset"] for r in false})[:40]}


def inventory(key, recs):
    hosts = [h for h in key["estates"][0]["hosts"] if h.get("kind") == "service" and h.get("up", True)]
    got = ports = tot_ports = 0
    for h in hosts:
        found = [r for r in recs if mentions(r, h["host"]) or (not h.get("vhost") and mentions(r, h.get("address", "")))]
        got += bool(found)
        if h.get("vhost"):
            continue
        for p in h["ports"]:
            tot_ports += 1
            ports += any(r for r in found if has_port(r, p["port"]))
    return {"hosts_of": len(hosts), "hosts": got, "ports_of": tot_ports, "ports": ports, "records": len(recs)}


# --- the run's own numbers -------------------------------------------------------

def host_probes(stream):
    """Commands of the agent that look at the machine instead of the estate (range/grade.py's list)."""
    spec = importlib.util.spec_from_file_location("range_grade", os.path.join(dl.RANGE, "grade.py"))
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("range_grade", mod)
    spec.loader.exec_module(mod)
    out = {}
    try:
        f = gzip.open(stream, "rt", errors="replace")
        with f:
            for line in f:
                i = line.find("{")
                try:
                    o = json.loads(line[i:])
                except ValueError:
                    continue
                it = o.get("item") or {}
                if o.get("type") == "item.completed" and it.get("type") == "command_execution":
                    for label, rx in mod.PROBES:
                        if re.search(rx, it.get("command", "")):
                            out[label] = out.get(label, 0) + 1
    except OSError:
        pass
    return out


def meta(d, arm):
    return load_json(os.path.join(d, "%s.meta.json" % ("a2" if arm == "a2diff" else arm)), {}) or {}


def grade(root):
    key = load_json(os.path.join(root, "key.json"))
    dkey = load_json(os.path.join(root, "drift-key.json"))
    ents = dl.by_id(rangelib.load_catalog())
    res = {"dropped": dkey.get("dropped", 0), "arms": {}}
    for arm in ARMS:
        if arm == "a3" and not any(os.path.isdir(os.path.join(root, "e%d" % e, "a3")) for e in range(4)):
            continue  # a dry run has no agent
        a = {"epochs": {}, "totals": {}}
        for e in range(4):
            d = os.path.join(root, "e%d" % e)
            m = meta(d, arm)
            ent = {"seconds": m.get("seconds"), "wire": m.get("wire"), "exit": m.get("exit")}
            if arm == "a1" and m.get("summary"):
                ent["requests"] = m["summary"].get("requests")
            if arm == "a3":
                ent["tokens"] = m.get("tokens")
            if e == 0:
                recs = inventory_records(arm, d)
                ent["inventory"] = inventory(key, recs) if recs is not None else None
            else:
                recs = {"a1": lambda: a1_records(d), "a2": lambda: a2_records(d), "a2diff": lambda: a2_records(d, True),
                        "a3": lambda: a3_records(d, e)}[arm]()
                ent["missing"] = recs is None
                changes = dkey["epochs"][e]["changes"]
                if e == 2:
                    ent.update({"false_alarms": distinct(recs or []), "false_by_field": by_field(recs or []), "records": len(recs or []), "false_list": sorted({r["asset"] for r in recs or []})[:40]})
                else:
                    ent.update(grade_epoch(recs or [], changes, ents))
            a["epochs"][str(e)] = ent
        a["totals"] = totals(a)
        if arm == "a3":
            a["totals"]["host_probes"] = {}
            for e in range(4):
                for k2, v in host_probes(os.path.join(root, "e%d" % e, "a3", "stream.ts.jsonl.gz")).items():
                    a["totals"]["host_probes"][k2] = a["totals"]["host_probes"].get(k2, 0) + v
        res["arms"][arm] = a
    return res


def totals(a):
    t = {"of": 0, "hit": 0, "seen": 0, "by_name": 0, "classes": {}, "false_changes": 0, "false_alarms": 0, "ident": {"of": 0, "product": 0, "version": 0},
         "wall_s": 0.0, "requests": 0, "tokens": 0, "missing": 0}
    for e, ent in a["epochs"].items():
        t["wall_s"] += ent.get("seconds") or 0
        t["requests"] += ent.get("requests") or 0
        t["tokens"] += sum((ent.get("tokens") or {}).get(x, 0) for x in ("input", "output")) if ent.get("tokens") else 0
        t["missing"] += bool(ent.get("missing"))
        if e == "2":
            t["false_alarms"] += ent.get("false_alarms", 0)
        elif e != "0":
            t["false_changes"] += ent.get("false_changes", 0)
            for c, v in ent.get("classes", {}).items():
                tc = t["classes"].setdefault(c, {"of": 0, "hit": 0, "seen": 0, "by_name": 0})
                for f in tc:
                    tc[f] += v[f]
                    t[f] += v[f]
            for f in t["ident"]:
                t["ident"][f] += ent.get("identification", {}).get(f, 0)
    t["wall_s"] = round(t["wall_s"], 1)
    return t


def md(res):
    out = ["# experiment A, graded", "", "changes dropped because they did not come up: %d" % res["dropped"], ""]
    for arm, a in res["arms"].items():
        t = a["totals"]
        out.append("## %s: recall %d/%d (seen %d), product %d/%d, false changes %d, false alarms %d, wall %ss, requests %s, tokens %s" % (
            arm, t["hit"], t["of"], t["seen"], t["ident"]["product"], t["ident"]["of"], t["false_changes"], t["false_alarms"], t["wall_s"], t["requests"], t["tokens"]))
        for c, v in sorted(t["classes"].items()):
            out.append("- %s: %d/%d (seen %d, by name %d)" % (c, v["hit"], v["of"], v["seen"], v["by_name"]))
        inv = a["epochs"]["0"].get("inventory")
        if inv:
            out.append("- E0 inventory: hosts %d/%d, ports %d/%d" % (inv["hosts"], inv["hosts_of"], inv["ports"], inv["ports_of"]))
        for e in ("1", "2", "3"):
            ent = a["epochs"][e]
            if ent.get("false_by_field"):
                out.append("- E%s records not in the key, by field: %s" % (e, ent["false_by_field"]))
            if ent.get("false_list"):
                out.append("- E%s records not in the key: %s" % (e, ", ".join(ent["false_list"][:15])))
        out.append("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir")
    ap.add_argument("--json")
    ap.add_argument("--md")
    a = ap.parse_args(argv)
    res = grade(a.dir)
    dl.save_json(a.json or os.path.join(a.dir, "grade.json"), res)
    with open(a.md or os.path.join(a.dir, "grade.md"), "w") as f:
        f.write(md(res))
    print("graded %d arms" % len(res["arms"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
