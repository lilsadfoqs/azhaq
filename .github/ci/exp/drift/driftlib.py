"""Shared pieces of experiment A (drift): paths, the live-estate model, and the
ops that change it. Python 3 standard library only; the range scripts are
imported, not copied.

A model is what the estate holds right now: the DNS zones, the environments
that run, the proxy's routes and the deploy app's version. plan.py builds one
per epoch to check the budget; apply.py keeps one (live.json) next to the real
estate and renders its files.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
RANGE = os.path.abspath(os.path.join(HERE, "..", "..", "range"))
if RANGE not in sys.path:
    sys.path.append(RANGE)  # after this folder: grade.py and plan.py here are not the range's

import build  # noqa: E402
import rangelib  # noqa: E402

CLASSES = ["new-host", "new-port", "swap", "new-vhost", "dangling", "gone", "deploy"]
DEPLOY_PORT = 8080
DEPLOY_LABELS = ["api", "app", "portal", "orders"]
# The four route changes of bench/truth/deploy/expected.md, v1 -> v2.
DEPLOY_ROUTES = [
    {"kind": "new", "method": "POST", "route": "/api/v2/export", "fields": ["format", "userId"]},
    {"kind": "methods", "method": "DELETE", "route": "/api/orders/{id}", "fields": []},
    {"kind": "fields", "method": "PUT", "route": "/api/profile", "fields": ["role"]},
    {"kind": "gone", "method": "", "route": "/api/legacy/report", "fields": []},
]
CLOUDS = ["azurewebsites.net", "trafficmanager.net", "azureedge.net", "cloudapp.net"]
BASE_MB = 60  # the proxy, the resolver and the deploy app


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(path, doc):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, sort_keys=False)


def by_id(cat):
    return {e["id"]: e for e in cat["entries"]}


def mem(e):
    return e.get("mem_mb_measured") or e["mem_mb"]


def primary(e):
    return next(p for p in e["ports"] if p["primary"])


def fq(name):
    return name if name.endswith(".") else name + "."


def host_key(h):
    return h["host"].lower().rstrip(".")


# --- the model -----------------------------------------------------------

def model_from_files(est):
    """The estate as plan.py wrote it and up.py started it (epoch 0)."""
    plan = load_json(os.path.join(est, "plan.json"))
    key = load_json(os.path.join(est, "key.json"))
    dplan = load_json(os.path.join(est, "drift-plan.json"))
    cat = rangelib.load_catalog()
    ents = by_id(cat)
    zone = load_json(os.path.join(est, "zone-1.json"))
    envs = {e["id"]: e for e in plan["envs"]}
    routes = []
    for h in key["estates"][0]["hosts"]:
        if h.get("vhost"):
            routes.append([h["host"], primary(ents[h["env"]])["host_port"], envs[h["env"]]["address"]])
    proxy = plan["proxies"][0]
    return {"apex": key["estates"][0]["domain"], "net": key["estates"][0]["net"], "proxy": proxy, "zone": zone,
            "envs": envs, "routes": routes, "deploy": dict(dplan["deploy"], version="v1"),
            "ns": [n["address"] for n in key["estates"][0]["ns"]]}


def render_conf(model):
    return build.proxy_conf(model["proxy"]["address"], [tuple(r) for r in model["routes"]])


def model_mem(model, ents):
    return BASE_MB + sum(mem(ents[i]) for i in model["envs"])


def zone_op(model, op):
    z = model["zone"]
    kind = op[0]
    if kind == "set":
        _, origin, name, recs = op
        z["zones"].setdefault(origin, {})[name] = list(recs)
    elif kind == "del":
        _, origin, name = op
        z["zones"].get(origin, {}).pop(name, None)
    elif kind == "ptr_set":
        _, origin, octet, names = op
        z.setdefault("ptr", {}).setdefault(origin, {})[octet] = list(names)
    elif kind == "ptr_del":
        _, origin, octet = op
        z.get("ptr", {}).get(origin, {}).pop(octet, None)
    else:
        raise ValueError("unknown zone op " + kind)


def apply_change(model, ch):
    """One change's effect on the model (what the files and containers become)."""
    for eid in ch.get("envs_down", []):
        model["envs"].pop(eid, None)
    for e in ch.get("envs_up", []):
        model["envs"][e["id"]] = e
    for op in ch.get("zone", []):
        zone_op(model, op)
    for r in ch.get("routes_add", []):
        model["routes"].append(list(r))
    for h in ch.get("routes_del", []):
        model["routes"] = [r for r in model["routes"] if r[0] != h]
    if ch.get("deploy"):
        model["deploy"]["version"] = ch["deploy"]
    return model


def reorder(recs):
    """Reverses the records of each type that has several, keeping the types' places."""
    slots = {}
    for i, r in enumerate(recs):
        slots.setdefault(r.split(" ", 1)[0].upper(), []).append(i)
    out = list(recs)
    for idx in slots.values():
        vals = [recs[i] for i in idx][::-1]
        for i, v in zip(idx, vals):
            out[i] = v
    return out


def dns_churn(model):
    """Benign DNS churn: multi-record answers in another order, and the SOA's
    serial and timers changed (labdns fixes every record's TTL at 60, so the
    timers are what a TTL change leaves of it)."""
    for names in model["zone"]["zones"].values():
        for n, recs in names.items():
            if len(recs) > 1:
                names[n] = reorder(recs)
            for i, r in enumerate(names[n]):
                p = r.split()
                if p[0].upper() == "SOA" and len(p) == 8:
                    p[3] = str(int(p[3]) + 1)
                    p[4], p[5], p[7] = str(int(p[4]) * 2), str(int(p[5]) + 300), str(int(p[7]) * 2)
                    names[n][i] = " ".join(p)
    return model


# --- the fence ------------------------------------------------------------

def live_key(model, ents, base_key):
    """A key and plan in the shape up.fence_rules reads, for what runs now."""
    hosts = []
    for eid, e in model["envs"].items():
        if e.get("backend"):
            continue
        remap = {int(k): v for k, v in e["remap"].items()}
        hosts.append({"address": e["address"], "ports": [
            {"port": remap.get(p["host_port"], p["host_port"]), "transport": p["transport"]} for p in ents[eid]["ports"]]})
    hosts.append({"address": model["proxy"]["address"], "ports": [{"port": 80, "transport": "tcp"}]})
    d = model["deploy"]
    hosts.append({"address": d["address"], "ports": [{"port": d["port"], "transport": "tcp"}]})
    est = base_key["estates"][0]
    key = {"estates": [{"net": est["net"], "hosts": hosts, "ns": est["ns"]}]}
    return key, {"envs": list(model["envs"].values())}


def fence_for(key, plan, chain, users):
    """up.fence_rules in a chain of this name (swapped in whole, so a fence is never half there),
    with the backend rules repeated for each user that must not reach the proxy's backends."""
    import up
    rules = [list(r) for r in up.fence_rules(key, plan, users[0])]
    out = []
    for r in rules:
        out.append([chain if x == "AZQ" else x for x in r])
        if "--uid-owner" in r:
            for u in users[1:]:
                out.append([chain if x == "AZQ" else (u if x == users[0] else x) for x in r])
    return out


# --- text helpers shared by the grader ---------------------------------------

def mention_re(name):
    """A name or address as a whole token: x.corp.test is not in y.x.corp.test, 1.2.3.4 is not in 1.2.3.45."""
    return re.compile(r"(?<![A-Za-z0-9.-])" + re.escape(name.lower().rstrip(".")) + r"(?![A-Za-z0-9-])(?!\.[A-Za-z0-9])")


# --- wire counters -------------------------------------------------------------
# One ruler for every arm: what each sent toward the estate, counted by the
# kernel (TCP connection attempts and UDP datagrams to the estate's range, and
# DNS to its resolver). The counting chain is called from the top of every
# fence chain, so a refused attempt is counted too.

COUNTERS = ["tcp_syn", "udp", "dns_resolver"]


def counter_rules(net, dns_port):
    return [["-N", "AZCNT"],
            ["-A", "AZCNT", "-d", net, "-p", "tcp", "--syn"],
            ["-A", "AZCNT", "-d", net, "-p", "udp"],
            ["-A", "AZCNT", "-d", "127.0.0.1", "-p", "udp", "--dport", str(dns_port)],
            ["-A", "AZCNT", "-d", "127.0.0.1", "-p", "tcp", "--dport", str(dns_port)]]


def counters_setup(net, dns_port, run=rangelib.sh):
    run(["sudo", "-n", "iptables", "-N", "AZCNT"])
    run(["sudo", "-n", "iptables", "-F", "AZCNT"])
    for r in counter_rules(net, dns_port)[1:]:
        run(["sudo", "-n", "iptables"] + r)


def parse_counters(text):
    """pkts of the four rules of `iptables -L AZCNT -n -v -x`, as the three counters."""
    pk = []
    for line in text.splitlines():
        p = line.split()
        if len(p) >= 8 and p[0].isdigit() and p[1].isdigit():
            pk.append(int(p[0]))
    if len(pk) < 4:
        return None
    return {"tcp_syn": pk[0], "udp": pk[1], "dns_resolver": pk[2] + pk[3]}


def counters_read(run=rangelib.sh):
    rc, out = run(["sudo", "-n", "iptables", "-L", "AZCNT", "-n", "-v", "-x"])
    return parse_counters(out) if rc == 0 else None


def counters_delta(a, b):
    if not a or not b:
        return None
    return {k: b[k] - a[k] for k in COUNTERS}
