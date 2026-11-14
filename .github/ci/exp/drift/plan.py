#!/usr/bin/env python3
"""plan.py SEED --out DIR: plans experiment A's estate and its four epochs.

One estate from range/build.py (--count 1, a small --size), plus the deploy
app (bench/truth/deploy, at v1) as one more host with its own address and
name, an alias CNAME to a cloud name that resolves, and a second TXT on the
apex. Then four epochs, deterministic from SEED:
  E0  the base
  E1  mutations M1        E3  mutations M2   (together: every class once,
                                              3 or 4 changes each)
  E2  no real change: restarts, DNS answers in another order, SOA timers.
The classes are the real-world ones of the protocol (new host, new port, swap,
new vhost, dangling CNAME, host gone, deploy); no choice looks at what any
tool reports. Peak memory of every epoch must fit --cap-mb.

Writes to DIR, besides build.py's files (key.json, plan.json, vars.json,
zone-1.json, proxy-1.conf, overrides/):
  drift-key.json    per epoch, each change with class, name, address, port,
                    product, version (a deploy: the four route lines)
  drift-plan.json   what apply.py runs per epoch
Nothing of it is printed except counts: the job log is public.
"""
import argparse
import copy
import json
import os
import random
import sys

import driftlib as dl
import build
import rangelib


class Skip(Exception):
    """This draw cannot make the change; plan() draws again."""


class Draw:
    def __init__(self, rng, model, key, cat):
        self.rng, self.cat, self.ents = rng, cat, dl.by_id(cat)
        self.model = model
        est = key["estates"][0]
        self.apex = est["domain"]
        self.hosts = est["hosts"]
        self.used_env = set(model["envs"])
        self.fams = {self.ents[i]["family"] for i in model["envs"]}
        self.labels = {n.split(".")[0] for n in model["zone"]["zones"][dl.fq(self.apex)]} | {"www", "ns1", "ns2", "mail", "mx"}
        self.addrs = {h["address"] for h in self.hosts if h.get("address")} | set(model["ns"]) | {model["proxy"]["address"]}
        self.ports = {}
        for h in self.hosts:
            if h.get("kind") == "service" and not h.get("vhost"):
                self.ports.setdefault(h["address"], set()).update(p["port"] for p in h["ports"])
        self.mx = {r.split()[-1].rstrip(".").lower() for r in model["zone"]["zones"][dl.fq(self.apex)][dl.fq(self.apex)] if r.upper().startswith("MX ")}
        direct = [h for h in self.hosts if h.get("kind") == "service" and not h.get("vhost") and h.get("env") in model["envs"]]
        rng.shuffle(direct)
        self.direct = direct
        backs = [e["address"] for e in model["envs"].values() if e.get("backend")]
        self.hidden = backs[0].rsplit(".", 1)[0] if backs else "127.200.0"
        self.back_n = max([int(a.rsplit(".", 1)[1]) for a in backs] + [9])
        self.ptr_origin = "%s.in-addr.arpa." % ".".join(reversed(model["net"].split("/")[0].rsplit(".", 1)[0].split(".")))
        self.base = model["net"].split("/")[0].rsplit(".", 1)[0]

    def fresh(self, test=lambda e: True):
        out = [e for e in self.cat["entries"] if e["family"] not in self.fams and e["id"] not in self.used_env and test(e)]
        if not out:
            raise Skip("no fresh entry")
        return out

    def take(self, e):
        self.used_env.add(e["id"])
        self.fams.add(e["family"])

    def label(self, e):
        opts = [n for n in e["names"] if n not in self.labels]
        if opts and self.rng.random() < 0.5:
            lab = self.rng.choice(opts)
        else:
            lab = self.rng.choice([n for n in build.NEUTRAL if n not in self.labels])
        self.labels.add(lab)
        return lab

    def addr(self):
        free = [o for o in range(10, 251) if "%s.%d" % (self.base, o) not in self.addrs]
        a = "%s.%d" % (self.base, self.rng.choice(free))
        self.addrs.add(a)
        return a

    def direct_host(self, ok=lambda h: True):
        for i, h in enumerate(self.direct):
            if ok(h):
                return self.direct.pop(i)
        raise Skip("no host")

    def env(self, e, addr, remap=None, backend=False):
        pe = build.plan_env(1, e, addr, remap or {}, backend=backend)
        return pe

    def ptr_maybe(self, addr, name, ops):
        if self.rng.random() < 0.35:
            ops.append(["ptr_set", self.ptr_origin, addr.rsplit(".", 1)[1], [dl.fq(name)]])


def ports_of(e, remap=None):
    remap = remap or {}
    return [remap.get(p["host_port"], p["host_port"]) for p in e["ports"]]


def mk_new_host(d):
    e = d.rng.choice(d.fresh())
    d.take(e)
    name = d.label(e) + "." + d.apex
    addr = d.addr()
    remap = {}
    prim = dl.primary(e)
    if prim["protocol"] in ("http", "https") and d.rng.random() < 0.3:
        opts = [p for p in build.PORT_POOL if p not in {x["host_port"] for x in e["ports"]}]
        remap[prim["host_port"]] = d.rng.choice(opts)
    zone = [["set", dl.fq(d.apex), dl.fq(name), ["A " + addr]]]
    d.ptr_maybe(addr, name, zone)
    ch = {"envs_up": [d.env(e, addr, remap)], "zone": zone}
    k = {"name": name, "address": addr, "port": remap.get(prim["host_port"], prim["host_port"]), "ports": ports_of(e, remap),
         "product": e["product"], "version": e["version"], "env": e["id"]}
    return ch, k


def mk_new_port(d):
    h = d.direct_host()
    used = d.ports.get(h["address"], set())
    e = d.rng.choice(d.fresh(lambda e: not (set(ports_of(e)) & used) and len(e["ports"]) <= 3))
    d.take(e)
    d.ports[h["address"]] = used | set(ports_of(e))
    ch = {"envs_up": [d.env(e, h["address"])]}
    k = {"name": h["host"], "address": h["address"], "port": dl.primary(e)["host_port"], "ports": ports_of(e),
         "product": e["product"], "version": e["version"], "env": e["id"]}
    return ch, k


def mk_swap(d):
    h = d.direct_host()
    old = d.ents[h["env"]]
    same = [e for e in d.cat["entries"] if e["family"] == old["family"] and e["id"] != old["id"] and e["id"] not in d.used_env]
    if same:
        e = d.rng.choice(same)
    else:
        cat = [e for e in d.fresh() if e["category"] == old["category"]]
        e = d.rng.choice(cat or d.fresh())
    d.take(e)
    if e["family"] != old["family"]:
        d.fams.discard(old["family"])
    ch = {"envs_down": [old["id"]], "envs_up": [d.env(e, h["address"])]}
    k = {"name": h["host"], "address": h["address"], "port": dl.primary(e)["host_port"], "ports": ports_of(e),
         "product": e["product"], "version": e["version"], "old_product": old["product"], "old_version": old["version"],
         "same_family": e["family"] == old["family"], "env": e["id"]}
    return ch, k


def mk_new_vhost(d):
    e = d.rng.choice(d.fresh(lambda e: e["proxy"] and any(p["primary"] and p["protocol"] == "http" for p in e["ports"])))
    d.take(e)
    name = d.label(e) + "." + d.apex
    d.back_n += 1
    back = "%s.%d" % (d.hidden, d.back_n)
    if d.rng.random() < 0.4:
        rec = "CNAME www." + dl.fq(d.apex)
    else:
        rec = "A " + d.model["proxy"]["address"]
    ch = {"envs_up": [d.env(e, back, backend=True)], "routes_add": [[name, dl.primary(e)["host_port"], back]],
          "zone": [["set", dl.fq(d.apex), dl.fq(name), [rec]]]}
    k = {"name": name, "address": d.model["proxy"]["address"], "port": 80, "product": e["product"], "version": e["version"], "env": e["id"]}
    return ch, k


def mk_dangling(d, alias):
    mode = d.rng.choice(["target-gone", "new-cname"])
    if mode == "target-gone":
        ch = {"zone": [["del", alias["origin"], alias["target"]]]}
        k = {"name": alias["name"].rstrip("."), "target": alias["target"].rstrip("."), "mode": mode}
        return ch, k
    free = [n for n in build.DANGLING_NAMES if n not in d.labels]
    if not free:
        raise Skip("no dangling name")
    n = d.rng.choice(free)
    d.labels.add(n)
    name = n + "." + d.apex
    target = "%s-%s.%s." % ("%010x" % d.rng.getrandbits(40), d.apex.split(".")[0], d.rng.choice(dl.CLOUDS))
    ch = {"zone": [["set", dl.fq(d.apex), dl.fq(name), ["CNAME " + target]]]}
    return ch, {"name": name, "target": target.rstrip("."), "mode": mode}


def mk_gone(d):
    h = d.direct_host(lambda h: dl.host_key(h) not in d.mx)
    name = h["host"]
    ch = {"envs_down": [h["env"]], "zone": [["del", dl.fq(d.apex), dl.fq(name)]]}
    octet = h["address"].rsplit(".", 1)[1]
    if octet in d.model["zone"].get("ptr", {}).get(d.ptr_origin, {}):
        ch["zone"].append(["ptr_del", d.ptr_origin, octet])
    e = d.ents[h["env"]]
    k = {"name": name, "address": h["address"], "ports": ports_of(e, {int(a): b for a, b in d.model["envs"][h["env"]]["remap"].items()}),
         "product": e["product"], "version": e["version"], "env": e["id"]}
    return ch, k


def mk_deploy(d, dep):
    return {"deploy": "v2"}, {"name": dep["host"], "address": dep["address"], "port": dep["port"], "routes": copy.deepcopy(dl.DEPLOY_ROUTES)}


def attempt(seed, n, model0, key, cat, dplan, classes, cap_mb):
    rng = random.Random("%s:drift:%d" % (seed, n))
    d = Draw(rng, model0, key, cat)
    makers = {"new-host": mk_new_host, "new-port": mk_new_port, "swap": mk_swap, "new-vhost": mk_new_vhost,
              "dangling": lambda d: mk_dangling(d, dplan["alias"]), "gone": mk_gone, "deploy": lambda d: mk_deploy(d, dplan["deploy"])}
    epochs = {0: [], 1: [], 2: [], 3: []}
    model, mems = copy.deepcopy(model0), [dl.model_mem(model0, d.ents)]
    for ep, cls in ((1, classes[0]), (2, []), (3, classes[1])):
        for i, c in enumerate(cls, 1):
            ch, k = makers[c](d)
            ch["id"] = "e%dc%d" % (ep, i)
            ch["class"] = c
            k["id"], k["class"] = ch["id"], c
            ch["key"] = k
            epochs[ep].append(ch)
            dl.apply_change(model, ch)
        if ep == 1:
            live = sorted(model["envs"])
            churn = {"restart": sorted(rng.sample(live, min(4, len(live)))), "proxy": True, "deploy": True, "dns": True}
        mems.append(dl.model_mem(model, d.ents))
    if max(mems) > cap_mb:
        raise Skip("over the memory cap")
    return epochs, churn, mems


def augment(rng, out, cat):
    """The deploy host, the alias and the second TXT, added to build.py's files."""
    key = dl.load_json(os.path.join(out, "key.json"))
    est = key["estates"][0]
    zone = dl.load_json(os.path.join(out, "zone-1.json"))
    apex = dl.fq(est["domain"])
    names = zone["zones"][apex]
    proxy = dl.load_json(os.path.join(out, "plan.json"))["proxies"][0]["address"]
    used = {h["address"] for h in est["hosts"] if h.get("address")} | {n["address"] for n in est["ns"]} | {proxy}
    base = est["net"].split("/")[0].rsplit(".", 1)[0]
    taken = {n.split(".")[0] for n in names}
    label = next((x for x in dl.DEPLOY_LABELS if x not in taken), None) or "app-" + "%03d" % rng.randrange(1000)
    addr = "%s.%d" % (base, rng.choice([o for o in range(10, 251) if "%s.%d" % (base, o) not in used]))
    host = label + "." + est["domain"]
    names[dl.fq(host)] = ["A " + addr]
    est["hosts"].append({"kind": "service", "host": host, "address": addr, "vhost": False, "dns_visible": True, "app": "deploy",
                         "product": "", "version": "", "cve": [], "category": "app", "vulnerable": False,
                         "summary": "a small orders app; its script's API routes change when it is deployed",
                         "ports": [{"port": dl.DEPLOY_PORT, "protocol": "http", "transport": "tcp", "primary": True}]})
    # An alias to a cloud name that resolves now (the lab holds that name's zone), which a drift can orphan.
    free = [n for n in build.DANGLING_NAMES if n not in taken]
    alias = rng.choice(free)
    cloud = rng.choice(dl.CLOUDS)
    target = "%s-%s.%s." % ("%010x" % rng.getrandbits(40), est["domain"].split(".")[0], cloud)
    origin = cloud + "."
    names[dl.fq(alias + "." + est["domain"])] = ["CNAME " + target]
    zone["zones"][origin] = {origin: ["SOA ns1.%s hostmaster.%s 1 3600 600 86400 60" % (origin, origin), "NS ns1." + origin],
                             "ns1." + origin: ["A " + proxy], target: ["A " + proxy]}
    est["hosts"].append({"kind": "alias", "host": alias + "." + est["domain"], "target": target.rstrip("."), "category": "dns",
                         "vulnerable": False, "summary": "CNAME to a cloud name", "ports": []})
    names[apex] = names[apex] + ['TXT "google-site-verification=%010x"' % rng.getrandbits(40)]
    dl.save_json(os.path.join(out, "key.json"), key)
    dl.save_json(os.path.join(out, "zone-1.json"), zone)
    return {"deploy": {"host": host, "address": addr, "port": dl.DEPLOY_PORT},
            "alias": {"name": alias + "." + est["domain"], "target": target, "origin": origin}}


def plan(seed, out, size=7, budget_mb=5200, disk_mb=14000, cap_mb=8500, tries=400):
    out = os.path.abspath(out)
    rc = build.main([seed, "--out", out, "--count", "1", "--size", str(size), "--budget-mb", str(budget_mb),
                     "--disk-mb", str(disk_mb), "--vhosts", "2", "--dangling", "2"])
    if rc:
        raise SystemExit("build.py failed")
    cat = rangelib.load_catalog()
    dplan = augment(random.Random(seed + ":base"), out, cat)
    dl.save_json(os.path.join(out, "drift-plan.json"), dplan)
    model0 = dl.model_from_files(out)
    key = dl.load_json(os.path.join(out, "key.json"))
    crng = random.Random(seed + ":classes")
    classes = dl.CLASSES[:]
    crng.shuffle(classes)
    k = crng.choice([3, 4])
    split = (classes[:k], classes[k:])
    last = None
    for n in range(tries):
        try:
            epochs, churn, mems = attempt(seed, n, model0, key, cat, dplan, split, cap_mb)
            break
        except Skip as e:
            last = e
    else:
        raise SystemExit("no draw of the changes fits the estate (%s)" % last)
    ents = dl.by_id(cat)
    for ep in (1, 3):
        for ch in epochs[ep]:
            for pe in ch.get("envs_up", []):
                with open(os.path.join(out, pe["override"]), "w") as f:
                    f.write(rangelib.override_text(ents[pe["id"]], pe["address"], {int(a): b for a, b in pe["remap"].items()}))
    dplan.update({"seed_draw": n, "cap_mb": cap_mb, "mem_mb": mems, "classes": {"1": [c["class"] for c in epochs[1]], "3": [c["class"] for c in epochs[3]]},
                  "epochs": [{"epoch": e, "changes": epochs[e], **({"churn": churn} if e == 2 else {})} for e in range(4)]})
    dl.save_json(os.path.join(out, "drift-plan.json"), dplan)
    dl.save_json(os.path.join(out, "drift-key.json"), {
        "domain": key["estates"][0]["domain"], "net": key["estates"][0]["net"], "dropped": 0,
        "epochs": [{"epoch": e, "changes": [c["key"] for c in epochs[e]]} for e in range(4)]})
    print("planned 4 epochs: %d + %d changes, peak %d of %d MB" % (len(epochs[1]), len(epochs[3]), max(mems), cap_mb))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("seed")
    ap.add_argument("--out", required=True)
    ap.add_argument("--size", type=int, default=7)
    ap.add_argument("--budget-mb", type=int, default=5200, help="memory of the base estate (build.py)")
    ap.add_argument("--cap-mb", type=int, default=8500, help="peak memory of any epoch: the base plus every addition")
    ap.add_argument("--disk-mb", type=int, default=14000)
    a = ap.parse_args(argv)
    return plan(a.seed, a.out, a.size, a.budget_mb, a.disk_mb, a.cap_mb)


if __name__ == "__main__":
    sys.exit(main())
