#!/usr/bin/env python3
"""gen.py SEED --out DIR: writes one random web application and its answer key.

  app.json   everything server.py needs (routes, guards, objects, accounts)
  key.json   every route of the app with its class, visibility, actors and a
             machine-checked proof (selfcheck.py) and a curl recipe
  vars.json  base URL placeholder, accounts, passwords

The same SEED gives the same app. The design follows the OWASP API Security
Top 10 classes (API1 BOLA, API3 property level, API5 BFLA): which routes are
flawed, the theme, id and auth styles, refusal styles and what the SPA shows
are drawn from the seed. The classes and traps are fixed lists below, written
from the OWASP descriptions.
"""
import argparse
import hashlib
import hmac
import json
import os
import random
import re
import sys
import uuid

THEMES = {
    "clinic": ("carepoint", ["visit", "prescription", "referral", "lab-result", "appointment", "invoice", "allergy",
                              "vaccination", "claim", "ward", "device", "consent"]),
    "fleet": ("fleetdesk", ["repair", "vehicle", "driver", "inspection", "fuel-card", "route", "part", "insurance",
                             "fine", "booking", "depot", "tyre"]),
    "finance": ("ledgerly", ["invoice", "payment", "expense", "budget", "quote", "refund", "contract", "payout",
                              "statement", "vendor", "receipt", "tax-note"]),
    "helpdesk": ("deskhub", ["ticket", "article", "macro", "survey", "escalation", "asset", "shift", "outage",
                              "review", "template", "tag-rule", "export-job"]),
    "grants": ("grantbase", ["application", "reviewer-note", "milestone", "award", "budget-line", "report", "site-visit",
                              "reference", "amendment", "disbursement", "panel", "attachment"]),
}
PLURAL = {"allergy": "allergies", "ward": "wards"}
FIRST = ["mira", "joel", "tessa", "arlo", "nadia", "felix", "ines", "kofi", "lena", "omar", "petra", "silas", "tove",
         "uri", "vera", "wren", "yosef", "zara", "ansel", "bianca", "cyrus", "dalia", "emil", "farah"]
ADMINS = ["root", "sysadmin", "operator", "manager", "supervisor"]
ADJ = ["amber", "brisk", "calm", "dusty", "eager", "faint", "gentle", "hazy", "iron", "jolly", "keen", "lucid", "mossy",
       "noble", "opal", "plain", "quiet", "rustic", "sunny", "tidy", "umber", "vivid", "witty", "zesty"]
NOUN = ["falcon", "harbor", "meadow", "lantern", "orchid", "pebble", "quarry", "ripple", "summit", "thicket", "willow",
        "anchor", "beacon", "cedar", "delta", "ember"]
STATUS = ["open", "pending", "closed", "review", "queued"]
SVC = ["core", "ops", "hub", "edge", "portal"]
OWNER_KEYS = ["owner", "owner_id", "user", "created_by", "account"]
ID_KEYS = ["id", "uuid", "ref", "number"]
LIST_KEYS = [None, "items", "data", "results"]
TRUST_PARAMS = ["owner", "account", "user", "owner_id"]
# Refusal messages: some say the words a tester's detector looks for, some do not.
MSG_DENY = ["forbidden", "access denied", "not permitted for this account", "no such record for you",
            "insufficient privileges", "operation not allowed"]
MSG_UNAUTH = ["unauthorized", "login required", "missing or invalid credentials", "session expired"]
FLAWS = ["bola-read", "bola-write", "bola-delete", "nested-bola", "idor-query", "bfla", "mass-assignment",
         "data-exposure", "no-auth"]
TRAPS = ["shared", "public", "twin-read", "soft-refusal", "empty-list", "admin-refused", "twin-write", "ignored-param"]
ISO = "2026-01-01T00:00:00Z"


def hx(r, n):
    return "".join(r.choice("0123456789abcdef") for _ in range(n))


def js_url(path, r):
    parts = [x for x in re.split(r"(\{[^}]+\})", path) if x]
    if r.random() < 0.6:
        return "`" + "".join("${%s}" % x[1:-1] if x.startswith("{") else x for x in parts) + "`"
    return "+".join(x[1:-1] if x.startswith("{") else json.dumps(x) for x in parts)


def word_slug(r):
    return "%s-%s-%d" % (r.choice(ADJ), r.choice(NOUN), r.randint(10, 99))


class Gen:
    def __init__(self, seed):
        self.seed = str(seed)
        self.r = r = random.Random("authz/1/" + self.seed)
        self.theme = r.choice(sorted(THEMES))
        domain, nouns = THEMES[self.theme]
        self.domain = domain
        self.nouns = r.sample(nouns, r.randint(6, 10))
        self.secret = hx(r, 32)
        self.style = r.choice(["bearer", "jwt", "cookie", "header"])
        self.idk = r.choice(ID_KEYS)
        self.ownerk = r.choice(OWNER_KEYS)
        self.list_key = r.choice(LIST_KEYS)
        self.err_shape = r.randint(0, 2)
        cands = ["/api", "/api/v2", "/svc/" + r.choice(SVC), "/internal/" + r.choice(SVC)]
        r.shuffle(cands)
        self.groups = cands[: r.randint(2, 3)]
        self.main = self.groups[0]
        self.routes = []
        self.key = []
        self.items = {}
        self.res = {}
        self.ids = {}

    # --- accounts -----------------------------------------------------------
    def accounts(self):
        r = self.r
        a, b = r.sample(FIRST, 2)
        out = []
        for label, user, role in (("alice", a, "user"), ("bob", b, "user"), ("admin", r.choice(ADMINS), "admin")):
            out.append({"label": label, "user": user, "role": role,
                        "password": "%s-%s-%d" % (r.choice(ADJ), r.choice(NOUN), r.randint(10, 99)),
                        "display_name": user.capitalize(), "email": "%s@%s.example" % (user, self.domain),
                        "phone": "+1-555-01%02d" % r.randint(0, 99),
                        "address": "%d %s street" % (r.randint(2, 98), r.choice(NOUN)),
                        "api_token": "ik_" + hx(r, 24), "org": "%s-%s" % (user, r.choice(NOUN)), "credit": r.randint(0, 50)})
        self.acct = out
        self.by = {a["label"]: a for a in out}

    # --- resources and items ---------------------------------------------------
    def make_resources(self):
        r = self.r
        n = len(self.nouns)
        nested_left = 2
        for i, noun in enumerate(self.nouns):
            plural = PLURAL.get(noun, noun + "s")
            kind = "catalogue" if i == 0 else "team" if i == 1 else "private"
            style = r.choice(["int", "uuid", "slug", "nested"]) if kind == "private" else r.choice(["int", "uuid", "slug"])
            if style == "nested":
                if nested_left == 0:
                    style = r.choice(["int", "uuid", "slug"])
                else:
                    nested_left -= 1
            group = r.choice(self.groups)
            base = "%s/%s" % (group, plural)
            if style == "nested":
                base = "%s/orgs/{org}/%s" % (group, plural)
            self.res[plural] = {
                "noun": noun, "plural": plural, "kind": kind, "id_style": style, "base": base, "group": group,
                "sub": None, "unauth": r.choices([401, 302, "200error"], [5, 1.5, 1.5])[0],
                "deny": r.choices([403, 404, "200error", 302], [4, 3, 2, 1])[0],
                "put": r.random() < 0.4,
            }
        self.order = [x["plural"] for x in sorted(self.res.values(), key=lambda x: self.nouns.index(x["noun"]))]
        self.cat, self.team = self.order[0], self.order[1]
        self.priv = self.order[2:]

    def new_key(self, res, org, used):
        r = self.r
        st = self.res[res]["id_style"]
        if st == "int":
            self.ids[res] = self.ids.get(res, r.randint(100, 4000)) + 1
            return [str(self.ids[res])]
        if st == "uuid":
            return [str(uuid.UUID(int=r.getrandbits(128), version=4))]
        if st == "slug":
            while True:
                s = word_slug(r)
                if s not in used:
                    return [s]
        self.ids[(res, org)] = self.ids.get((res, org), 0) + 1
        return [org, str(self.ids[(res, org)])]

    def make_items(self):
        r = self.r
        for plural in self.order:
            st = self.res[plural]
            kind = st["kind"]
            owners = []
            if kind == "catalogue":
                owners = ["system"] * 5
            elif kind == "team":
                owners = ["alice"] * 3 + ["bob"] * 3
            else:
                owners = ["alice"] * 4 + ["bob"] * 4 + ["admin"] * 2
                r.shuffle(owners)
            items, used = [], set()
            for j, ow in enumerate(owners):
                acct = self.by.get(ow)
                org = acct["org"] if acct else "system"
                key = self.new_key(plural, org, used)
                used.add(key[-1])
                items.append({
                    "key": key, "owner": acct["user"] if acct else "system", "org": org,
                    "title": "%s %s %d" % (r.choice(ADJ), st["noun"], r.randint(1, 999)),
                    "status": r.choice(STATUS), "amount": r.randint(5, 9000), "notes": "mk-" + hx(r, 10),
                    "approved": False, "deleted": False,
                    "shared": (kind == "team" and j % 3 != 2) or kind == "catalogue", "public": kind == "catalogue",
                    "children": []})
            self.items[plural] = items

    def add_children(self, plural):
        r = self.r
        self.res[plural]["sub"] = r.choice(["notes", "attachments", "comments", "lines", "history"])
        for it in self.items[plural]:
            it["children"] = [{"id": "c%d" % k, "text": "mk-" + hx(r, 10)} for k in range(r.randint(2, 3))]

    # --- routes -----------------------------------------------------------------
    def route(self, op, method, path, res=None, cls="plain", **kw):
        rt = {"id": "r%02d" % len(self.routes), "op": op, "method": method, "path": path, "res": res,
              "auth": "user", "guard": "strict", "vis": "journey"}
        st = self.res.get(res) if res else None
        if st:
            rt["unauth"], rt["deny"] = st["unauth"], st["deny"]
        else:
            rt["unauth"], rt["deny"] = self.main_unauth, 403
        rt["msg"] = self.r.choice(MSG_DENY)
        rt["umsg"] = self.r.choice(MSG_UNAUTH)
        rt.update(kw)
        rt["_cls"] = cls
        self.routes.append(rt)
        return rt

    def ipath(self, rt_path, item):
        p = rt_path
        if "{org}" in p:
            p = p.replace("{org}", item["key"][0])
        return p.replace("{id}", item["key"][-1])

    def build_routes(self):
        r = self.r
        self.main_unauth = r.choice([401, 401, 302, "200error"])
        k = r.randint(6, 9)
        classes = r.sample(FLAWS, k)
        self.flaws = classes
        priv = list(self.priv)
        # which resource hosts each per-resource flaw
        host = {}
        sub_cands = [p for p in priv]
        if "nested-bola" in classes:
            host["nested-bola"] = r.choice(sub_cands)
            self.add_children(host["nested-bola"])
        non_nested = [p for p in priv if self.res[p]["id_style"] != "nested"]
        for c in ("bola-read", "bola-write", "bola-delete", "idor-query", "no-auth"):
            if c in classes:
                host[c] = r.choice(priv)
        if "bfla" in classes:
            host["bfla"] = r.choice(non_nested)
        self.host = host
        # a second resource with children and a correct parent check, for the empty-list trap
        spare = [p for p in priv if p != host.get("nested-bola")]
        self.spare_sub = r.choice(spare)
        self.add_children(self.spare_sub)

        a = self.main
        self.login_path = r.choice(["%s/auth/login" % a, "%s/login" % a, "%s/session" % a])
        self.me_path = r.choice(["%s/me" % a, "%s/profile" % a])
        self.dir_path = r.choice(["%s/members" % a, "%s/directory" % a])
        self.admin = r.choice(["/admin", "%s/admin" % a])
        mass_field = r.choice(["role", "is_admin", "credit"])
        self.mass_field = mass_field

        self.route("login", "POST", self.login_path, auth="none", guard="none")
        self.route("me", "GET", self.me_path)
        self.route("me_patch", "PATCH", self.me_path, cls="mass-assignment" if "mass-assignment" in classes else "plain",
                   mass=[mass_field] if "mass-assignment" in classes else [])
        self.route("prefs", "PATCH", self.me_path + "/preferences")
        self.route("directory", "GET", self.dir_path, cls="data-exposure" if "data-exposure" in classes else "plain",
                   expose="data-exposure" in classes)
        self.route("admin_users", "GET", self.admin + "/users", auth="admin")

        # catalogue (public by design)
        cb = self.res[self.cat]["base"]
        self.route("list", "GET", cb, self.cat, auth="none", guard="public")
        self.route("get", "GET", cb + "/{id}", self.cat, auth="none", guard="public")
        # team (shared objects)
        tb = self.res[self.team]["base"]
        self.route("list", "GET", tb, self.team, guard="shared")
        self.route("get", "GET", tb + "/{id}", self.team, guard="shared")
        self.route("create", "POST", tb, self.team)
        self.route("update", "PUT" if self.res[self.team]["put"] else "PATCH", tb + "/{id}", self.team)
        self.route("delete", "DELETE", tb + "/{id}", self.team)

        for p in priv:
            st = self.res[p]
            b = st["base"]
            um = "PUT" if st["put"] else "PATCH"
            fl = lambda c: host.get(c) == p and c in classes
            lst = self.route("list", "GET", b, p, cls="idor-query" if fl("idor-query") else "plain",
                             trust=r.choice(TRUST_PARAMS) if fl("idor-query") else None)
            if not lst["trust"]:
                lst["ignore"] = None
            self.route("create", "POST", b, p)
            self.route("get", "GET", b + "/{id}", p, cls="bola-read" if fl("bola-read") else "plain",
                       guard="none" if fl("bola-read") else "strict")
            self.route("update", um, b + "/{id}", p, cls="bola-write" if fl("bola-write") else "plain",
                       guard="none" if fl("bola-write") else "strict")
            self.route("delete", "DELETE", b + "/{id}", p, cls="bola-delete" if fl("bola-delete") else "plain",
                       guard="none" if fl("bola-delete") else "strict")
            if st["sub"]:
                self.route("sublist", "GET", b + "/{id}/" + st["sub"], p,
                           cls="nested-bola" if fl("nested-bola") else "plain",
                           guard="none" if fl("nested-bola") else "strict")
            if fl("no-auth"):
                self.route("feed", "GET", b + "/feed", p, cls="no-auth", auth="none", guard="none")
            ap = ex = None
            if st["id_style"] != "nested":
                ap = self.route("approve", "POST", "%s/%s/{id}/approve" % (self.admin, p), p, auth="admin")
            ex = self.route("export", "GET", b + "/export", p, auth="admin")
            if fl("bfla"):
                flawed = r.choice([x for x in (ap, ex) if x])
                flawed["_cls"] = "bfla"
                flawed["auth"] = "user"

    def finalize_flaws(self):
        """Every drawn class has exactly one flawed route; fix the ones drawn twice or none."""
        by = {}
        for rt in self.routes:
            if rt["_cls"] in FLAWS:
                by.setdefault(rt["_cls"], []).append(rt)
        for c in self.flaws:
            lst = by.get(c, [])
            assert len(lst) == 1, (c, len(lst))

    # --- traps -------------------------------------------------------------------
    def pick(self, op, pred=lambda rt: True):
        c = [rt for rt in self.routes if rt["op"] == op and rt["_cls"] == "plain" and rt["res"] in self.priv
             and "_trap" not in rt and pred(rt)]
        return self.r.choice(c) if c else None

    def pick_traps(self):
        r = self.r
        want = r.sample(TRAPS, r.randint(5, 8))
        self.traps = []
        for t in want:
            rt = None
            if t == "shared":
                rt = next(x for x in self.routes if x["op"] == "get" and x["res"] == self.team)
            elif t == "public":
                rt = next(x for x in self.routes if x["op"] == "get" and x["res"] == self.cat)
            elif t == "twin-read":
                rt = self.pick("get")
            elif t == "soft-refusal":
                rt = self.pick("get")
                if rt:
                    rt["deny"] = "200error"
            elif t == "empty-list":
                rt = next((x for x in self.routes if x["op"] == "sublist" and x["res"] == self.spare_sub), None)
                if rt:
                    rt["deny"] = "200empty"
            elif t == "admin-refused":
                rt = self.pick("approve") or self.pick("export")
            elif t == "twin-write":
                rt = self.pick("update")
            elif t == "ignored-param":
                rt = self.pick("list", lambda x: not x.get("trust"))
                if rt:
                    rt["ignore"] = r.choice(TRUST_PARAMS)
            if rt is not None and "_trap" not in rt:
                rt["_trap"] = t
                self.traps.append(t)

    # --- visibility --------------------------------------------------------------
    def assign_visibility(self):
        r = self.r
        flawed = [rt for rt in self.routes if rt["_cls"] in FLAWS]
        r.shuffle(flawed)
        cyc = ["journey", "js-only", "unlinked"]
        r.shuffle(cyc)
        for i, rt in enumerate(flawed):
            rt["vis"] = cyc[i % 3]
        for rt in self.routes:
            if rt["_cls"] in FLAWS or rt["op"] in ("login", "me"):
                continue
            rt["vis"] = r.choices(["journey", "js-only", "unlinked"], [55, 25, 20])[0]
        # a journey delete has a journey create, so the capture deletes a throwaway
        for rt in self.routes:
            if rt["op"] == "delete" and rt["vis"] == "journey":
                for c in self.routes:
                    if c["op"] == "create" and c["res"] == rt["res"]:
                        c["vis"] = "journey"
        # a trap or flaw read-back route (the owner's get) must exist for proofs; it always does

    # --- the key -------------------------------------------------------------------
    def item_of(self, res, label, idx=0, shared=None):
        acct = self.by[label]
        c = [i for i in self.items[res] if i["owner"] == acct["user"] and (shared is None or i["shared"] == shared)]
        return c[idx]

    def get_route(self, res):
        return next(x for x in self.routes if x["op"] == "get" and x["res"] == res)

    def step(self, who, method, path, expect=None, body=None):
        s = {"as": who, "method": method, "path": path, "expect": expect or {}}
        if body is not None:
            s["body"] = body
        return s

    def proofs(self):
        r = self.r
        out = {}
        for rt in self.routes:
            cls, p = rt["_cls"], rt["res"]
            trap = rt.get("_trap")
            steps, actor, owner, expect = None, None, None, None
            if cls == "bola-read":
                it = self.item_of(p, "alice", 0)
                actor, owner = "bob", "alice"
                steps = [self.step("bob", "GET", self.ipath(rt["path"], it), {"status": [200], "contains": it["notes"]})]
            elif cls == "bola-write":
                it = self.item_of(p, "alice", 1)
                tag = "zz-bw-" + hx(r, 6)
                actor, owner = "bob", "alice"
                body = {"title": tag}
                g = self.get_route(p)
                steps = [self.step("bob", rt["method"], self.ipath(rt["path"], it), {"status_class": 2}, body),
                         self.step("alice", "GET", self.ipath(g["path"], it), {"contains": tag})]
            elif cls == "bola-delete":
                it = self.item_of(p, "alice", 3)
                actor, owner = "bob", "alice"
                g = self.get_route(p)
                steps = [self.step("alice", "GET", self.ipath(g["path"], it), {"status": [200], "contains": it["notes"]}),
                         self.step("bob", "DELETE", self.ipath(rt["path"], it), {"status_class": 2}),
                         self.step("alice", "GET", self.ipath(g["path"], it), {"status": [404]})]
            elif cls == "nested-bola":
                it = self.item_of(p, "alice", 0)
                actor, owner = "bob", "alice"
                steps = [self.step("bob", "GET", self.ipath(rt["path"], it),
                                   {"status": [200], "contains": it["children"][0]["text"]})]
            elif cls == "idor-query":
                it = self.item_of(p, "alice", 0)
                actor, owner = "bob", "alice"
                steps = [self.step("bob", "GET", "%s?%s=%s" % (self.ipath(rt["path"], it), rt["trust"], self.by["alice"]["user"]),
                                   {"status": [200], "contains": it["notes"]})]
            elif cls == "bfla":
                actor, owner = "alice", "admin"
                if rt["op"] == "approve":
                    it = self.item_of(p, "bob", 2)
                    g = self.get_route(p)
                    steps = [self.step("alice", "POST", self.ipath(rt["path"], it), {"status_class": 2}),
                             self.step("bob", "GET", self.ipath(g["path"], it), {"json_eq": ["approved", True]})]
                else:
                    it = self.item_of(p, "bob", 0)
                    steps = [self.step("alice", "GET", self.ipath(rt["path"], it), {"status": [200], "contains": it["notes"]})]
            elif cls == "mass-assignment":
                actor, owner = "bob", "bob"
                val = {"role": "admin", "is_admin": True, "credit": 99999}[self.mass_field]
                shown = {"role": "role", "is_admin": "role", "credit": "credit"}[self.mass_field]
                shown_val = "admin" if shown == "role" else 99999
                steps = [self.step("bob", "PATCH", rt["path"], {"status_class": 2}, {self.mass_field: val}),
                         self.step("bob", "GET", self.me_path, {"json_eq": [shown, shown_val]})]
            elif cls == "data-exposure":
                actor, owner = "alice", "bob"
                steps = [self.step("alice", "GET", rt["path"], {"status": [200], "contains": self.by["bob"]["api_token"]})]
            elif cls == "no-auth":
                it = self.item_of(p, "alice", 0)
                actor, owner = "anon", "alice"
                steps = [self.step("anon", "GET", self.ipath(rt["path"], it), {"status": [200], "contains": it["notes"]})]
            elif trap == "shared":
                s = self.item_of(p, "alice", 0, shared=True)
                n = self.item_of(p, "alice", 0, shared=False)
                actor, owner, expect = "bob", "alice", "allowed-by-design"
                steps = [self.step("bob", "GET", self.ipath(rt["path"], s), {"status": [200], "contains": s["notes"]}),
                         self.step("bob", "GET", self.ipath(rt["path"], n), {"not_contains": n["notes"]})]
            elif trap == "public":
                it = self.items[p][0]
                actor, owner, expect = "anon", "system", "allowed-by-design"
                steps = [self.step("anon", "GET", self.ipath(rt["path"], it), {"status": [200], "contains": it["notes"]})]
            elif trap in ("twin-read", "soft-refusal"):
                it = self.item_of(p, "alice", 0)
                actor, owner, expect = "bob", "alice", "refused"
                steps = [self.step("bob", "GET", self.ipath(rt["path"], it), {"not_contains": it["notes"]})]
            elif trap == "empty-list":
                it = self.item_of(p, "alice", 0)
                actor, owner, expect = "bob", "alice", "refused"
                steps = [self.step("bob", "GET", self.ipath(rt["path"], it), {"not_contains": it["children"][0]["text"]})]
            elif trap == "admin-refused":
                actor, owner, expect = "alice", "admin", "refused"
                if rt["op"] == "approve":
                    it = self.item_of(p, "bob", 3)
                    g = self.get_route(p)
                    steps = [self.step("alice", "POST", self.ipath(rt["path"], it), {}),
                             self.step("bob", "GET", self.ipath(g["path"], it), {"json_eq": ["approved", False]})]
                else:
                    it = self.item_of(p, "bob", 1)
                    steps = [self.step("alice", "GET", self.ipath(rt["path"], it), {"not_contains": it["notes"]})]
            elif trap == "twin-write":
                it = self.item_of(p, "alice", 2)
                actor, owner, expect = "bob", "alice", "refused"
                g = self.get_route(p)
                steps = [self.step("bob", rt["method"], self.ipath(rt["path"], it), {}, {"title": "zz-neg-write"}),
                         self.step("alice", "GET", self.ipath(g["path"], it), {"not_contains": "zz-neg-write",
                                                                                "contains": it["notes"]})]
            elif trap == "ignored-param":
                it = self.item_of(p, "alice", 0)
                actor, owner, expect = "bob", "alice", "refused"
                steps = [self.step("bob", "GET", "%s?%s=%s" % (self.ipath(rt["path"], it), rt["ignore"], self.by["alice"]["user"]),
                                   {"not_contains": it["notes"]})]
            out[rt["id"]] = (steps, actor, owner, expect)
        return out

    def curl(self, steps):
        lines = []
        for s in steps:
            hdr = {"anon": "", "alice": ' -H "$ALICE"', "bob": ' -H "$BOB"', "admin": ' -H "$ADMIN"'}[s["as"]]
            body = (" -H 'Content-Type: application/json' -d '%s'" % json.dumps(s["body"])) if "body" in s else ""
            lines.append('curl -s -X %s%s%s "$URL%s"' % (s["method"], hdr, body, s["path"]))
        return lines

    def build_key(self):
        pr = self.proofs()
        keyroutes = []
        for rt in self.routes:
            steps, actor, owner, expect = pr[rt["id"]]
            cls = rt["_cls"] if rt["_cls"] in FLAWS else "negative" if rt.get("_trap") else "plain"
            e = {"id": rt["id"], "method": rt["method"], "template": rt["path"], "class": cls,
                 "visibility": rt["vis"], "actor": actor, "owner": owner}
            if cls == "negative":
                e["trap"] = rt["_trap"]
                e["expect"] = expect
            if cls != "plain":
                e["proof"] = steps
                e["curl"] = self.curl(steps)
            keyroutes.append(e)
        # fixed routes
        fixed = [("GET", "/", "n/a"), ("GET", "/login", "n/a"), ("GET", self.bundle_path, "n/a"),
                 ("GET", self.openapi_path, "n/a")]
        for m, t, v in fixed:
            keyroutes.append({"id": "s%d" % len(keyroutes), "method": m, "template": t, "class": "plain",
                              "visibility": v, "actor": None, "owner": None})
        return keyroutes

    # --- front end -------------------------------------------------------------------
    def js_name(self, rt):
        parts = [x for x in rt["path"].replace("{", "").replace("}", "").replace("-", "/").split("/") if x]
        return rt["op"] + "".join(p.capitalize() for p in parts[-2:])

    def js_call(self, rt):
        r = self.r
        p = rt["path"]
        args = []
        for tok in ("org", "id"):
            if "{%s}" % tok in p:
                args.append(tok)
        url = js_url(p, r) if args else '"%s"' % p
        body = ""
        if rt["method"] in ("POST", "PUT", "PATCH"):
            f = {"login": "username:u,password:pw", "create": "title:t,status:s,amount:a,notes:n",
                 "update": "title:t,status:s", "me_patch": "display_name:d,phone:ph", "prefs": "theme:th,locale:lc",
                 "approve": ""}.get(rt["op"], "")
            body = ",body:JSON.stringify({%s})" % f if f else ""
        if rt["op"] == "list" and rt.get("trust"):
            url = '%s+"?%s="+encodeURIComponent(me.user)' % (url, rt["trust"])
        return "  %s(%s){return api(%s,{method:\"%s\"%s})}," % (self.js_name(rt), ",".join(args), url, rt["method"], body)

    def make_bundle(self):
        r = self.r
        head = {"bearer": 'const H=()=>({Authorization:"Bearer "+localStorage.getItem("tok")});',
                "jwt": 'const H=()=>({Authorization:"Bearer "+localStorage.getItem("jwt")});',
                "cookie": "const H=()=>({});",
                "header": 'const H=()=>({"X-Api-Key":localStorage.getItem("key")});'}[self.style]
        lines = ["!function(){", head,
                 'const api=(u,o={})=>fetch(u,{credentials:"same-origin",...o,headers:{"Content-Type":"application/json",...H(),...(o.headers||{})}}).then(r=>r.json());',
                 "let me={user:null};", "const calls={"]
        for rt in self.routes:
            if rt["vis"] in ("journey", "js-only"):
                lines.append(self.js_call(rt))
        lines += ["};", 'document.getElementById("app").textContent="%s";' % self.domain, "window.__app=calls;", "}();"]
        text = "\n".join(lines) + "\n"
        self.bundle_path = "/static/app.%s.js" % hashlib.sha1(text.encode()).hexdigest()[:8]
        self.bundle = text

    def make_openapi(self):
        r = self.r
        self.openapi_path = r.choice(["/openapi.json", "/swagger.json", "/v2/api-docs", "/api-docs", "/docs/openapi.json"])
        pick = [rt for rt in self.routes if rt["vis"] == "unlinked"]
        extra = [rt for rt in self.routes if rt["vis"] == "journey" and rt["_cls"] == "plain" and rt["op"] in ("list", "get")]
        pick += r.sample(extra, min(3, len(extra)))
        paths = {}
        for rt in pick:
            params = [{"name": n, "in": "path", "required": True, "schema": {"type": "string"}}
                      for n in ("org", "id") if "{%s}" % n in rt["path"]]
            op = {"operationId": self.js_name(rt), "parameters": params, "responses": {"200": {"description": "ok"}}}
            if rt["method"] in ("POST", "PUT", "PATCH"):
                props = {"title": {"type": "string"}, "status": {"type": "string"}} if rt["op"] in ("create", "update") else {}
                if rt["op"] == "me_patch":
                    props = {"display_name": {"type": "string"}, "phone": {"type": "string"}}
                op["requestBody"] = {"content": {"application/json": {"schema": {"type": "object", "properties": props}}}}
            paths.setdefault(rt["path"], {})[rt["method"].lower()] = op
        self.openapi = {"openapi": "3.0.0", "info": {"title": "%s internal api" % self.domain, "version": "2"}, "paths": paths}

    # --- output ---------------------------------------------------------------------------
    def app(self):
        routes = []
        for rt in self.routes:
            routes.append({k: v for k, v in rt.items() if not k.startswith("_")})
        return {
            "seed": self.seed, "theme": self.theme, "domain": self.domain, "secret": self.secret,
            "auth": {"style": self.style, "cookie": "sid", "header": "X-Api-Key", "login": self.login_path, "form": "/login"},
            "fields": {"id": self.idk, "owner": self.ownerk, "list": self.list_key, "err": self.err_shape},
            "accounts": self.acct, "resources": self.res, "items": self.items, "routes": routes,
            "static": {"bundle": self.bundle_path, "openapi": self.openapi_path}, "bundle": self.bundle,
            "openapi": self.openapi, "words": {"adj": ADJ, "noun": NOUN}, "status": STATUS,
            "me_path": self.me_path,
        }


def build(seed):
    g = Gen(seed)
    g.accounts()
    g.make_resources()
    g.make_items()
    g.build_routes()
    g.finalize_flaws()
    g.pick_traps()
    g.assign_visibility()
    g.make_bundle()
    g.make_openapi()
    app = g.app()
    key = {"seed": g.seed, "theme": g.theme, "routes": g.build_key(), "flaws": g.flaws, "traps": g.traps,
           "notes": "admin has no override on object routes; reports on a route whose class is plain or negative are false positives"}
    vars_ = {"url": "__URL__", "accounts": {a["label"]: {"user": a["user"], "password": a["password"], "role": a["role"]}
                                              for a in g.acct}}
    return app, key, vars_


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("seed")
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv)
    app, key, vars_ = build(a.seed)
    os.makedirs(a.out, exist_ok=True)
    for name, doc in (("app.json", app), ("key.json", key), ("vars.json", vars_)):
        with open(os.path.join(a.out, name), "w") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
    flaws = [r for r in key["routes"] if r["class"] not in ("plain", "negative")]
    neg = [r for r in key["routes"] if r["class"] == "negative"]
    print("gen: %d routes, %d flaws, %d negatives" % (len(key["routes"]), len(flaws), len(neg)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
