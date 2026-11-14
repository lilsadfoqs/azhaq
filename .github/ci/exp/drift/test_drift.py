"""Tests for experiment A's scripts. No docker, no network, no root:
    python3 -m unittest discover -s .github/ci/exp/drift
"""
import contextlib
import copy
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import a3  # noqa: E402
import apply as drift_apply  # noqa: E402
import arms  # noqa: E402
import driftlib as dl  # noqa: E402
import grade  # noqa: E402
import plan  # noqa: E402
import rangelib  # noqa: E402
import summary  # noqa: E402

REPO = dl.REPO


def planned(seed, **kw):
    d = tempfile.mkdtemp()
    with contextlib.redirect_stdout(io.StringIO()):
        plan.plan(seed, d, **kw)
    return d


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def read(d, name):
    with open(os.path.join(d, name)) as f:
        return f.read()


class Plan(unittest.TestCase):
    seeds = ["s%d" % i for i in range(10)]

    @classmethod
    def setUpClass(cls):
        cls.dirs = {s: planned(s) for s in cls.seeds}

    def test_deterministic(self):
        again = planned("s3")
        for name in ("drift-key.json", "drift-plan.json", "zone-1.json", "proxy-1.conf", "key.json", "plan.json"):
            self.assertEqual(read(self.dirs["s3"], name), read(again, name), name)
        self.assertNotEqual(read(self.dirs["s3"], "drift-key.json"), read(self.dirs["s4"], "drift-key.json"))

    def test_every_class_in_e1_and_e3(self):
        for s, d in self.dirs.items():
            k = json.loads(read(d, "drift-key.json"))
            e1, e3 = k["epochs"][1]["changes"], k["epochs"][3]["changes"]
            self.assertIn(len(e1), (3, 4), s)
            self.assertIn(len(e3), (3, 4), s)
            self.assertEqual(sorted(c["class"] for c in e1 + e3), sorted(dl.CLASSES), s)
            self.assertEqual(k["epochs"][0]["changes"], [])
            self.assertEqual(k["epochs"][2]["changes"], [], "E2 is churn only")

    def test_e2_is_churn_only(self):
        p = json.loads(read(self.dirs["s1"], "drift-plan.json"))
        e2 = p["epochs"][2]
        self.assertEqual(e2["changes"], [])
        self.assertTrue(e2["churn"]["restart"] and e2["churn"]["dns"])

    def test_budget(self):
        for s, d in self.dirs.items():
            p = json.loads(read(d, "drift-plan.json"))
            ents = dl.by_id(rangelib.load_catalog())
            m = dl.model_from_files(d)
            mems = [dl.model_mem(m, ents)]
            for ep in p["epochs"][1:]:
                for ch in ep["changes"]:
                    dl.apply_change(m, ch)
                mems.append(dl.model_mem(m, ents))
            self.assertEqual(mems, p["mem_mb"], s)
            self.assertLessEqual(max(mems), p["cap_mb"], s)

    def test_cap_is_enforced(self):
        with self.assertRaises(SystemExit):
            with contextlib.redirect_stdout(io.StringIO()):
                plan.plan("s1", tempfile.mkdtemp(), cap_mb=100, tries=20)

    def test_base_model_renders_builds_proxy_conf(self):
        for s, d in self.dirs.items():
            self.assertEqual(dl.render_conf(dl.model_from_files(d)), read(d, "proxy-1.conf"), s)

    def test_deploy_host_and_alias_in_the_base(self):
        d = self.dirs["s2"]
        key = json.loads(read(d, "key.json"))
        dep = [h for h in key["estates"][0]["hosts"] if h.get("app") == "deploy"][0]
        self.assertEqual(dep["ports"][0]["port"], dl.DEPLOY_PORT)
        zone = json.loads(read(d, "zone-1.json"))
        apex = key["estates"][0]["domain"] + "."
        self.assertEqual(zone["zones"][apex][dep["host"] + "."], ["A " + dep["address"]])
        dp = json.loads(read(d, "drift-plan.json"))
        tgt = dp["alias"]["target"]
        self.assertIn("A ", zone["zones"][dp["alias"]["origin"]][tgt][0])
        self.assertEqual(sum(1 for r in zone["zones"][apex][apex] if r.startswith("TXT")), 2)

    def test_changes_are_consistent_with_the_estate(self):
        for s, d in self.dirs.items():
            key = json.loads(read(d, "key.json"))
            used = {h["address"] for h in key["estates"][0]["hosts"] if h.get("address")}
            p = json.loads(read(d, "drift-plan.json"))
            hosts = []
            for ep in p["epochs"]:
                for ch in ep["changes"]:
                    k = ch["key"]
                    if ch["class"] == "new-host":
                        self.assertNotIn(k["address"], used, s)
                        used.add(k["address"])
                    if ch["class"] in ("gone", "swap", "new-port"):
                        hosts.append(k["name"])
                    for pe in ch.get("envs_up", []):
                        self.assertTrue(os.path.exists(os.path.join(d, pe["override"])), s)
            self.assertEqual(len(hosts), len(set(hosts)), "one change per host: " + s)

    def test_zone_ops(self):
        d = self.dirs["s5"]
        m = dl.model_from_files(d)
        p = json.loads(read(d, "drift-plan.json"))
        for ep in p["epochs"]:
            for ch in ep["changes"]:
                before = copy.deepcopy(m["zone"])
                dl.apply_change(m, ch)
                k = ch["key"]
                apex = m["apex"] + "."
                names = m["zone"]["zones"][apex]
                if ch["class"] == "gone":
                    self.assertNotIn(k["name"] + ".", names)
                if ch["class"] == "new-host":
                    self.assertIn(k["name"] + ".", names)
                if ch["class"] == "new-vhost":
                    self.assertIn(k["name"] + ".", names)
                    self.assertIn(k["name"], [r[0] for r in m["routes"]])
                if ch["class"] == "dangling" and k["mode"] == "target-gone":
                    self.assertNotIn(k["target"] + ".", m["zone"]["zones"][p["alias"]["origin"]])
                    self.assertIn(p["alias"]["name"] + ".", names)
                if ch["class"] == "dangling" and k["mode"] == "new-cname":
                    self.assertNotEqual(before, m["zone"])


class Model(unittest.TestCase):
    def test_reorder_keeps_the_set_and_the_types_places(self):
        recs = ["SOA a b 1 2 3 4 5", "NS x.", "NS y.", "A 1.2.3.4", 'TXT "a"', 'TXT "b"']
        out = dl.reorder(recs)
        self.assertEqual(sorted(out), sorted(recs))
        self.assertEqual(out, ["SOA a b 1 2 3 4 5", "NS y.", "NS x.", "A 1.2.3.4", 'TXT "b"', 'TXT "a"'])
        self.assertEqual(dl.reorder(out), recs)

    def test_dns_churn_changes_order_and_soa_only(self):
        d = planned("s6")
        m = dl.model_from_files(d)
        before = copy.deepcopy(m["zone"])
        dl.dns_churn(m)
        for origin, names in before["zones"].items():
            for n, recs in names.items():
                now = m["zone"]["zones"][origin][n]
                self.assertEqual(len(recs), len(now))
                self.assertEqual(sorted(r for r in recs if not r.startswith("SOA")), sorted(r for r in now if not r.startswith("SOA")))
        self.assertNotEqual(before, m["zone"])
        soa = [r for r in m["zone"]["zones"][m["apex"] + "."][m["apex"] + "."] if r.startswith("SOA")][0].split()
        self.assertEqual(len(soa), 8)

    def test_fence_chain_and_users(self):
        d = planned("s7")
        m = dl.model_from_files(d)
        ents = dl.by_id(rangelib.load_catalog())
        key = json.loads(read(d, "key.json"))
        k, p = dl.live_key(m, ents, key)
        rules = dl.fence_for(k, p, "AZQ9", ["runner", "analyst"])
        self.assertEqual(rules[0], ["-N", "AZQ9"])
        self.assertEqual(rules[-1], ["-I", "OUTPUT", "1", "-j", "AZQ9"])
        self.assertFalse([r for r in rules if "AZQ" in r])
        owners = [r[r.index("--uid-owner") + 1] for r in rules if "--uid-owner" in r]
        self.assertEqual(sorted(set(owners)), ["analyst", "runner"])
        # The deploy host's port and every host's ports are let through.
        accepts = {(r[r.index("-d") + 1], r[r.index("--dport") + 1]) for r in rules if "ACCEPT" in r and "--dport" in r}
        self.assertIn((m["deploy"]["address"], str(dl.DEPLOY_PORT)), accepts)

    def test_mention(self):
        rx = dl.mention_re("x.corp.test")
        self.assertTrue(rx.search("new host x.corp.test (127.0.0.1)"))
        self.assertTrue(rx.search("http://x.corp.test:8080 [200]"))
        self.assertFalse(rx.search("y.x.corp.test"))
        self.assertFalse(rx.search("x.corp.test.evil"))
        ip = dl.mention_re("127.31.0.23")
        self.assertTrue(ip.search("127.31.0.23:8080"))
        self.assertFalse(ip.search("127.31.0.230"))
        self.assertFalse(ip.search("127.31.0.23.4"))

    def test_counters(self):
        text = """Chain AZCNT (1 references)
    pkts      bytes target     prot opt in     out     source               destination
      10       600            tcp  --  *      *       0.0.0.0/0            127.31.0.0/24        tcp flags:0x17/0x02
       4       300            udp  --  *      *       0.0.0.0/0            127.31.0.0/24
       7       500            udp  --  *      *       0.0.0.0/0            127.0.0.1            udp dpt:5301
       1        60            tcp  --  *      *       0.0.0.0/0            127.0.0.1            tcp dpt:5301
"""
        c = dl.parse_counters(text)
        self.assertEqual(c, {"tcp_syn": 10, "udp": 4, "dns_resolver": 8})
        self.assertEqual(dl.counters_delta({"tcp_syn": 1, "udp": 1, "dns_resolver": 1}, c), {"tcp_syn": 9, "udp": 3, "dns_resolver": 7})
        self.assertIsNone(dl.parse_counters("Chain AZCNT\n"))

    def test_deploy_routes_are_expected_md(self):
        text = read(os.path.join(REPO, "bench", "truth", "deploy"), "expected.md")
        for r in dl.DEPLOY_ROUTES:
            self.assertIn(r["route"], text)
        self.assertIn("POST", text)
        self.assertIn("DELETE", text)
        self.assertIn("role", text)

    def test_deploy_app_has_one_bind_to_patch(self):
        text = read(os.path.join(REPO, "bench", "truth", "deploy"), "app.py")
        self.assertEqual(text.count('ThreadingHTTPServer(("127.0.0.1", PORT)'), 1)


class Arms(unittest.TestCase):
    def test_a1_flags_are_the_replays(self):
        sh = read(os.path.join(REPO, ".github", "ci", "parity"), "replay.sh")
        line = re.search(r"^flags=\((.*)\)$", sh, re.M).group(1)
        want = re.sub(r'"\$domain"', "{domain}", line)
        want = re.sub(r'"\$net"', "{net}", want)
        want = re.sub(r'"\$dns"', "{dns}", want)
        self.assertEqual(want.split(), arms.A1_FLAGS)

    def test_summary_requests(self):
        err = '{"type":"progress"}\n{"type":"summary","command":"run","requests":321,"seconds":12.5,"exit":0}\nnot json\n'
        self.assertEqual(arms.summary_requests(err), {"requests": 321, "seconds": 12.5, "exit": 0})
        self.assertIsNone(arms.summary_requests("nothing"))

    def test_a1_runs_watch_the_documented_way(self):
        seen = {}

        def fake(cmd, cwd, stdout, stderr, stdin, timeout):
            seen.update(cmd=cmd, cwd=cwd)
            stdout.write('{"db":"x"}\n')
            stderr.write('{"type":"summary","command":"run","requests":5}\n')
            return subprocess.CompletedProcess(cmd, 0)

        arms.read_counters = lambda: None
        out, work = tempfile.mkdtemp(), tempfile.mkdtemp()
        with contextlib.redirect_stdout(io.StringIO()):
            arms.a1({"DOMAIN1": "d.test", "NET1": "127.31.0.0/24", "DNS1": "127.0.0.1:5301"}, out, 1, work, "azhaq", 5, run=fake)
        c = seen["cmd"]
        self.assertEqual(c[:2], ["azhaq", "watch"])
        self.assertIn("-json", c)
        self.assertEqual(c[c.index("--") + 1: c.index("--") + 3], ["-domain", "d.test"])
        self.assertEqual(c[-2:], ["-max-time", "300s"])
        self.assertEqual(json.load(open(os.path.join(out, "a1.meta.json")))["summary"]["requests"], 5)

    def test_a2_pipe_with_fake_tools_and_diff(self):
        tools = tempfile.mkdtemp()
        scripts = {
            "dnsx": 'cat "$STUB_DNSX"',
            "naabu": 'cat "$STUB_NAABU"',
            "httpx": 'cat "$STUB_HTTPX"',
            "nuclei": 'cat "$STUB_NUCLEI"',
            # anew: print the lines not in FILE, and add them
            "anew": 'touch "$1"; while IFS= read -r l; do grep -qxF -- "$l" "$1" || { echo "$l" >> "$1"; echo "$l"; }; done',
        }
        for n, body in scripts.items():
            p = os.path.join(tools, n)
            with open(p, "w") as f:
                f.write("#!/bin/bash\n" + body + "\n")
            os.chmod(p, 0o755)
        stub = tempfile.mkdtemp()

        def feed(**lines):
            for k, v in lines.items():
                with open(os.path.join(stub, k), "w") as f:
                    f.write("".join(x + "\n" for x in v))
                os.environ["STUB_" + k.upper()] = os.path.join(stub, k)

        vars_ = {"DOMAIN1": "d.test", "NET1": "127.31.0.0/24", "DNS1": "127.0.0.1:5301"}
        wl = os.path.join(stub, "wl")
        write(wl, "a\nb\n")
        arms.read_counters = lambda: None
        work = tempfile.mkdtemp()
        root = tempfile.mkdtemp()
        with contextlib.redirect_stdout(io.StringIO()):
            feed(dnsx=["a.d.test", "b.d.test"], naabu=["a.d.test:80", "127.31.0.5:8080"], httpx=["http://a.d.test:80 [200] [Hi] [nginx]"], nuclei=["[tech-detect:nginx] [http] [info] http://a.d.test"])
            self.assertEqual(arms.a2(vars_, os.path.join(root, "e0"), 0, work, tools, wl, None), 0)
            feed(dnsx=["a.d.test", "c.d.test"], naabu=["a.d.test:80", "127.31.0.5:8080"], httpx=["http://a.d.test:80 [200] [Hi] [nginx]", "http://c.d.test:80 [200] [New] [Joomla]"], nuclei=[])
            self.assertEqual(arms.a2(vars_, os.path.join(root, "e1"), 1, work, tools, wl, os.path.join(root, "e0")), 0)
        a = os.path.join(root, "e1", "a2")
        self.assertEqual(open(os.path.join(a, "alerts", "dnsx.txt")).read(), "c.d.test\n")
        self.assertEqual(open(os.path.join(a, "alerts", "naabu.txt")).read(), "")
        self.assertEqual(open(os.path.join(a, "diff", "dnsx.gone")).read(), "b.d.test\n")
        self.assertEqual(open(os.path.join(a, "diff", "dnsx.new")).read(), "c.d.test\n")
        self.assertIn("Joomla", open(os.path.join(a, "alerts", "httpx.txt")).read())
        self.assertEqual(open(os.path.join(a, "diff", "nuclei.gone")).read(), "[tech-detect:nginx] [http] [info] http://a.d.test\n")
        # the whole outputs of E0 are the baseline inventory
        self.assertEqual(open(os.path.join(root, "e0", "a2", "alerts", "dnsx.txt")).read(), "a.d.test\nb.d.test\n")


class Apply(unittest.TestCase):
    def test_probe_via_and_status(self):
        # No proxy listens here: a probe through it fails without raising.
        self.assertFalse(drift_apply.probe_via("127.0.0.1", "x.test", {"kind": "http", "path": "/"}, timeout=0.2))

    def test_host_up(self):
        k = {"estates": [{"hosts": [{"host": "a.t", "up": False}, {"host": "b.t", "up": True}, {"host": "c.t"}]}]}
        self.assertFalse(drift_apply.host_up(k, "a.t"))
        self.assertTrue(drift_apply.host_up(k, "b.t"))
        self.assertTrue(drift_apply.host_up(k, "c.t"))
        self.assertFalse(drift_apply.host_up(k, "zzz"))

    def test_epoch_changes_drops_what_does_not_come_up(self):
        """apply.py's bookkeeping with the containers stubbed: a failed change leaves the key."""
        d = planned("s8")
        dplan = json.loads(read(d, "drift-plan.json"))
        base_key = json.loads(read(d, "key.json"))
        live = {"chain": None, "model": dl.model_from_files(d), "epoch": 0}
        ents = dl.by_id(rangelib.load_catalog())
        plan_json = json.loads(read(d, "plan.json"))
        ctx = type("C", (), {"out": d, "vulhub": "/none", "run": staticmethod(lambda *a, **k: (0, "")), "note": staticmethod(lambda t: None)})()
        up = drift_apply.up
        orig = (up.start_env, drift_apply.wait_env, drift_apply.restart_dns, drift_apply.reload_proxy, drift_apply.deploy_version, drift_apply.deploy_ready)
        first_up = [pe["id"] for ch in dplan["epochs"][1]["changes"] for pe in ch.get("envs_up", [])]
        try:
            up.start_env = lambda c, env: (env["id"] != first_up[0], "x")
            drift_apply.wait_env = lambda c, env, m: True
            drift_apply.restart_dns = lambda *a: True
            drift_apply.reload_proxy = lambda *a: None
            drift_apply.deploy_version = lambda v: True
            drift_apply.deploy_ready = lambda *a, **k: True
            args = type("A", (), {"labdns": "x", "run_as": "nobody", "users": [], "no_fence": True})()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(drift_apply.epoch_changes(ctx, d, args, ents, plan_json, base_key, dplan, live, 1), 0)
        finally:
            up.start_env, drift_apply.wait_env, drift_apply.restart_dns, drift_apply.reload_proxy, drift_apply.deploy_version, drift_apply.deploy_ready = orig
        dkey = json.loads(read(d, "drift-key.json"))
        self.assertEqual(dkey["dropped"], 1)
        self.assertEqual(len(dkey["epochs"][1]["changes"]), len(dplan["epochs"][1]["changes"]) - 1)
        self.assertNotIn(first_up[0], live["model"]["envs"])
        self.assertEqual(live["epoch"], 1)


class A3(unittest.TestCase):
    def test_tokens(self):
        s = ['1 {"type":"thread.started"}', '2 {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":40,"output_tokens":7}}',
             '3 {"type":"turn.completed","usage":{"input_tokens":50,"output_tokens":3,"reasoning_output_tokens":2}}', "4 garbage"]
        self.assertEqual(a3.tokens_of(s), {"input": 150, "cached": 40, "output": 10, "reasoning": 2, "turns": 2})

    def test_budgets_and_brief(self):
        self.assertEqual([a3.minutes_for(e) for e in range(4)], [60, 30, 30, 30])
        v = {"DOMAIN1": "corp.test", "NET1": "127.31.0.0/24", "DNS1": "127.0.0.1:5301"}
        p = a3.prompt(v, 2)
        self.assertIn("corp.test", p)
        self.assertIn("changes-E2.jsonl", p)
        self.assertNotRegex(p.lower(), r"experiment|mutation|planted|answer key|\bkey\b|drift|azhaq")
        self.assertNotRegex(p, r"\{\{")


class Grade(unittest.TestCase):
    """Hand-made outputs, one case per class: hit, miss, a false change, an E2 false alarm."""

    def root(self, a1=None, a2=None, a3=None, a1_e2=None, a2_e2=None):
        r = tempfile.mkdtemp()
        key = {"estates": [{"hosts": [
            {"kind": "service", "host": "old1.c.test", "address": "127.31.0.10", "vhost": False, "up": True, "ports": [{"port": 80}]},
            {"kind": "service", "host": "v1.c.test", "address": "127.31.0.99", "vhost": True, "up": True, "ports": [{"port": 80}]}]}]}
        e1 = [
            {"id": "e1c1", "class": "new-host", "name": "nh.c.test", "address": "127.31.0.20", "port": 8080, "product": "Jenkins", "version": "2.46.1", "env": "x"},
            {"id": "e1c2", "class": "new-port", "name": "old1.c.test", "address": "127.31.0.10", "port": 6379, "product": "Redis", "version": "4.0.14"},
            {"id": "e1c3", "class": "swap", "name": "sw.c.test", "address": "127.31.0.30", "port": 80, "product": "Apache Tomcat", "version": "8.5.19"},
            {"id": "e1c4", "class": "new-vhost", "name": "vh.c.test", "address": "127.31.0.99", "port": 80, "product": "Joomla!", "version": "4.2.7"}]
        e3 = [
            {"id": "e3c1", "class": "dangling", "name": "cdn.c.test", "target": "t.azurewebsites.net", "mode": "target-gone"},
            {"id": "e3c2", "class": "gone", "name": "gn.c.test", "address": "127.31.0.40", "ports": [80]},
            {"id": "e3c3", "class": "deploy", "name": "api.c.test", "address": "127.31.0.50", "port": 8080, "routes": dl.DEPLOY_ROUTES}]
        dk = {"dropped": 0, "epochs": [{"epoch": 0, "changes": []}, {"epoch": 1, "changes": e1}, {"epoch": 2, "changes": []}, {"epoch": 3, "changes": e3}]}
        write(os.path.join(r, "key.json"), json.dumps(key))
        write(os.path.join(r, "drift-key.json"), json.dumps(dk))
        for e in range(4):
            os.makedirs(os.path.join(r, "e%d" % e))
        for e, o in (a1 or {}).items():
            write(os.path.join(r, "e%d" % e, "a1.json"), json.dumps(o))
        for e, files in (a2 or {}).items():
            base = os.path.join(r, "e%d" % e, "a2", "alerts")
            os.makedirs(base)
            for st, ls in files.items():
                write(os.path.join(base, st + ".txt"), "".join(x + "\n" for x in ls))
        for e, ls in (a3 or {}).items():
            os.makedirs(os.path.join(r, "e%d" % e, "a3"))
            write(os.path.join(r, "e%d" % e, "a3", "changes-E%d.jsonl" % e), "".join(json.dumps(x) + "\n" for x in ls))
        return r

    def test_a1_hits_and_misses(self):
        a1 = {
            1: {"hosts": ["nh.c.test (127.31.0.20)", "stray.c.test (127.31.0.200)"],
                "services": ["http://nh.c.test:8080/ [200] Dashboard [Jenkins]", "http://vh.c.test/ [200] Joomla! Home"],
                "ports": ["old1.c.test: 80,6379"], "changed": ["http://sw.c.test/: [200] Old → [200] Apache Tomcat/8.5.19"]},
            2: {"hosts": ["boo.c.test (127.31.0.7)"]},
            3: {"gone_hosts": ["gn.c.test", "cdn.c.test"],
                "routes": [{"kind": "new", "route": "/api/v2/export", "methods_added": ["POST"], "fields_added": ["format", "userId"], "host": "api.c.test"},
                           {"kind": "methods", "route": "/api/orders/{orderId}", "methods_added": ["DELETE"]},
                           {"kind": "gone", "route": "/api/legacy/report"}]},
        }
        res = grade.grade(self.root(a1=a1))
        t = res["arms"]["a1"]["totals"]
        c = t["classes"]
        self.assertEqual((c["new-host"]["hit"], c["new-host"]["of"]), (1, 1))
        self.assertEqual(c["new-port"]["hit"], 1)
        self.assertEqual(c["swap"]["hit"], 1)
        self.assertEqual(c["new-vhost"]["hit"], 1)
        self.assertEqual((c["dangling"]["hit"], c["dangling"]["seen"]), (0, 1), "a gone name is not flagged dangling")
        self.assertEqual(c["gone"]["hit"], 1)
        self.assertEqual((c["deploy"]["hit"], c["deploy"]["of"]), (3, 4), "the field line is missed")
        self.assertEqual(t["ident"], {"of": 4, "product": 3, "version": 1})  # a ports line names no product; only the Tomcat title has a version
        self.assertEqual(t["false_changes"], 1, "stray.c.test is in no change")
        self.assertEqual(t["false_alarms"], 1)
        self.assertEqual(res["arms"]["a1"]["epochs"]["2"]["false_list"], ["boo.c.test"])

    def test_a2_sees_addresses_and_misses_what_it_cannot_see(self):
        a2 = {1: {"dnsx": ["nh.c.test", "vh.c.test"], "naabu": ["127.31.0.20:8080", "old1.c.test:6379", "vh.c.test:80"],
                  "httpx": ["http://127.31.0.20:8080 [200] [Dashboard] [Jenkins]"], "nuclei": ["[tech-detect:jenkins] [http] [info] http://127.31.0.20:8080"]},
              2: {"httpx": ["http://old1.c.test:80 [503] [x]"]}, 3: {}}
        res = grade.grade(self.root(a2=a2))
        t = res["arms"]["a2"]["totals"]
        c = t["classes"]
        self.assertEqual(c["new-host"]["hit"], 1)
        self.assertEqual(c["new-host"]["by_name"], 1)
        self.assertEqual(c["new-port"]["hit"], 1)
        self.assertEqual(c["swap"]["hit"], 0)
        self.assertEqual(c["new-vhost"]["hit"], 1)
        self.assertEqual(c["deploy"]["hit"], 0)
        self.assertEqual(c["gone"]["hit"], 0, "anew never prints a gone line")
        self.assertEqual(t["false_changes"], 0)
        self.assertEqual(t["false_alarms"], 1)

    def test_a2_by_address_only(self):
        a2 = {1: {"naabu": ["127.31.0.20:8080"]}}
        c = grade.grade(self.root(a2=a2))["arms"]["a2"]["totals"]["classes"]["new-host"]
        self.assertEqual((c["hit"], c["by_name"]), (1, 0))

    def test_a3_jsonl(self):
        a3 = {
            1: [{"kind": "new", "asset": "nh.c.test:8080", "product": "Jenkins", "version": "2.46.1", "detail": "new host", "priority": 1},
                {"kind": "changed", "asset": "sw.c.test", "product": "Tomcat", "version": "8.5.19", "detail": "swapped", "priority": 2},
                {"kind": "new", "asset": "ghost.c.test", "detail": "a guess", "priority": 3}],
            2: [],
            3: [{"kind": "gone", "asset": "gn.c.test", "detail": "no longer resolves"},
                {"kind": "changed", "asset": "cdn.c.test", "detail": "dangling CNAME: its target no longer resolves, a takeover candidate"},
                {"kind": "new", "asset": "POST /api/v2/export", "detail": "api.c.test now sends format and userId; new route"},
                {"kind": "changed", "asset": "/api/orders/{id}", "detail": "DELETE added"},
                {"kind": "changed", "asset": "PUT /api/profile", "detail": "the body now has role"},
                {"kind": "gone", "asset": "/api/legacy/report", "detail": "removed from main.js"}]}
        res = grade.grade(self.root(a3=a3))
        t = res["arms"]["a3"]["totals"]
        c = t["classes"]
        self.assertEqual(c["new-host"]["hit"], 1)
        self.assertEqual(c["swap"]["hit"], 1)
        self.assertEqual(c["dangling"]["hit"], 1)
        self.assertEqual(c["gone"]["hit"], 1)
        self.assertEqual((c["deploy"]["hit"], c["deploy"]["of"]), (4, 4))
        self.assertEqual(c["new-port"]["hit"], 0)
        self.assertEqual(t["false_changes"], 1)
        self.assertEqual(t["false_alarms"], 0)

    def test_missing_output_is_a_miss_and_flagged(self):
        res = grade.grade(self.root())
        t = res["arms"]["a1"]["totals"]
        self.assertEqual(t["hit"], 0)
        self.assertEqual(t["of"], 10)
        self.assertEqual(t["missing"], 3)

    def test_e0_inventory(self):
        r = self.root(a1={0: {"baseline": True, "hosts": ["old1.c.test (127.31.0.10)"], "services": ["http://v1.c.test/ [200] x"]}})
        inv = grade.grade(r)["arms"]["a1"]["epochs"]["0"]["inventory"]
        self.assertEqual((inv["hosts"], inv["hosts_of"], inv["ports"], inv["ports_of"]), (2, 2, 0, 1))

    def test_product_and_version_naming(self):
        r = grade.rec("new", "x.t:80", "Java RMI registry listens")
        self.assertTrue(grade.names_product(r, "Java RMI registry"))
        self.assertFalse(grade.names_product(grade.rec("new", "x.t", "nginx"), "uWSGI behind nginx"))
        self.assertTrue(grade.names_product(grade.rec("new", "x.t", "uwsgi 2.0"), "uWSGI behind nginx"))
        self.assertTrue(grade.names_product(grade.rec("new", "x.t", "H2 console"), "H2 Database console (Spring app)"))
        self.assertTrue(grade.names_version(grade.rec("new", "x.t", "Tomcat/8.5.19"), "8.5.19"))
        self.assertFalse(grade.names_version(grade.rec("new", "x.t", "Tomcat/8.5.190"), "8.5.19"))
        self.assertFalse(grade.names_version(grade.rec("new", "x.t", "x"), ""))


class Summary(unittest.TestCase):
    def sample(self, recall_hit, of, a2_hit, false_a1, false_a2, alarms, a1_min, a3=None):
        def arm(hit, f, a, wall, prod=4):
            return {"totals": {"hit": hit, "of": of, "seen": hit, "by_name": hit, "classes": {"gone": {"of": 1, "hit": 1, "seen": 1, "by_name": 1}},
                               "false_changes": f, "false_alarms": a, "ident": {"of": 4, "product": prod, "version": 1}, "wall_s": wall * 60, "requests": 0,
                               "tokens": 0, "missing": 0}, "epochs": {}}
        arms_ = {"a1": arm(recall_hit, false_a1, alarms, a1_min), "a2": arm(a2_hit, false_a2, 3, 50)}
        if a3:
            arms_["a3"] = arm(a3[0], 1, 0, a3[1])
        return {"arms": arms_}

    def test_rules(self):
        good = self.sample(9, 10, 5, 0, 10, 0, 10, a3=(7, 150))
        samples = {"s%d" % i: good for i in range(1, 5)}
        text, data = summary.render(samples)
        self.assertEqual(data["verdicts"], {"1": "holds", "2": "holds", "3": "holds"})
        self.assertIn("A passes", text)

    def test_one_failing_sample_of_four_still_holds_two_fail_it(self):
        good = self.sample(9, 10, 5, 0, 10, 0, 10, a3=(7, 150))
        bad = self.sample(5, 10, 5, 0, 10, 2, 10, a3=(7, 150))
        _, d = summary.render({"s1": good, "s2": good, "s3": good, "s4": bad})
        self.assertEqual(d["verdicts"]["1"], "holds")
        _, d = summary.render({"s1": good, "s2": good, "s3": bad, "s4": bad})
        self.assertEqual(d["verdicts"]["1"], "fails")

    def test_fewer_than_four_samples_give_no_verdict(self):
        _, d = summary.render({"s1": self.sample(9, 10, 5, 0, 10, 0, 10)})
        self.assertTrue(d["verdicts"]["1"].startswith("no verdict"))
        self.assertIsNone(d["verdicts"]["3"], "no A3 in a dry run")

    def test_false_change_ratio(self):
        s = self.sample(9, 10, 5, 3, 10, 0, 10)
        _, d = summary.render({"s1": s})
        self.assertFalse(d["rules"]["s1"]["2"], "3 > 10/5")
        s = self.sample(9, 10, 5, 2, 10, 0, 10)
        _, d = summary.render({"s1": s})
        self.assertTrue(d["rules"]["s1"]["2"])

    def test_wall_time_rule(self):
        s = self.sample(9, 10, 5, 0, 10, 0, 16, a3=(7, 150))
        _, d = summary.render({"s1": s})
        self.assertFalse(d["rules"]["s1"]["3"], "16 min > 150/10")


class Files(unittest.TestCase):
    def test_shell_scripts_parse(self):
        for n in ("launch.sh", "fetch.sh", "install-tools.sh", "agent-user.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(HERE, n)]).returncode, 0, n)

    def test_workflow(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("no yaml")
        w = yaml.safe_load(read(os.path.join(REPO, ".github", "workflows"), "exp-drift.yml"))
        self.assertEqual(w[True]["push"]["tags"], ["exp-drift-*"])
        self.assertEqual(list(w["jobs"]), ["kind", "build", "drift"])
        d = w["jobs"]["drift"]
        self.assertEqual(d["strategy"]["max-parallel"], 2)
        self.assertEqual(d["timeout-minutes"], 330)
        steps = " ".join(s.get("run", "") for s in d["steps"])
        self.assertNotIn("azhaq watch", steps)
        for script in re.findall(r"\.github/ci/exp/drift/([\w.-]+)", steps):
            self.assertTrue(os.path.exists(os.path.join(HERE, script)), script)

    def test_launch_refuses_bad_arguments(self):
        for args in (["x", "huge"], ["x", "dryrun", "samples=9"], ["x", "dryrun", "n=2"]):
            r = subprocess.run(["bash", os.path.join(HERE, "launch.sh")] + args, capture_output=True)
            self.assertEqual(r.returncode, 2, args)


if __name__ == "__main__":
    unittest.main()
