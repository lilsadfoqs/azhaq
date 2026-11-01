"""Tests for the range scripts. No docker, no network:
    python3 -m unittest discover -s .github/ci/range
VULHUB=/path/to/checkout also renders every override with `docker compose config`.
"""
import gzip
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build  # noqa: E402
import grade  # noqa: E402
import merge_gate  # noqa: E402
import pool_pick  # noqa: E402
import rangelib  # noqa: E402
import render_brief  # noqa: E402
import smoke  # noqa: E402
import smoke_apply  # noqa: E402
import up  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
CAT = rangelib.load_catalog()


class Catalog(unittest.TestCase):
    def test_entries_are_complete(self):
        ids = set()
        for e in CAT["entries"]:
            self.assertNotIn(e["id"], ids)
            ids.add(e["id"])
            self.assertIn(e["category"], CAT["categories"], e["id"])
            self.assertTrue(e["summary"] and e["product"] and e["version"], e["id"])
            self.assertTrue(e["ports"], e["id"])
            prim = [p for p in e["ports"] if p["primary"]]
            self.assertEqual(len(prim), 1, e["id"])
            self.assertEqual(e["probe"]["port"], prim[0]["host_port"], e["id"])
            self.assertIn(e["probe"]["kind"], ("http", "tcp", "dns-tcp"), e["id"])
            self.assertGreater(e["mem_mb"], 0)
            self.assertLessEqual(e["mem_mb"], 1500, e["id"] + ": the brief allows at most 1.5 GB")
            for s in e["services"].values():
                self.assertTrue(s["image"], e["id"])
            for p in e["ports"]:
                self.assertIn(p["service"], e["services"], e["id"])

    def test_size_and_spread(self):
        n = len(CAT["entries"])
        self.assertTrue(60 <= n <= 100, n)
        per = {}
        for e in CAT["entries"]:
            per[e["category"]] = per.get(e["category"], 0) + 1
        for c in CAT["categories"]:
            # two disjoint estates draw from each; the smoke run drops what failed
            self.assertGreaterEqual(per.get(c, 0), 4, c)

    def test_pinned(self):
        self.assertRegex(CAT["vulhub"]["commit"], r"^[0-9a-f]{40}$")

    @unittest.skipUnless(os.environ.get("VULHUB") and shutil.which("docker"), "set VULHUB to a checkout to render with docker compose config")
    def test_overrides_render_with_compose(self):
        dec = json.JSONDecoder()
        for e in CAT["entries"]:
            with tempfile.NamedTemporaryFile("w", suffix=".yml") as f:
                f.write(rangelib.override_text(e, "127.31.0.9"))
                f.flush()
                rc, out = rangelib.sh(rangelib.compose_cmd("az-t", os.path.join(os.environ["VULHUB"], e["path"]), f.name, "config", "--format", "json"),
                                      env={"TARGET_IP": "127.31.0.9"})
            self.assertEqual(rc, 0, e["id"] + out[:200])
            doc, _ = dec.raw_decode(out[out.index("{"):])
            got = {(n, int(p["published"]), p["target"], p["protocol"]) for n, s in doc["services"].items() for p in s.get("ports", []) if p["host_ip"] == "127.31.0.9"}
            allp = sum(len(s.get("ports", [])) for s in doc["services"].values())
            self.assertEqual(allp, len(got), e["id"] + ": a port stayed published on another address")
            self.assertEqual(got, {(p["service"], p["host_port"], p["container_port"], p["transport"]) for p in e["ports"]}, e["id"])


class Lib(unittest.TestCase):
    def test_override_text(self):
        e = {"ports": [{"service": "web", "host_port": 8080, "container_port": 80, "transport": "tcp"},
                       {"service": "web", "host_port": 53, "container_port": 53, "transport": "udp"}]}
        t = rangelib.override_text(e, "127.31.0.7", {8080: 9090})
        self.assertIn("ports: !override", t)
        self.assertIn('"127.31.0.7:9090:80/tcp"', t)
        self.assertIn('"127.31.0.7:53:53/udp"', t)

    def test_parse_size(self):
        self.assertAlmostEqual(rangelib.parse_size_mb("512MiB / 15GiB"), 512)
        self.assertAlmostEqual(rangelib.parse_size_mb("1.5GiB"), 1536)
        self.assertAlmostEqual(rangelib.parse_size_mb("1024KiB"), 1)
        self.assertIsNone(rangelib.parse_size_mb("--"))

    def test_project_name(self):
        self.assertEqual(rangelib.project_name("Jenkins--CVE-2018.1", "x"), "x-jenkins--cve-2018-1")

    def _http(self, status):
        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b"x")

            def log_message(self, *a):
                pass
        srv = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        return srv.server_address[1]

    def test_http_probe(self):
        for status, ok in ((200, True), (403, True), (404, True), (503, False)):
            port = self._http(status)
            got, _ = rangelib.probe_once({"kind": "http", "port": port, "path": "/", "status_below": 500}, "127.0.0.1")
            self.assertEqual(got, ok, status)

    def _tcp(self, banner=None, close=False, reply=None):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)
        self.addCleanup(srv.close)

        def serve():
            while True:
                try:
                    c, _ = srv.accept()
                except OSError:
                    return
                if close:
                    c.close()
                    continue
                if banner:
                    c.sendall(banner)
                if reply:
                    try:
                        c.recv(100)
                        c.sendall(reply)
                    except OSError:
                        pass
                time.sleep(3)
                c.close()
        threading.Thread(target=serve, daemon=True).start()
        return srv.getsockname()[1]

    def test_tcp_probes(self):
        port = self._tcp(banner=b"SSH-2.0-OpenSSH_9\r\n")
        self.assertTrue(rangelib.probe_once({"kind": "tcp", "port": port, "expect": "^SSH-"}, "127.0.0.1", timeout=2)[0])
        port = self._tcp(banner=b"HTTP/1.1 400\r\n")
        self.assertFalse(rangelib.probe_once({"kind": "tcp", "port": port, "expect": "^SSH-"}, "127.0.0.1", timeout=1)[0])
        port = self._tcp(reply=b"+PONG\r\n")
        self.assertTrue(rangelib.probe_once({"kind": "tcp", "port": port, "send": "PING\r\n", "expect": "PONG"}, "127.0.0.1", timeout=2)[0])
        # A published port with nothing behind it: the proxy accepts and hangs up.
        port = self._tcp(close=True)
        self.assertFalse(rangelib.probe_once({"kind": "tcp", "port": port}, "127.0.0.1", timeout=2)[0])
        port = self._tcp()
        self.assertTrue(rangelib.probe_once({"kind": "tcp", "port": port}, "127.0.0.1", timeout=2)[0])

    def test_probe_refused_is_a_failure_not_an_error(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertFalse(rangelib.probe_once({"kind": "http", "port": port}, "127.0.0.1")[0])

    def test_wait_ready(self):
        t = [0.0]
        calls = []

        def check(p, a, r):
            calls.append(t[0])
            return t[0] >= 9, "late"
        ok, secs, _ = rangelib.wait_ready({"port": 1}, "x", 30, clock=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s), check=check, interval=3)
        self.assertTrue(ok)
        self.assertEqual(secs, 9)
        t[0] = 0
        ok, secs, _ = rangelib.wait_ready({"port": 1}, "x", 6, clock=lambda: t[0], sleep=lambda s: t.__setitem__(0, t[0] + s), check=lambda *a: (False, "no"), interval=3)
        self.assertFalse(ok)
        self.assertEqual(secs, 6)

    def test_remap_applies_to_the_probe(self):
        seen = []
        rangelib.probe_once  # noqa: B018
        ok, _, _ = rangelib.wait_ready({"port": 8080}, "a", 0, {8080: 9999}, check=lambda p, a, r: (seen.append(r) or True, "ok"))
        self.assertEqual(seen, [{8080: 9999}])


class Pool(unittest.TestCase):
    """The gate's fixed pool (range/pool.json) and how a run picks from it."""

    def test_pool_file_is_a_non_empty_list_of_unique_seeds(self):
        pool = rangelib.load_pool()
        self.assertGreaterEqual(len(pool), 4)
        self.assertEqual(len(pool), len(set(pool)))
        self.assertTrue(all(isinstance(s, str) and s for s in pool))

    def test_load_pool_rejects_bad_files(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        for bad in ([], ["a", "a"], ["a", ""], "not-a-list", [1, 2]):
            p = os.path.join(tmp, "p.json")
            with open(p, "w") as f:
                json.dump(bad, f)
            with self.assertRaises(SystemExit):
                rangelib.load_pool(p)

    def test_round_robin_by_run_number(self):
        pool = ["w", "x", "y", "z"]
        got = [rangelib.pick_pool_seed(pool, n) for n in (1, 2, 3, 4, 5, 6)]
        self.assertEqual(got, ["w", "x", "y", "z", "w", "x"])

    def test_requested_seed_wins_and_must_be_in_the_pool(self):
        pool = ["w", "x", "y", "z"]
        self.assertEqual(rangelib.pick_pool_seed(pool, 1, "y"), "y")
        self.assertEqual(rangelib.pick_pool_seed(pool, 999, "y"), "y")  # the run number is ignored
        with self.assertRaises(SystemExit):
            rangelib.pick_pool_seed(pool, 1, "not-in-the-pool")

    def test_sample_two_is_always_a_different_estate(self):
        pool = ["w", "x", "y", "z"]
        for n in range(1, 9):
            s1 = rangelib.pick_pool_seed(pool, n, sample=1)
            s2 = rangelib.pick_pool_seed(pool, n, sample=2)
            self.assertNotEqual(s1, s2)
        self.assertEqual(rangelib.pick_pool_seed(pool, 1, "z", sample=2), "w")  # wraps around

    def test_cli_prints_one_seed(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "pool_pick.py"), "3"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(r.stdout.strip(), rangelib.load_pool())

    def test_cli_rejects_a_seed_outside_the_pool(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "pool_pick.py"), "1", "--seed", "not-a-pool-entry"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)


def entry(i, cat="cms", mem=100, family=None, **kw):
    e = {"id": "e%d" % i, "path": "x/e%d" % i, "product": "P%d" % i, "family": family or "f%d" % i, "version": "1", "cve": ["CVE-2020-%04d" % i],
         "category": cat, "services": {"web": {"image": "img%d" % i}},
         "ports": [{"service": "web", "host_port": 8080, "container_port": 80, "transport": "tcp", "protocol": "http", "primary": True}],
         "probe": {"kind": "http", "port": 8080, "path": "/", "status_below": 500}, "summary": "s", "mem_mb": mem, "ready_s": 30,
         "names": ["n%d" % i], "proxy": True}
    e.update(kw)
    return e


class Smoke(unittest.TestCase):
    def test_batches_respect_memory_and_count(self):
        es = [entry(i, mem=m) for i, m in enumerate([900, 800, 700, 100, 100, 100])]
        bs = smoke.make_batches(es, 1700, 3)
        self.assertTrue(all(sum(e["mem_mb"] for e in b) <= 1700 and len(b) <= 3 for b in bs))
        self.assertEqual(sorted(e["id"] for b in bs for e in b), sorted(e["id"] for e in es))
        self.assertEqual(smoke.make_batches([entry(1, mem=5000)], 1000, 3)[0][0]["id"], "e1")

    def test_shards_partition(self):
        es = [entry(i, mem=i * 10) for i in range(10)]
        got = sorted(e["id"] for i in range(3) for e in smoke.shard(es, "%d/3" % i))
        self.assertEqual(got, sorted(e["id"] for e in es))

    def test_run_batch_records_results(self):
        cmds = []

        def run(cmd, cwd=None, env=None, timeout=0):
            cmds.append(cmd)
            if cmd[:2] == ["docker", "compose"] and "up" in cmd:
                # By the project only: the temporary paths in the command are random.
                return (1, "pull access denied") if cmd[3] == rangelib.project_name("e1", "azs") else (0, "")
            if cmd[:2] == ["docker", "ps"]:
                return 0, "abc\ndef\n"
            if cmd[:2] == ["docker", "stats"]:
                return 0, "100MiB / 15GiB\n50MiB / 15GiB\n"
            if cmd[:3] == ["docker", "image", "inspect"]:
                return 0, str(200 * 1024 * 1024) + "\n"
            return 0, ""

        def check(p, a, r):
            return (a.endswith(".10"), "refused")  # only the first entry answers
        ctx = smoke.Ctx("/vh", tempfile.mkdtemp(), run=run, check=check, settle=0, sleep=lambda s: None)
        t = [0]
        ctx.clock = lambda: t.__setitem__(0, t[0] + 1) or t[0]
        res = smoke.run_batch(ctx, [entry(0), entry(1), entry(2)])
        by = {r["id"]: r for r in res}
        self.assertTrue(by["e0"]["ok"])
        self.assertFalse(by["e1"]["ok"])
        self.assertIn("compose up failed", by["e1"]["reason"])
        ok = [r for r in res if r["ok"]]
        self.assertEqual(len(ok), 1)
        self.assertEqual(ok[0]["mem_mb"], 150)
        self.assertEqual(ok[0]["image_mb"], 200)
        bad = [r for r in res if r["ok"] is False and "probe failed" in r.get("reason", "")]
        self.assertEqual(len(bad), 1)
        self.assertTrue(any(c[-2:] == ["--volumes"] or "prune" in c for c in cmds), "the disk is freed after a batch")
        self.assertTrue(any("down" in c for c in cmds))

    def test_apply_keeps_only_passes(self):
        cat = {"vulhub": {"commit": "a" * 40}, "categories": ["cms"], "entries": [entry(1), entry(2), entry(3)]}
        doc = {"vulhub_commit": "a" * 40, "results": [
            {"id": "e1", "ok": True, "ready_s": 12.5, "mem_mb": 321, "image_mb": 456},
            {"id": "e2", "ok": False, "reason": "probe failed"},
            {"id": "other", "ok": True}]}
        new, summary = smoke_apply.apply(cat, [doc])
        self.assertEqual([e["id"] for e in new["entries"]], ["e1", "e3"])
        self.assertEqual(new["entries"][0]["mem_mb_measured"], 321)
        self.assertEqual(new["entries"][0]["image_mb"], 456)
        self.assertEqual(new["dropped"][0]["id"], "e2")
        self.assertEqual(summary["kept"], 2)
        # a dry run changes nothing; a result for another Vulhub commit is refused
        same, _ = smoke_apply.apply(cat, [{"dry_run": True, "vulhub_commit": "b" * 40, "results": [{"id": "e1", "ok": None}]}])
        self.assertEqual(len(same["entries"]), 3)
        with self.assertRaises(ValueError):
            smoke_apply.apply(cat, [{"vulhub_commit": "b" * 40, "results": []}])


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "o")
        build.main(["unit-1", "--out", cls.out])
        cls.key = json.load(open(os.path.join(cls.out, "key.json")))
        cls.plan = json.load(open(os.path.join(cls.out, "plan.json")))
        cls.vars = json.load(open(os.path.join(cls.out, "vars.json")))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def services(self, est):
        return [h for h in est["hosts"] if h["kind"] == "service"]

    def test_deterministic_and_seed_dependent(self):
        for seed, same in (("unit-1", True), ("unit-2", False)):
            out = os.path.join(self.tmp, "again-" + seed)
            build.main([seed, "--out", out])
            self.assertEqual(open(os.path.join(out, "key.json")).read() == open(os.path.join(self.out, "key.json")).read(), same)

    def test_two_disjoint_estates_with_the_same_mix(self):
        a, b = self.key["estates"]
        ea = {h["env"] for h in self.services(a)}
        eb = {h["env"] for h in self.services(b)}
        self.assertEqual(len(ea), 10)
        self.assertEqual(len(eb), 10)
        self.assertFalse(ea & eb)
        mix = lambda est: sorted(h["category"] for h in self.services(est))  # noqa: E731
        self.assertEqual(mix(a), mix(b))
        for est in (a, b):
            fams = [next(e["family"] for e in CAT["entries"] if e["id"] == h["env"]) for h in self.services(est)]
            self.assertEqual(len(fams), len(set(fams)), "a product family twice in one estate")

    def test_memory_budget(self):
        by = {e["id"]: e for e in CAT["entries"]}
        total = sum(build.mem(by[h["env"]]) for est in self.key["estates"] for h in self.services(est))
        self.assertLessEqual(total, 9500)
        with self.assertRaises(SystemExit):
            build.main(["unit-1", "--out", os.path.join(self.tmp, "tight"), "--budget-mb", "2000"])

    def test_domains_networks_and_addresses(self):
        a, b = self.key["estates"]
        self.assertNotEqual(a["domain"], b["domain"])
        self.assertTrue(a["domain"].endswith(".test") and b["domain"].endswith(".test"))
        self.assertEqual(self.vars["DOMAIN1"], a["domain"])
        self.assertEqual(self.vars["NET2"], "127.47.0.0/24")
        for est, prefix in ((a, "127.31.0."), (b, "127.47.0.")):
            direct = [h["address"] for h in self.services(est) if not h["vhost"]]
            self.assertEqual(len(direct), len(set(direct)), "one address per host")
            self.assertTrue(all(x.startswith(prefix) for x in direct))
            infra = [h for h in est["hosts"] if h["kind"] == "infra"][0]
            self.assertTrue(infra["address"].startswith(prefix))
            self.assertNotIn(infra["address"], direct)
        names = [h["host"] for est in self.key["estates"] for h in est["hosts"]]
        self.assertEqual(len(names), len(set(names)))

    def test_name_servers_are_inside_the_range_on_unused_addresses(self):
        for i, est in enumerate(self.key["estates"], 1):
            prefix = est["net"].rsplit(".", 1)[0] + "."
            used = {h["address"] for h in est["hosts"] if h.get("address")}
            self.assertEqual(len(est["ns"]), 2)
            self.assertEqual(len({n["address"] for n in est["ns"]}), 2)
            z = json.load(open(os.path.join(self.out, "zone-%d.json" % i)))
            recs = z["zones"][est["domain"] + "."]
            self.assertEqual(sorted(r for r in recs[est["domain"] + "."] if r.startswith("NS ")),
                             ["NS ns1.%s." % est["domain"], "NS ns2.%s." % est["domain"]])
            for n in est["ns"]:
                self.assertTrue(n["address"].startswith(prefix), n)
                self.assertNotIn(n["address"], used)
                self.assertEqual(recs[n["host"] + "."], ["A " + n["address"]])
            for env in self.plan["envs"]:
                if env["estate"] == i:
                    self.assertNotIn(env["address"], [n["address"] for n in est["ns"]])
            d = next(x for x in self.plan["dns"] if x["estate"] == i)
            self.assertEqual(d["ns"], [n["address"] for n in est["ns"]])
            self.assertEqual(d["listen"], est["dns"])

    def test_name_servers_refuse_a_transfer(self):
        # Even beside a planted BIND that allows one: that BIND has its own zone and host.
        for seed in ("unit-1", "d", "n"):
            out = os.path.join(self.tmp, "x-" + seed)
            build.main([seed, "--out", out])
            key = json.load(open(os.path.join(out, "key.json")))
            for i, _ in enumerate(key["estates"], 1):
                z = json.load(open(os.path.join(out, "zone-%d.json" % i)))
                self.assertFalse(z["axfr"], (seed, i))

    def test_vhosts_dangling_and_names(self):
        for est in self.key["estates"]:
            vh = [h for h in self.services(est) if h["vhost"]]
            self.assertEqual(len(vh), 3)
            self.assertEqual({h["address"] for h in vh}, {[h for h in est["hosts"] if h["kind"] == "infra"][0]["address"]})
            self.assertEqual(len([h for h in est["hosts"] if h["kind"] == "dangling-cname"]), 2)
            labels = {h["host"].split(".")[0] for h in self.services(est)}
            by = {e["id"]: e for e in CAT["entries"]}
            product_named = [h for h in self.services(est) if h["host"].split(".")[0] in by[h["env"]]["names"]]
            self.assertTrue(product_named, "some names are named after the product")
            self.assertTrue(len(labels) > len(product_named), "some are neutral")

    def test_zone_and_proxy_files(self):
        for i, est in enumerate(self.key["estates"], 1):
            z = json.load(open(os.path.join(self.out, "zone-%d.json" % i)))
            origin = est["domain"] + "."
            recs = z["zones"][origin]
            self.assertTrue(any(r.startswith("SOA ") for r in recs[origin]))
            for h in est["hosts"]:
                if h["kind"] == "service" and not h["vhost"]:
                    self.assertIn("A " + h["address"], recs[h["host"] + "."])
                if h["kind"] == "dangling-cname":
                    self.assertEqual(recs[h["host"] + "."], ["CNAME " + h["target"]])
            conf = open(os.path.join(self.out, "proxy-%d.conf" % i)).read()
            for h in est["hosts"]:
                if h.get("vhost"):
                    self.assertIn("server_name %s;" % h["host"], conf)
                    self.assertIn(h["host"] + ".", recs)
            self.assertIn("return 404;", conf)

    def test_overrides_match_the_key(self):
        by = {e["id"]: e for e in CAT["entries"]}
        for env in self.plan["envs"]:
            text = open(os.path.join(self.out, env["override"])).read()
            e = by[env["id"]]
            for p in e["ports"]:
                port = {int(k): v for k, v in env["remap"].items()}.get(p["host_port"], p["host_port"])
                self.assertIn('"%s:%d:%d/%s"' % (env["address"], port, p["container_port"], p["transport"]), text)
            if env["backend"]:
                self.assertTrue(env["address"].startswith("127.20"))
        for est in self.key["estates"]:
            for h in self.services(est):
                if h["vhost"]:
                    continue
                env = next(x for x in self.plan["envs"] if x["id"] == h["env"])
                prim = [p for p in h["ports"] if p["primary"]][0]["port"]
                self.assertEqual(prim, {int(k): v for k, v in env["remap"].items()}.get(next(p["host_port"] for p in by[h["env"]]["ports"] if p["primary"]),
                                                                                         next(p["host_port"] for p in by[h["env"]]["ports"] if p["primary"])))

    def test_some_ports_are_not_the_default(self):
        moved = 0
        for seed in ("a", "b", "c"):
            out = os.path.join(self.tmp, "m" + seed)
            build.main([seed, "--out", out])
            moved += sum(len(e["remap"]) for e in json.load(open(os.path.join(out, "plan.json")))["envs"])
        self.assertGreater(moved, 0)

    def test_hidden_vhosts_have_no_dns_name(self):
        out = os.path.join(self.tmp, "hid")
        build.main(["unit-1", "--out", out, "--hidden-vhosts", "1"])
        key = json.load(open(os.path.join(out, "key.json")))
        for i, est in enumerate(key["estates"], 1):
            hid = [h for h in est["hosts"] if h["kind"] == "service" and not h["dns_visible"]]
            self.assertEqual(len(hid), 1)
            z = json.load(open(os.path.join(out, "zone-%d.json" % i)))
            self.assertNotIn(hid[0]["host"] + ".", z["zones"][est["domain"] + "."])
            self.assertIn("server_name %s;" % hid[0]["host"], open(os.path.join(out, "proxy-%d.conf" % i)).read())

    def test_build_prints_no_estate_detail(self):
        r = subprocess.run([sys.executable, os.path.join(HERE, "build.py"), "unit-1", "--out", os.path.join(self.tmp, "quiet")], capture_output=True, text=True)
        for est in self.key["estates"]:
            self.assertNotIn(est["domain"], r.stdout + r.stderr)
        for h in self.key["estates"][0]["hosts"]:
            self.assertNotIn(h.get("product") or "-", r.stdout)


class BuildSingle(unittest.TestCase):
    """The gate's pool builds one estate (build.py --count 1), not a pair."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "o")
        build.main(["gate-unit-1", "--out", cls.out, "--count", "1"])
        cls.key = json.load(open(os.path.join(cls.out, "key.json")))
        cls.plan = json.load(open(os.path.join(cls.out, "plan.json")))
        cls.vars = json.load(open(os.path.join(cls.out, "vars.json")))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_one_estate_only(self):
        self.assertEqual(len(self.key["estates"]), 1)
        self.assertEqual(self.key["estates"][0]["index"], 1)
        self.assertEqual({e["estate"] for e in self.plan["envs"]}, {1})
        self.assertEqual(len(self.plan["proxies"]), 1)
        self.assertEqual(len(self.plan["dns"]), 1)

    def test_vars_has_no_second_estate(self):
        self.assertEqual(set(self.vars), {"DOMAIN1", "NET1", "DNS1"})
        self.assertEqual(self.vars["DOMAIN1"], self.key["estates"][0]["domain"])
        self.assertEqual(self.vars["NET1"], "127.31.0.0/24")

    def test_deterministic(self):
        out2 = os.path.join(self.tmp, "again")
        build.main(["gate-unit-1", "--out", out2, "--count", "1"])
        self.assertEqual(open(os.path.join(out2, "key.json")).read(), open(os.path.join(self.out, "key.json")).read())

    def test_up_py_handles_one_estate(self):
        # up.py's main() loop used to assume estates 1 and 2; it must not
        # need a second one to report per-estate counts.
        rc = up.main([self.out, "--vulhub", "/nonexistent", "--labdns", "/nonexistent", "--dry-run"])
        self.assertEqual(rc, 1)  # the vulhub checkout and its files are missing, not a crash

    def test_pool_seeds_are_single_estate_buildable(self):
        for seed in rangelib.load_pool():
            out = os.path.join(self.tmp, "pool-" + seed)
            build.main([seed, "--out", out, "--count", "1"])
            key = json.load(open(os.path.join(out, "key.json")))
            self.assertEqual(len(key["estates"]), 1)


class Up(unittest.TestCase):
    def test_up_marks_what_answers(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "o")
        build.main(["unit-1", "--out", out])
        plan = json.load(open(os.path.join(out, "plan.json")))
        key = json.load(open(os.path.join(out, "key.json")))
        victim = plan["envs"][3]
        calls, procs = [], []

        def run(cmd, cwd=None, env=None, timeout=0):
            calls.append((cmd, env))
            if cmd[:2] == ["docker", "compose"] and victim["project"] in cmd:
                return 1, "manifest unknown"
            return 0, ""

        class FakeProc:
            pass

        ctx = up.Ctx(out, "/vh", run=run, check=lambda p, a, r: (True, "ok"), sleep=lambda s: None,
                     popen=lambda cmd, **kw: procs.append(cmd) or FakeProc())
        ctx.clock = lambda: 0.0
        orig = up.dns_ready
        up.dns_ready = lambda c, d, apex: True
        self.addCleanup(setattr, up, "dns_ready", orig)
        result, dns_ok = up.run(ctx, plan, key, "/bin/labdns", "nobody", workers=1)
        self.assertFalse(result[victim["id"]]["up"])
        self.assertEqual(sum(1 for r in result.values() if r["up"]), len(plan["envs"]) - 1)
        downs = [h for est in key["estates"] for h in est["hosts"] if h.get("env") == victim["id"]]
        self.assertTrue(downs and all(h["up"] is False for h in downs))
        for est in key["estates"]:
            for h in est["hosts"]:
                if h.get("env") and h["env"] != victim["id"]:
                    self.assertTrue(h["up"])
        # each environment is started with TARGET_IP set to its own address
        ups = [(c, e) for c, e in calls if c[:2] == ["docker", "compose"] and "up" in c]
        self.assertTrue(all(e["TARGET_IP"] for _, e in ups))
        self.assertEqual(len(procs), 2)
        self.assertEqual(procs[0][:5], ["sudo", "-n", "-u", "nobody", "setsid"])
        self.assertTrue(any(c[0] == "docker" and c[1] == "run" and "--network" in c and "host" in c for c, _ in calls), "the proxy runs on the host network")


class NameServers(unittest.TestCase):
    d = {"estate": 1, "zone": "zone-1.json", "listen": "127.0.0.1:5301", "ns": ["127.31.0.20", "127.31.0.30"]}

    def test_the_resolver_listens_on_port_53_of_each_name_server(self):
        self.assertEqual(up.listen_addrs(self.d), ["127.0.0.1:5301", "127.31.0.20:53", "127.31.0.30:53"])
        self.assertEqual(up.listen_addrs({"listen": "127.0.0.1:5301"}), ["127.0.0.1:5301"])

    def test_start_dns_gives_every_address_to_one_process(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        with open(os.path.join(tmp, "zone-1.json"), "w") as f:
            f.write("{}")
        cmds = []

        class P:
            stdin = None

        ctx = up.Ctx(tmp, "/vh", popen=lambda cmd, **kw: cmds.append(cmd) or P())
        up.start_dns(ctx, self.d, "/bin/labdns", "nobody")
        self.assertEqual(len(cmds), 1)
        self.assertEqual(cmds[0][cmds[0].index("-addr") + 1], "127.0.0.1:5301,127.31.0.20:53,127.31.0.30:53")

    def serve(self, udp=True, tcp=True):
        """A resolver on one loopback port, answering every query; returns the port."""
        import struct
        socks = []
        port = None
        tcp_s = socket.socket()
        tcp_s.bind(("127.0.0.1", 0))
        port = tcp_s.getsockname()[1]
        tcp_s.listen(4)
        udp_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_s.bind(("127.0.0.1", port))

        def reply(q):
            return q[:2] + b"\x84\x00" + q[4:]

        def serve_udp():
            while True:
                try:
                    q, a = udp_s.recvfrom(512)
                except OSError:
                    return
                if udp:
                    udp_s.sendto(reply(q), a)

        def serve_tcp():
            while True:
                try:
                    c, _ = tcp_s.accept()
                except OSError:
                    return
                if tcp:
                    n = struct.unpack(">H", c.recv(2))[0]
                    r = reply(c.recv(n))
                    c.sendall(struct.pack(">H", len(r)) + r)
                c.close()

        for fn in (serve_udp, serve_tcp):
            threading.Thread(target=fn, daemon=True).start()
        self.addCleanup(tcp_s.close)
        self.addCleanup(udp_s.close)
        return port

    def test_ready_needs_udp_and_tcp_on_every_address(self):
        ctx = up.Ctx(tempfile.mkdtemp(), "/vh", sleep=lambda s: None)
        self.addCleanup(shutil.rmtree, ctx.out, True)
        good, no_tcp = self.serve(), self.serve(tcp=False)
        d = {"listen": "127.0.0.1:%d" % good}
        self.assertTrue(up.dns_ready(ctx, d, "one.test."))
        self.assertFalse(up.dns_ready(ctx, {"listen": "127.0.0.1:%d" % no_tcp}, "one.test."))
        orig = up.listen_addrs
        up.listen_addrs = lambda d: ["127.0.0.1:%d" % good, "127.0.0.1:%d" % no_tcp]
        self.addCleanup(setattr, up, "listen_addrs", orig)
        self.assertFalse(up.dns_ready(ctx, d, "one.test."), "one dead address fails the estate")


class UpDryRun(unittest.TestCase):
    def test_dry_run_checks_the_files(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        out = os.path.join(tmp, "o")
        build.main(["unit-1", "--out", out])
        vh = os.path.join(tmp, "vh")
        for e in json.load(open(os.path.join(out, "plan.json")))["envs"]:
            os.makedirs(os.path.join(vh, e["path"]))
            open(os.path.join(vh, e["path"], "docker-compose.yml"), "w").close()
        self.assertEqual(up.main([out, "--vulhub", vh, "--labdns", "x", "--dry-run"]), 0)
        os.remove(os.path.join(out, "zone-2.json"))
        self.assertEqual(up.main([out, "--vulhub", vh, "--labdns", "x", "--dry-run"]), 1)


class Brief(unittest.TestCase):
    def test_fills_every_placeholder(self):
        v = {"DOMAIN1": "a.test", "NET1": "127.31.0.0/24", "DNS1": "127.0.0.1:5301", "DOMAIN2": "b.test", "NET2": "127.47.0.0/24", "DNS2": "127.0.0.1:5302"}
        d = os.path.join(HERE, "..", "trial")
        r = render_brief.render("research", "v0.10.1", v, d)
        self.assertIn("v0.10.1", r)
        self.assertIn("a.test", r)
        where = "azhaq v0.10.1 is installed at ./bin/azhaq"
        self.assertRegex(r, r"Phase 1, client 1.*" + where + r".*Do not run it in phase 1")
        self.assertRegex(r, r"Phase 2, client 2.*" + where + r".*Use it as your main tool")
        h = render_brief.render("hunter", "v0.10.1", v, d)
        self.assertRegex(h, r"Session 1, program 1.*" + where + r".*Use it as your main tool")
        self.assertRegex(h, r"Session 2, program 2.*azhaq must not be used")
        for text in (r, h):
            self.assertNotIn("install azhaq from", text)
            self.assertIn("do not reinstall it", text)
        with self.assertRaises(ValueError):
            render_brief.render("hunter", "v", {}, d)
        with self.assertRaises(ValueError):
            render_brief.render("switch", "v", v, d)


class Workflow(unittest.TestCase):
    """The shape of trial.yml: every kind is isolated and has a heartbeat; no review is told it has docker or sudo."""

    @classmethod
    def setUpClass(cls):
        text = open(os.path.join(HERE, "..", "..", "workflows", "trial.yml")).read()
        cls.codex = text.split("\n  codex:\n")[1].split("\n  work:\n")[0]
        cls.steps = {}
        for job, body in (("codex", cls.codex), ("work", text.split("\n  work:\n")[1])):
            cls.steps[job] = [a or b for a, b in re.findall(r"^      - (?:name: (.+)|uses: (.+))$", body, re.M)]

    def test_both_jobs_heartbeat_and_isolate_before_the_review(self):
        for job, steps in self.steps.items():
            order = [steps.index(x) for x in ("heartbeat", "isolate", "remove the source", "review")]
            self.assertEqual(order, sorted(order), job)

    def test_the_switch_job_readies_the_labs_and_the_tools_first(self):
        steps = self.steps["codex"]
        self.assertLess(steps.index("packages"), steps.index("labs"))
        self.assertLess(steps.index("labs"), steps.index("lab source"))
        self.assertLess(steps.index("lab source"), steps.index("isolate"))
        codex = self.codex
        self.assertRegex(codex.split("- name: packages")[1].split("- name: labs")[0], r"\bnmap\b")
        self.assertIn("stream.ts.jsonl", codex.split("- name: heartbeat")[1].split("- name: isolate")[0])
        self.assertIn("lab_ready.py", open(os.path.join(HERE, "..", "labs.sh")).read())

    def test_the_switch_brief_offers_no_docker_or_sudo(self):
        brief = open(os.path.join(HERE, "..", "trial", "BRIEF.md")).read()
        self.assertNotIn("docker restart", brief)
        self.assertNotIn("docker cp", brief)
        self.assertNotIn("apt-get", brief)
        self.assertIn("./lab-source", brief)


class Isolate(unittest.TestCase):
    def test_dry_run_lists_each_step(self):
        r = subprocess.run(["bash", os.path.join(HERE, "isolate.sh"), "runner"], capture_output=True, text=True, env=dict(os.environ, ISOLATE_DRY_RUN="1"))
        self.assertEqual(r.returncode, 0, r.stderr)
        for want in ("hidepid=2 /proc", "chown root:root /var/run/docker.sock", "chmod 600 /var/run/docker.sock", "gpasswd -d runner docker",
                     "gpasswd -d runner sudo", "check: sudo is gone", "check: docker is unusable", "processes of other users are hidden"):
            self.assertIn(want, r.stdout)

    def test_syntax(self):
        self.assertEqual(subprocess.run(["bash", "-n", os.path.join(HERE, "isolate.sh")]).returncode, 0)


def mkkey():
    def host(name, addr, cat, product, cves, ports, **kw):
        h = {"kind": "service", "host": name, "address": addr, "vhost": False, "dns_visible": True, "env": name.split(".")[0], "product": product,
             "version": "1", "cve": cves, "category": cat, "summary": "s", "vulnerable": True,
             "ports": [{"port": p, "protocol": pr, "primary": i == 0} for i, (p, pr) in enumerate(ports)]}
        h.update(kw)
        return h
    est1 = {"index": 1, "domain": "one.test", "net": "127.31.0.0/24", "dns": "127.0.0.1:5301", "wildcard": None, "hosts": [
        host("ci.one.test", "127.31.0.10", "ci-cd", "Jenkins", ["CVE-2018-1000861"], [(8080, "http"), (50000, "jenkins-agent")]),
        host("grafana.one.test", "127.31.0.99", "monitoring", "Grafana", ["CVE-2021-43798"], [(80, "http")], vhost=True),
        host("db.one.test", "127.31.0.11", "datastore", "Redis", [], [(6379, "redis")]),
        host("gone.one.test", "127.31.0.12", "cms", "WordPress", ["CVE-2026-1"], [(8081, "http")], up=False),
        {"kind": "dangling-cname", "host": "assets.one.test", "target": "abc-one.azurewebsites.net.", "category": "dns", "vulnerable": True, "ports": [], "summary": "x"},
        {"kind": "infra", "host": "www.one.test", "address": "127.31.0.99", "product": "nginx", "cve": [], "category": "infra", "vulnerable": False,
         "ports": [{"port": 80, "protocol": "http", "primary": True}]}]}
    est2 = {"index": 2, "domain": "two.test", "net": "127.47.0.0/24", "dns": "127.0.0.1:5302", "wildcard": None, "hosts": [
        host("wiki.two.test", "127.47.0.20", "cms", "Tiki Wiki CMS Groupware", ["CVE-2020-15906"], [(8080, "http")])]}
    return {"seed": "s", "vulhub_commit": "c" * 40, "estates": [est1, est2]}


def event(ts, kind, iid, cmd):
    return "%d %s" % (ts, json.dumps({"type": kind, "item": {"id": iid, "type": "command_execution", "command": cmd}}))


class Grade(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)
        os.makedirs(os.path.join(self.d, "notes"))

    def write(self, name, text):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(text)

    def test_grades_a_run(self):
        t0 = 1_800_000_000
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))  # noqa: E731
        self.write("phases.log", "phase 1 start %s\nphase 1 end %s\nphase 2 start %s\nphase 2 end %s\n" % (iso(t0), iso(t0 + 5400), iso(t0 + 5500), iso(t0 + 10900)))
        lead1 = {"phase": 1, "time": iso(t0 + 700), "kind": "vulnerable-software", "severity": "critical", "host": "ci.one.test", "port": 8080,
                 "product": "Jenkins 2.138", "cve": "CVE-2018-1000861", "title": "Jenkins Stapler RCE", "evidence": "version header 2.138"}
        lead2 = {"phase": 1, "time": iso(t0 + 900), "host": "127.31.0.99", "port": 80, "product": "Grafana 8.2.6", "title": "Grafana path traversal",
                 "url": "http://grafana.one.test/public/plugins/x"}
        lead3 = {"phase": 1, "host": "127.31.0.11", "port": 6379, "title": "open service", "evidence": "PING answered"}   # place only
        lead4 = {"phase": 1, "host": "10.9.9.9", "port": 22, "title": "unrelated", "product": "OpenSSH"}                  # matches nothing
        lead5 = {"phase": 1, "host": "ci.one.test", "port": 8080, "product": "Jenkins", "title": "Jenkins again", "evidence": "dup"}
        lead6 = {"phase": 1, "kind": "takeover", "host": "assets.one.test", "title": "Dangling CNAME takeover on assets", "evidence": "NXDOMAIN target"}
        lead7 = {"phase": 2, "time": iso(t0 + 5500 + 100), "host": "wiki.two.test", "url": "http://wiki.two.test:8080/", "product": "Tiki Wiki 21.1", "title": "Tiki auth bypass", "cve": "CVE-2020-15906"}
        self.write("leads.jsonl", "\n".join(json.dumps(l) for l in [lead1, lead2, lead3, lead4, lead5, lead6, lead7]) + "\nnot json\n")
        self.write("surface-1.txt", "ci.one.test 127.31.0.10 8080/tcp http Jenkins\n127.31.0.10 50000 tcp\ngrafana.one.test 80 http\n127.31.0.11 6379 redis\nwww.one.test 127.31.0.99 80 nginx\n")
        self.write("surface-2.txt", "# nothing but one name\nwiki.two.test\n")
        self.write("notes/fallbacks.md", "- nmap: azhaq has no -sV here\n")
        ev = [
            event(t0 + 1, "item.started", "a", "bash -lc 'echo \"phase 1 start $(date -u +%FT%TZ)\" >> phases.log'"),
            event(t0 + 2, "item.completed", "a", "bash -lc 'echo \"phase 1 start $(date -u +%FT%TZ)\" >> phases.log'"),
            event(t0 + 30, "item.started", "b", "nmap -sV 127.31.0.0/24"),
            event(t0 + 600, "item.started", "c", "docker ps"),
            event(t0 + 610, "item.started", "c2", "ls /proc/net"),
            event(t0 + 650, "item.started", "d", "bash -lc \"echo '" + json.dumps(lead1) + "' >> leads.jsonl\""),
            event(t0 + 651, "item.completed", "d", "bash -lc \"echo '" + json.dumps(lead1) + "' >> leads.jsonl\""),
            event(t0 + 1300, "item.started", "e", "bash -lc \"echo '" + json.dumps(lead2) + "' >> leads.jsonl\""),
            event(t0 + 5499, "item.started", "f", "bash -lc 'echo \"phase 2 start $(date -u +%FT%TZ)\" >> phases.log'"),
            event(t0 + 5600, "item.started", "g", "./bin/azhaq map http://wiki.two.test:8080/"),
            event(t0 + 5700, "item.started", "h", "bash -lc \"echo '" + json.dumps(lead7) + "' >> leads.jsonl\""),
        ]
        with gzip.open(os.path.join(self.d, "stream.ts.jsonl.gz"), "wt") as f:
            f.write("\n".join(ev) + "\n")
        rep = grade.grade(mkkey(), self.d)
        p1, p2 = rep["phases"]
        # surface: gone.one.test is not up and is left out; the vhost needs its name
        self.assertEqual(p1["excluded_not_up"], ["gone.one.test"])
        self.assertEqual(p1["surface"]["hosts"], [4, 4])
        self.assertEqual(p1["surface"]["ports"], [5, 5])
        self.assertEqual(p1["surface"]["services"], [4, 5])  # 50000 is listed as "tcp" only
        self.assertEqual(p2["surface"]["hosts"], [1, 1])
        self.assertEqual(p2["surface"]["ports"], [0, 1])
        # vulnerabilities: Jenkins by CVE, Grafana by product (found through the proxy address and the URL host), the takeover; Redis only by place
        self.assertEqual(p1["vulns"]["identified"], 3)
        self.assertEqual(p1["vulns"]["strong"], 2)
        self.assertEqual(p1["vulns"]["of"], 4)
        self.assertEqual(p1["vulns"]["missed"], ["db.one.test"])
        self.assertEqual(len(p1["leads"]["place_only"]), 1)
        self.assertEqual(p1["leads"]["place_only"][0]["key_host"], "db.one.test")
        self.assertEqual(p1["leads"]["duplicates"], 1)
        titles = [u["title"] for u in p1["leads"]["unmatched"]]
        self.assertIn("unrelated", titles)
        self.assertEqual(len(rep["unreadable_lead_lines"]), 1)
        # time comes from the stream: the command at +650 s, not the lead's own +700 s
        found = {v["key_host"]: v for v in p1["vulns"]["found"]}
        self.assertEqual(found["ci.one.test"]["seconds"], 649)
        self.assertEqual(found["ci.one.test"]["time_from"], "stream")
        self.assertEqual(p1["time"]["first_match_s"], 649)
        self.assertEqual(p1["time"]["start_from"], "stream")
        self.assertEqual(p2["vulns"]["identified"], 1)
        self.assertEqual(p2["time"]["first_match_s"], 5700 - 5499)
        # commands are counted inside each phase
        self.assertEqual(p1["commands"]["total"], 6)
        self.assertEqual(p2["commands"]["by_tool"].get("azhaq"), 1)
        kinds = sorted({p["kind"] for p in rep["machine_probes"]})
        self.assertEqual(kinds, ["docker", "processes", "sockets"])  # docker ps; ls /proc/net
        self.assertEqual(rep["fallbacks_noted"], 1)
        md = grade.markdown(rep)
        self.assertIn("| Vulnerabilities identified | 3 of 4 (2 by CVE) |", md)
        self.assertIn("docker ps", md)
        self.assertIn("Leads for a person to judge", md)

    def test_the_lead_time_is_the_fallback(self):
        t0 = 1_800_000_000
        self.write("phases.log", "phase 1 start %s\n" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)))
        self.write("leads.jsonl", json.dumps({"phase": 1, "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0 + 120)), "host": "wiki.two.test", "port": 8080,
                                              "product": "Tiki Wiki", "title": "t"}) + "\n")
        key = mkkey()
        key["estates"][0], key["estates"][1] = key["estates"][1], key["estates"][0]
        key["estates"][0]["index"], key["estates"][1]["index"] = 1, 2
        rep = grade.grade(key, self.d)
        v = rep["phases"][0]["vulns"]["found"][0]
        self.assertEqual((v["seconds"], v["time_from"]), (120, "lead"))
        self.assertIsNone(rep["stream"])

    def test_empty_run_does_not_crash(self):
        rep = grade.grade(mkkey(), self.d)
        self.assertEqual(rep["phases"][0]["vulns"]["identified"], 0)
        self.assertIn("none found", grade.markdown(rep))

    def test_numbers_ignore_addresses_names_and_versions(self):
        self.assertEqual(grade.numbers_in("ci-03.x.test 127.31.0.10:8080/tcp Jenkins 2.138 qa-5 dev-03 udp/53"), {8080, 53})

    def test_cli_writes_json_and_markdown(self):
        key = os.path.join(self.d, "key.json")
        json.dump(mkkey(), open(key, "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "grade.py"), key, self.d, "--md", os.path.join(self.d, "g.md")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.d, "grade.json")))
        self.assertIn("Workflow trial grade", open(os.path.join(self.d, "g.md")).read())

    def test_baseline_comparison_reads_a_same_seed_run_beside_this_one(self):
        # azhaq's run: one estate (index 1), one vulnerability found fast.
        key = mkkey()
        key["estates"] = [key["estates"][0]]
        key["seed"] = "gate-alpha"
        self.write("phases.log", "phase 1 start 2026-01-01T00:00:00Z\n")
        self.write("leads.jsonl", json.dumps({"phase": 1, "time": "2026-01-01T00:01:00Z", "host": "ci.one.test", "port": 8080,
                                              "product": "Jenkins", "cve": "CVE-2018-1000861", "title": "t"}) + "\n")
        ours = grade.grade(key, self.d)

        baseline_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, baseline_dir, True)
        os.makedirs(os.path.join(baseline_dir, "notes"))
        with open(os.path.join(baseline_dir, "phases.log"), "w") as f:
            f.write("phase 1 start 2026-01-01T00:00:00Z\n")
        with open(os.path.join(baseline_dir, "leads.jsonl"), "w") as f:
            f.write(json.dumps({"phase": 1, "time": "2026-01-01T00:05:00Z", "host": "ci.one.test", "port": 8080,
                                "product": "Jenkins", "cve": "CVE-2018-1000861", "title": "t"}) + "\n")
        theirs = grade.grade(key, baseline_dir)
        with open(os.path.join(baseline_dir, "grade.json"), "w") as f:
            json.dump(theirs, f)

        cmp_ = grade.compare_baseline(ours, grade.load_baseline(baseline_dir))
        self.assertEqual(len(cmp_), 1)
        c = cmp_[0]
        self.assertTrue(c["same_seed"])
        self.assertEqual(c["vulns_identified"], [1, 1])
        self.assertEqual(c["first_match_s"], [60, 300])  # ours found it faster
        md = "\n".join(grade.markdown_baseline(cmp_))
        self.assertIn("Compared with the estate's baseline", md)
        self.assertIn("yes", md)

    def test_baseline_comparison_flags_a_different_seed(self):
        key = mkkey()
        other = mkkey()
        other["seed"] = "not-the-same-seed"
        rep = {"seed": key["seed"], "phases": [{"phase": 1, "vulns": {"identified": 0, "of": 3}, "leads": {"total": 0}, "time": {"first_match_s": None}, "commands": {"total": 0}}]}
        baseline = {"seed": other["seed"], "phases": [{"phase": 1, "vulns": {"identified": 0, "of": 3}, "leads": {"total": 0}, "time": {"first_match_s": None}, "commands": {"total": 0}}]}
        cmp_ = grade.compare_baseline(rep, baseline)
        self.assertFalse(cmp_[0]["same_seed"])
        self.assertIn("not a fair comparison", "\n".join(grade.markdown_baseline(cmp_)))

    def test_cli_with_baseline_flag(self):
        key = os.path.join(self.d, "key.json")
        one = mkkey()
        one["estates"] = [one["estates"][0]]
        json.dump(one, open(key, "w"))
        baseline_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, baseline_dir, True)
        json.dump({"seed": one["seed"], "phases": [{"phase": 1, "vulns": {"identified": 0, "of": 4}, "leads": {"total": 0}, "time": {"first_match_s": None}, "commands": {"total": 0}}]},
                  open(os.path.join(baseline_dir, "grade.json"), "w"))
        r = subprocess.run([sys.executable, os.path.join(HERE, "grade.py"), key, self.d, "--baseline", baseline_dir], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.load(open(os.path.join(self.d, "grade.json")))
        self.assertIn("baseline_comparison", rep)
        self.assertIn("Compared with the estate's baseline", r.stdout)


GATE_A_REPORT = """# Report

7. Scorecard

| Item | Score | Reasoning |
|---|---|---|
| findings against the key and the baseline | 9 | matched all |
| time to the first finding | 8 | a bit slow |
| signal versus noise | 9 | clean |
| trust | 9 | held up |
| would use on the next engagement | 9 | yes |
| overall (this part) | 9 | good |
"""

GATE_B_REPORT = """# Report

2. Scorecard

| Item | Score | Reasoning |
|---|---|---|
| install and first run | 9 | smooth |
| docs | 8 | mostly clear |
| subdomain recon | 9 | great |
| host and port discovery | 9 | great |
| web and api mapping | 9 | great |
| signed-in and multi-role testing | 9 | great |
| output and integration (including assistants) | 9 | great |
| reliability (crashes, hangs, wrong data, silent failures) | 9 | great |
| performance (time, memory and cpu, and the requests it sends to the target for the same result) | 8 | slower than ffuf |
| overall (this part) | 9 | great |
| extra thing nobody asked for | 7 | for a human |
"""


class MergeGate(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def write_pair(self, a="a", b="b", a_text=GATE_A_REPORT, b_text=GATE_B_REPORT):
        os.makedirs(os.path.join(self.d, a), exist_ok=True)
        os.makedirs(os.path.join(self.d, b), exist_ok=True)
        with open(os.path.join(self.d, a, "REPORT.md"), "w") as f:
            f.write(a_text)
        with open(os.path.join(self.d, b, "REPORT.md"), "w") as f:
            f.write(b_text)

    def test_parses_and_matches_both_scorecards(self):
        rows, _ = merge_gate.parse_scorecard(GATE_A_REPORT)
        self.assertEqual(rows["trust"], (9, "held up"))
        matched, leftover = merge_gate.match_items(rows, merge_gate.PART_A_ITEMS)
        self.assertEqual([m[0] for m in matched], merge_gate.PART_A_ITEMS)
        self.assertTrue(all(score is not None for _, score, _ in matched))
        self.assertEqual(leftover, [])  # "overall (this part)" is not a leftover

    def test_anchor_for_every_bucket(self):
        self.assertIn("second look", merge_gate.anchor_for(10))
        self.assertIn("at least as good", merge_gate.anchor_for(9))
        self.assertIn("gaps you can name", merge_gate.anchor_for(8))
        self.assertIn("keep your usual tools", merge_gate.anchor_for(6))
        self.assertIn("costs you more", merge_gate.anchor_for(4))
        self.assertIn("fails or misleads", merge_gate.anchor_for(1))

    def test_merges_one_pair_and_computes_overall_as_the_lowest_score(self):
        self.write_pair()
        text, overall = merge_gate.one_pair(os.path.join(self.d, "a"), os.path.join(self.d, "b"))
        self.assertEqual(overall, 8)  # "docs", "performance" and "time to the first finding" are 8
        self.assertIn("| install and first run | 9 |", text)
        self.assertIn("| **overall** | **8** |", text)
        self.assertIn("extra thing nobody asked for", text)  # unmatched row, listed for a person

    def test_missing_report_is_reported_not_crashed(self):
        os.makedirs(os.path.join(self.d, "a"))
        os.makedirs(os.path.join(self.d, "b"))
        text, overall = merge_gate.one_pair(os.path.join(self.d, "a"), os.path.join(self.d, "b"))
        self.assertIsNone(overall)
        self.assertIn("No REPORT.md for part A.", text)
        self.assertIn("No REPORT.md for part B.", text)

    def test_find_pairs_prefers_samples_over_flat(self):
        os.makedirs(os.path.join(self.d, "a1"))
        os.makedirs(os.path.join(self.d, "b1"))
        os.makedirs(os.path.join(self.d, "a2"))
        os.makedirs(os.path.join(self.d, "b2"))
        pairs = merge_gate.find_pairs(self.d)
        self.assertEqual([p[2] for p in pairs], ["sample 1", "sample 2"])

    def test_find_pairs_falls_back_to_flat(self):
        os.makedirs(os.path.join(self.d, "a"))
        os.makedirs(os.path.join(self.d, "b"))
        pairs = merge_gate.find_pairs(self.d)
        self.assertEqual(len(pairs), 1)
        self.assertTrue(pairs[0][0].endswith(os.sep + "a"))

    def test_cli_verdict_pass(self):
        self.write_pair()
        r = subprocess.run([sys.executable, os.path.join(HERE, "merge_gate.py"), self.d], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("not a pass", r.stdout)  # two rows are 8, below 9

    def test_cli_verdict_pass_when_every_score_is_nine_or_more(self):
        nines_a = GATE_A_REPORT.replace("| 8 |", "| 9 |")
        nines_b = GATE_B_REPORT.replace("| 8 |", "| 9 |")
        self.write_pair(a_text=nines_a, b_text=nines_b)
        out = os.path.join(self.d, "out.md")
        r = subprocess.run([sys.executable, os.path.join(HERE, "merge_gate.py"), self.d, "--out", out], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        text = open(out).read()
        self.assertIn("PASS: every sample scored every item at 9 or more", text)

    def test_baseline_summary_is_embedded_when_graded(self):
        self.write_pair()
        with open(os.path.join(self.d, "a", "grade.json"), "w") as f:
            json.dump({"baseline_comparison": [{"phase": 1, "same_seed": True, "vulns_identified": [4, 3], "vulns_of": [5, 5],
                                                "leads_total": [6, 5], "first_match_s": [120, 300], "commands_total": [40, 30]}]}, f)
        text, _ = merge_gate.one_pair(os.path.join(self.d, "a"), os.path.join(self.d, "b"))
        self.assertIn("Part A's grade beside its baseline", text)
        self.assertIn("4 vs 3", text)


if __name__ == "__main__":
    unittest.main()


class FenceTest(unittest.TestCase):
    def test_only_the_hosts_ports_answer(self):
        import up
        key = {"estates": [{"net": "127.31.0.0/24", "hosts": [
            {"address": "127.31.0.5", "ports": [{"port": 8080}, {"port": 161, "transport": "udp"}]},
            {"kind": "dangling-cname"}]}]}
        plan = {"envs": [{"address": "127.200.0.10", "backend": True}, {"address": "127.31.0.5"}]}
        rules = [" ".join(r) for r in up.fence_rules(key, plan)]
        self.assertIn("-A AZQ -d 127.31.0.5 -p tcp --dport 8080 -j ACCEPT", rules)
        self.assertIn("-A AZQ -d 127.31.0.5 -p udp --dport 161 -j ACCEPT", rules)
        self.assertIn("-A AZQ -d 127.31.0.0/24 -p tcp -j REJECT --reject-with tcp-reset", rules)
        self.assertTrue(any("127.200.0.0/24 -m owner --uid-owner runner" in r for r in rules))
        self.assertLess(rules.index("-A AZQ -d 127.31.0.5 -p tcp --dport 8080 -j ACCEPT"),
                        rules.index("-A AZQ -d 127.31.0.0/24 -p tcp -j REJECT --reject-with tcp-reset"))
        self.assertEqual(rules[-1], "-I OUTPUT 1 -j AZQ")

    def test_the_name_servers_answer_on_53(self):
        import up
        key = {"estates": [{"net": "127.31.0.0/24", "ns": [{"host": "ns1.a.test", "address": "127.31.0.20"}, {"host": "ns2.a.test", "address": "127.31.0.30"}],
                            "hosts": [{"address": "127.31.0.5", "ports": [{"port": 8080}]}]}]}
        rules = [" ".join(r) for r in up.fence_rules(key, {"envs": []})]
        reject = rules.index("-A AZQ -d 127.31.0.0/24 -p tcp -j REJECT --reject-with tcp-reset")
        for a in ("127.31.0.20", "127.31.0.30"):
            for proto in ("tcp", "udp"):
                r = "-A AZQ -d %s -p %s --dport 53 -j ACCEPT" % (a, proto)
                self.assertIn(r, rules)
                self.assertLess(rules.index(r), reject)
            self.assertIn("-A AZQ -d %s -p icmp -j ACCEPT" % a, rules)
            self.assertNotIn("-A AZQ -d %s -p tcp --dport 80 -j ACCEPT" % a, rules)
