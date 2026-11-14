import contextlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import authzlib as z  # noqa: E402
import autorize  # noqa: E402
import brief  # noqa: E402
import gen  # noqa: E402
import grade  # noqa: E402
import journey  # noqa: E402
import selfcheck  # noqa: E402
import server  # noqa: E402
import summary  # noqa: E402


@contextlib.contextmanager
def live(seed):
    """gen + a server on a free port for SEED: yields (dir, url)."""
    with tempfile.TemporaryDirectory() as d:
        gen.main([str(seed), "--out", d])
        app = server.App(json.load(open(os.path.join(d, "app.json"))))
        srv = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(app))
        srv.daemon_threads = True
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            yield d, "http://127.0.0.1:%d" % srv.server_address[1]
        finally:
            srv.shutdown()
            srv.server_close()


class GenTest(unittest.TestCase):
    def test_deterministic(self):
        a = gen.build("s1")
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(gen.build("s1"), sort_keys=True))
        self.assertNotEqual(json.dumps(a[1], sort_keys=True), json.dumps(gen.build("s2")[1], sort_keys=True))

    def test_counts_and_visibility(self):
        for s in range(60):
            _, key, _ = gen.build(s)
            fl = [r for r in key["routes"] if r["class"] in gen.FLAWS]
            neg = [r for r in key["routes"] if r["class"] == "negative"]
            self.assertTrue(6 <= len(fl) <= 9, s)
            self.assertTrue(5 <= len(neg) <= 8, s)
            vis = {r["visibility"] for r in fl}
            self.assertEqual(vis, {"journey", "js-only", "unlinked"}, s)

    def test_key_covers_every_route(self):
        for s in range(40):
            app, key, _ = gen.build(s)
            m = z.Matcher(key["routes"])
            for rt in app["routes"]:
                sample = rt["path"].replace("{org}", "ZZorg").replace("{id}", "ZZid")
                hit = m.find(rt["method"], sample)
                self.assertIsNotNone(hit, (s, rt["path"]))
                self.assertEqual((hit["method"], hit["template"]), (rt["method"], rt["path"]), s)
            keyed = {(r["method"], r["template"]) for r in key["routes"]}
            self.assertEqual(len(keyed), len(key["routes"]))
            self.assertTrue({(r["method"], r["path"]) for r in app["routes"]} <= keyed)
            # the front page, the sign-in page, the bundle and the spec are keyed too
            for p in ("/", "/login", app["static"]["bundle"], app["static"]["openapi"]):
                self.assertTrue(("GET", p) in keyed)

    def test_every_served_route_is_in_the_key(self):
        # what the server answers (not 404 no-route, not 405) is a route of the key
        with live(3) as (d, url):
            key = json.load(open(os.path.join(d, "key.json")))
            m = z.Matcher(key["routes"])
            for r in key["routes"]:
                p = r["template"].replace("{org}", "ZZorg").replace("{id}", "ZZid")
                resp = z.call(r["method"], url + p, body="{}" if r["method"] in ("POST", "PUT", "PATCH") else None)
                self.assertNotEqual(resp["status"], 405, r["template"])
                self.assertIsNotNone(m.find(r["method"], p))

    def test_bundle_and_spec_hold_the_right_routes(self):
        for s in range(20):
            app, key, _ = gen.build(s)
            by_t = {(r["method"], r["template"]): r for r in key["routes"]}
            paths = [r["path"] for r in app["routes"]]
            for r in app["routes"]:
                k = by_t[(r["method"], r["path"])]
                spec = app["openapi"]["paths"].get(r["path"], {}).get(r["method"].lower())
                if k["visibility"] == "unlinked":
                    self.assertIsNotNone(spec, (s, r["path"]))
                    if "{" not in r["path"] and paths.count(r["path"]) == 1:
                        self.assertNotIn('"%s"' % r["path"], app["bundle"], (s, r["path"]))
                elif k["visibility"] == "js-only":
                    if "{" not in r["path"] and paths.count(r["path"]) == 1:
                        self.assertIn('"%s"' % r["path"], app["bundle"], (s, r["path"]))


class SelfcheckTest(unittest.TestCase):
    def test_passes_on_several_seeds(self):
        for s in (1, 2, 3, 4, 5, 6, 7, 8):
            with live(s) as (d, url):
                self.assertEqual(selfcheck.main(["selfcheck.py", d, url]), 0, s)

    def test_fails_when_a_flaw_is_missing(self):
        with live(3) as (d, url):
            key = json.load(open(os.path.join(d, "key.json")))
            bad = next(r for r in key["routes"] if r["class"] == "bola-read" or r["class"] == "bfla" or r["class"] == "data-exposure")
            bad["proof"][-1]["expect"]["contains"] = "no-such-marker-zz"
            json.dump(key, open(os.path.join(d, "key.json"), "w"))
            self.assertEqual(selfcheck.main(["selfcheck.py", d, url]), 1)


class JourneyTest(unittest.TestCase):
    def test_capture_is_journey_routes_only(self):
        with live(9) as (d, url):
            with tempfile.TemporaryDirectory() as out:
                journey.main([d, url, "--out", out])
                key = json.load(open(os.path.join(d, "key.json")))
                app = json.load(open(os.path.join(d, "app.json")))
                m = z.Matcher(key["routes"])
                sessions = json.load(open(os.path.join(out, "sessions.json")))
                self.assertEqual(set(sessions), {"alice", "bob", "admin"})
                n = 0
                for who in ("admin", "alice"):
                    for e in z.read_har(os.path.join(out, who + ".har")):
                        n += 1
                        r = m.find(e["request"]["method"], e["request"]["url"])
                        self.assertEqual(r["visibility"], "journey", e["request"]["url"])
                        self.assertNotEqual(r["template"], app["auth"]["login"])
                        names = {h["name"] for h in e["request"]["headers"]}
                        self.assertTrue(z.parse_header(sessions[who])[0] in names)
                self.assertGreater(n, 10)

    def test_journey_is_repeatable(self):
        with live(4) as (d, url):
            pass
        outs = []
        for _ in range(2):
            with live(4) as (d, url):
                with tempfile.TemporaryDirectory() as out:
                    journey.main([d, url, "--out", out])
                    outs.append((open(os.path.join(out, "sessions.json")).read(),
                                 [(e["request"]["method"], e["request"]["url"].split("/", 3)[3], e["response"]["status"])
                                  for e in z.read_har(os.path.join(out, "alice.har"))]))
        self.assertEqual(outs[0], outs[1])


class AutorizeTest(unittest.TestCase):
    def test_check_bypass(self):
        ok, e403 = "HTTP/1.1 200 OK", "HTTP/1.1 403 Forbidden"
        self.assertEqual(autorize.check_bypass(ok, e403, "a", "b"), autorize.ENFORCED)
        self.assertEqual(autorize.check_bypass(ok, ok, "same", "same"), autorize.BYPASSED)
        self.assertEqual(autorize.check_bypass(ok, ok, "a", "b"), autorize.IS_ENFORCED)
        self.assertEqual(autorize.check_bypass(ok, ok, "a", '{"error":"access denied"}'), autorize.ENFORCED)
        self.assertEqual(autorize.check_bypass(ok, ok, "a", '{"error":"no such record for you"}'), autorize.IS_ENFORCED)
        # a detector hit beats equal bodies
        self.assertEqual(autorize.check_bypass(ok, ok, "login", "login"), autorize.ENFORCED)

    def test_static_filter_and_headers(self):
        self.assertTrue(autorize.STATIC.search("http://h/static/app.js"))
        self.assertTrue(autorize.STATIC.search("http://h/a/logo.png?x=1"))
        self.assertFalse(autorize.STATIC.search("http://h/api/jsonata"))
        rec = [{"name": "Authorization", "value": "Bearer a"}, {"name": "Accept", "value": "*/*"}, {"name": "Host", "value": "h"}]
        hs = autorize.make_headers(rec, ["authorization"], "Authorization: Bearer b")
        self.assertEqual(hs, [("Accept", "*/*"), ("Authorization", "Bearer b")])
        self.assertEqual(autorize.make_headers(rec, ["Authorization"]), [("Accept", "*/*")])

    def test_run_finds_something_and_counts(self):
        with live(5) as (d, url):
            with tempfile.TemporaryDirectory() as out:
                journey.main([d, url, "--out", out])
        with live(5) as (d, url):
            with tempfile.TemporaryDirectory() as out:
                journey.main([d, url, "--out", out])
            # a second journey above moved nothing: this is a fresh app again
        with live(5) as (d, url):
            with tempfile.TemporaryDirectory() as out:
                with live(5) as (d2, url2):
                    journey.main([d2, url2, "--out", out])
                sessions = z.load_sessions(os.path.join(out, "sessions.json"))
                meta = {}
                rows = autorize.run(url, sessions, [(os.path.join(out, "admin.har"), "alice"),
                                                    (os.path.join(out, "alice.har"), "bob")], meta)
                self.assertTrue(rows)
                self.assertEqual({r["variant"] for r in rows}, {"user", "unauth"})
                self.assertGreater(meta["requests"], len(rows))
                self.assertIn(autorize.ENFORCED, {r["verdict"] for r in rows})


KEY = {"routes": [
    {"id": "r1", "method": "GET", "template": "/api/a/{id}", "class": "bola-read", "visibility": "journey"},
    {"id": "r2", "method": "PATCH", "template": "/api/a/{id}", "class": "bola-write", "visibility": "js-only"},
    {"id": "r3", "method": "GET", "template": "/api/a/export", "class": "bfla", "visibility": "unlinked"},
    {"id": "r4", "method": "GET", "template": "/api/b/{id}", "class": "negative", "trap": "twin-read", "visibility": "journey"},
    {"id": "r5", "method": "GET", "template": "/api/a", "class": "plain", "visibility": "journey"},
    {"id": "r6", "method": "GET", "template": "/api/c/{id}/notes", "class": "nested-bola", "visibility": "journey"},
]}


def write(d, name, lines):
    with open(os.path.join(d, name), "w") as f:
        for ln in lines:
            f.write((ln if isinstance(ln, str) else json.dumps(ln)) + "\n")


class GradeTest(unittest.TestCase):
    def run_grade(self, arm, files, meta=None):
        with tempfile.TemporaryDirectory() as d:
            for name, lines in files.items():
                write(d, name, lines)
            json.dump(meta or {}, open(os.path.join(d, "meta.json"), "w"))
            json.dump(KEY, open(os.path.join(d, "key.json"), "w"))
            self.assertEqual(grade.main([os.path.join(d, "key.json"), d, "--arm", arm, "--out", os.path.join(d, "g.json")]), 0)
            return json.load(open(os.path.join(d, "g.json")))

    def test_b1(self):
        rows = [
            {"url": "http://h/api/a/7", "template": "/api/a/{id}", "verdict": "reads another role's object", "confidence": "proved"},
            {"url": "http://h/api/a/7", "template": "/api/a/{id}", "method": "PATCH",
             "verdict": "writes another role's object: accepted; the change cannot be read back to confirm", "confidence": "likely"},
            {"url": "http://h/api/b/3", "verdict": "reads another role's object", "confidence": "guess"},
            {"url": "http://h/api/a", "verdict": "signed-in only"},
            {"url": "http://h/api/a/export", "verdict": "only one role reads it"},
            {"url": "http://h/api/c/9/notes", "verdict": "some roles refused"},
            {"url": "http://h/api/zz", "method": "DELETE", "verdict": "anyone writes another role's object"},
        ]
        g = self.run_grade("b1", {"b1.jsonl": rows}, {"wall_seconds": 12.5, "requests": 40, "server_requests": 44})
        self.assertEqual((g["found"], g["flaws"]), (2, 4))
        self.assertEqual(g["recall"], 0.5)
        self.assertEqual(g["false_positives"], 2)  # the twin and the route that is in no key row
        self.assertEqual((g["fp_negative"], g["fp_unmatched"], g["fp_plain"]), (1, 1, 0))
        self.assertEqual(g["fp_by_trap"], {"twin-read": 1})
        self.assertEqual(g["triage"], 3)
        self.assertEqual(g["confidence_of_true_flaws"], {"proved": 1, "likely": 1})
        self.assertEqual(g["wall_seconds"], 12.5)
        self.assertEqual(g["first_true_seconds"], 12.5)
        self.assertEqual(g["requests"], 44)
        self.assertEqual(g["by_class"]["bola-read"], {"total": 1, "found": 1})
        self.assertEqual(g["by_visibility"]["js-only"], {"total": 1, "found": 1})

    def test_b2(self):
        rows = [
            {"method": "GET", "url": "http://h/api/a/7", "verdict": "Bypassed!"},
            {"method": "GET", "url": "http://h/api/a/8", "verdict": "Bypassed!"},  # the same flaw again
            {"method": "GET", "url": "http://h/api/a", "verdict": "Bypassed!"},  # plain
            {"method": "GET", "url": "http://h/api/c/1/notes", "verdict": "Is enforced???"},
            {"method": "GET", "url": "http://h/api/c/1/notes", "verdict": "Is enforced???"},
            {"method": "GET", "url": "http://h/api/b/2", "verdict": "Is enforced???"},
            {"method": "GET", "url": "http://h/api/a/7", "verdict": "Is enforced???"},  # reported: not triage
            {"method": "PATCH", "url": "http://h/api/a/7", "verdict": "Enforced!"},
        ]
        g = self.run_grade("b2", {"b2.jsonl": rows}, {"wall_seconds": 3, "requests": 24})
        self.assertEqual(g["found"], 1)
        self.assertEqual((g["false_positives"], g["fp_plain"]), (1, 1))
        self.assertEqual(g["triage"], 2)
        self.assertEqual(g["requests"], 24)

    def test_agent(self):
        f = [
            {"method": "GET", "url": "http://h/api/a/7", "route": "/api/a/{id}", "kind": "read-other-object"},
            {"method": "GET", "url": "http://h/api/a/9", "route": "/api/a/:id", "kind": "read-other-object"},  # again
            {"url": "http://h/api/c/1/notes", "kind": "read-other-object"},  # no method: a read is GET
            {"method": "PATCH", "url": "http://h/api/a/7", "kind": "write-other-object"},
            {"method": "GET", "url": "http://h/api/b/5", "kind": "read-other-object"},  # negative
            {"method": "GET", "url": "http://h/nothing/here", "kind": "no-auth"},  # no route
            "not json",
        ]
        watch = [{"t": 1000 + 90, "line": json.dumps(f[0])}, {"t": 1000 + 300, "line": json.dumps(f[2])}]
        stream = ['1000 {"type":"thread.started"}',
                  '1500 {"type":"turn.completed","usage":{"input_tokens":100,"cached_input_tokens":60,"output_tokens":7}}',
                  '1600 {"type":"turn.completed","usage":{"input_tokens":50,"output_tokens":3}}']
        with tempfile.TemporaryDirectory() as d:
            write(d, "findings.jsonl", [json.dumps(x) if isinstance(x, dict) else x for x in f])
            write(d, "watch.jsonl", watch)
            write(d, "start.epoch", ["1000"])
            write(d, "end.epoch", ["4600"])
            write(d, "stream.ts.jsonl", stream)
            json.dump({"server_requests": 321}, open(os.path.join(d, "meta.json"), "w"))
            json.dump(KEY, open(os.path.join(d, "key.json"), "w"))
            grade.main([os.path.join(d, "key.json"), d, "--arm", "agent"])
            g = json.load(open(os.path.join(d, "grade.json")))
        self.assertEqual(g["found"], 3)  # read, write, nested
        self.assertEqual(g["false_positives"], 2)
        self.assertEqual(g["first_true_seconds"], 90)
        self.assertEqual(g["wall_seconds"], 3600)
        self.assertEqual(g["tokens"], {"input_tokens": 150, "cached_input_tokens": 60, "output_tokens": 10})
        self.assertEqual(g["requests"], 321)

    def test_b1_verdict_sets_follow_the_docs(self):
        docs = open(os.path.join(HERE, "..", "..", "..", "..", "docs", "commands", "roles.md")).read()
        for v in grade.B1_ASSERTS:
            self.assertIn("`%s" % v, docs)


class SummaryTest(unittest.TestCase):
    def g(self, found, flaws, fp, tri, first=None):
        return {"found": found, "flaws": flaws, "recall": found / flaws, "false_positives": fp, "triage": tri,
                "first_true_seconds": first}

    def test_rules(self):
        with tempfile.TemporaryDirectory() as d:
            for i in range(1, 5):
                sd = os.path.join(d, "s%d" % i)
                for arm, g in (("b1", self.g(6, 8, 1, 4)), ("b1c", self.g(3, 8, 0, 7)), ("b2", self.g(2, 8, 5, 30)),
                               ("usual", self.g(5, 8, 0, 0, 1200)), ("azhaq", self.g(6, 8, 1, 0, 400))):
                    os.makedirs(os.path.join(sd, arm))
                    json.dump(g, open(os.path.join(sd, arm, "grade.json"), "w"))
            self.assertEqual(summary.main(["summary.py", d]), 0)
            out = json.load(open(os.path.join(d, "summary.json")))
            self.assertEqual({n: r["verdict"] for n, r in out["rules"].items()},
                             {"1": "holds", "2": "holds", "3": "holds", "1c": "does not hold", "2c": "does not hold"})
            self.assertEqual(out["B_passes"], "yes")
            self.assertEqual(out["B_passes_with_canary"], "no")

    def test_fewer_than_four_is_not_a_verdict(self):
        with tempfile.TemporaryDirectory() as d:
            for i in (1, 2):
                os.makedirs(os.path.join(d, "s%d" % i, "b1"))
                json.dump(self.g(1, 8, 3, 1), open(os.path.join(d, "s%d" % i, "b1", "grade.json"), "w"))
            summary.main(["summary.py", d])
            out = json.load(open(os.path.join(d, "summary.json")))
            self.assertEqual(out["rules"]["1"]["count"], 0)
            self.assertTrue(out["rules"]["1"]["verdict"].startswith("n/a"))


class BriefAndScriptsTest(unittest.TestCase):
    def test_brief_is_neutral_and_complete(self):
        _, _, v = gen.build(2)
        for arm in ("usual", "azhaq"):
            t = brief.render(arm, v, "http://127.0.0.1:8090", HERE)
            for w in ("experiment", "planted", "generated", "answer key", "benchmark", "flaws:"):
                self.assertNotIn(w, t.lower())
            self.assertEqual("azhaq" in t, arm == "azhaq")
            self.assertIn("60 minutes", t)

    def test_seed_is_keyed(self):
        def seed(tag, n, key):
            env = dict(os.environ, CODEX_AUTH_KEY=key)
            return subprocess.run([os.path.join(HERE, "seed.sh"), tag, n], capture_output=True, text=True, env=env).stdout.strip()
        a = seed("exp-authz-x", "1", "k1")
        self.assertEqual(len(a), 16)
        self.assertEqual(a, seed("exp-authz-x", "1", "k1"))
        self.assertNotEqual(a, seed("exp-authz-x", "2", "k1"))
        self.assertNotEqual(a, seed("exp-authz-x", "1", "k2"))

    def test_scripts_parse(self):
        for f in ("appctl.sh", "toolfree.sh", "agent-prep.sh", "agent-post.sh", "watch.sh", "fetch.sh", "launch.sh", "seed.sh"):
            r = subprocess.run(["bash", "-n", os.path.join(HERE, f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f + r.stderr)

    def test_workflow_parses(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("no PyYAML")
        wf = yaml.safe_load(open(os.path.join(HERE, "..", "..", "..", "workflows", "exp-authz.yml")))
        self.assertEqual(set(wf["jobs"]), {"kind", "build", "toolfree", "agent"})


if __name__ == "__main__":
    unittest.main()
