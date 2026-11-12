"""Tests for the parity replay: no docker, no network, no azhaq run.
    python3 -m unittest discover -s .github/ci/parity
A synthetic key and a synthetic `azhaq export -format jsonl` stand in for an estate and a run.
"""
import atexit
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
RANGE = os.path.join(HERE, "..", "range")
sys.path.insert(0, HERE)
import summary  # noqa: E402
import to_leads  # noqa: E402

T0 = 1794470400  # the replay's start, 2026-11-12T08:00:00Z


def iso(offset, zone="Z"):
    """A time OFFSET seconds after T0, as azhaq writes one (nanoseconds, a zone) or as date -u does."""
    import datetime
    d = datetime.datetime.fromtimestamp(T0 + offset, datetime.timezone.utc)
    if zone == "+07:00":
        return (d + datetime.timedelta(hours=7)).strftime("%Y-%m-%dT%H:%M:%S.123456789+07:00")
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def port(p, proto="http", primary=True):
    return {"port": p, "protocol": proto, "transport": "tcp", "primary": primary}


KEY = {"seed": "x", "vulhub_commit": "c", "estates": [{
    "index": 1, "domain": "acme.test", "net": "127.31.0.0/24", "dns": "127.0.0.1:5301", "wildcard": None,
    "hosts": [
        {"kind": "service", "host": "app1.acme.test", "address": "127.31.0.20", "vhost": False, "env": "e1", "product": "Zorbo Server",
         "version": "2.3.1", "cve": ["CVE-2099-1111"], "category": "cms", "vulnerable": True, "ports": [port(28080)]},
        {"kind": "service", "host": "cache.acme.test", "address": "127.31.0.21", "vhost": False, "env": "e2", "product": "Flurb DB",
         "version": "4.0", "cve": ["CVE-2099-2222"], "category": "datastore", "vulnerable": True, "ports": [port(26379, "redis")]},
        {"kind": "service", "host": "wiki.acme.test", "address": "127.31.0.99", "vhost": True, "env": "e3", "product": "Quux Wiki",
         "version": "9.9", "cve": ["CVE-2099-3333"], "category": "cms", "vulnerable": True, "ports": [port(80)]},
        {"kind": "service", "host": "down.acme.test", "address": "127.31.0.30", "vhost": False, "env": "e4", "product": "Gone Thing",
         "version": "1", "cve": ["CVE-2099-4444"], "category": "framework", "vulnerable": True, "up": False, "ports": [port(28081)]},
        {"kind": "dangling-cname", "host": "old.acme.test", "target": "q1w2e3.azurewebsites.net.", "category": "dns",
         "vulnerable": True, "ports": []},
        {"kind": "infra", "host": "www.acme.test", "address": "127.31.0.99", "product": "nginx", "version": "", "cve": [],
         "category": "infra", "vulnerable": False, "ports": [port(80)]},
    ]}]}


def ent(i, typ, key, t):
    return {"kind": "entity", "entity": {"id": i, "type": typ, "key": key, "first_seen": iso(t, "+07:00"), "last_seen": iso(t)}, "scope": "target"}


def ob(i, eid, collector, kind, payload, t, zone="Z"):
    return {"kind": "observation", "observation": {"id": i, "entity_id": eid, "collector": collector, "source": "s", "kind": kind,
                                                   "payload": payload, "confidence": 0.9, "observed_at": iso(t, zone)}}


def web(url, ip, t, title, server="", tech=(), **extra):
    p = {"url": url, "final_url": url, "ip": ip, "status": 200, "title": title, "server": server, "tech": list(tech)}
    p.update(extra)
    return p


EXPORT = [
    ent("e-old", "Hostname", "old.acme.test", 25),
    ob("o1", "e-old", "azhaq-dns", "dns", {"fqdn": "old.acme.test", "cname": "q1w2e3.azurewebsites.net.", "takeover": {
        "service": "Azure App Service", "target": "q1w2e3.azurewebsites.net.", "evidence": "the CNAME target does not resolve",
        "strength": "dangling", "status": "candidate"}}, 30),
    ob("o2", "e-a", "azhaq-dns", "dns", {"fqdn": "app1.acme.test", "ips": ["127.31.0.20"]}, 20),
    ob("o3", "e-c", "azhaq-dns", "dns", {"fqdn": "cache.acme.test", "ips": ["127.31.0.21"]}, 20),
    ob("o4", "e-w", "azhaq-dns", "dns", {"fqdn": "wiki.acme.test", "ips": ["127.31.0.99"]}, 20),
    ob("o5", "e-p", "azhaq-ports", "ports", {"host": "127.31.0.20", "ip": "127.31.0.20", "open": [28080], "services": [
        {"port": 28080, "service": "http", "banner": "Zorbo/2.3.1", "product": "Zorbo Server", "version": "2.3.1"}]}, 60, "+07:00"),
    ob("o6", "e-p", "azhaq-ports", "ports", {"host": "127.31.0.21", "ip": "127.31.0.21", "open": [26379], "services": [
        {"port": 26379, "service": "redis", "product": "Flurb DB", "version": "4.0"}]}, 400),
    ob("o7", "e-p", "azhaq-ports", "ports", {"host": "127.31.0.99", "ip": "127.31.0.99", "open": [80], "services": [
        {"port": 80, "service": "http", "product": "nginx"}, {"port": 9, "service": "tcpwrapped"}]}, 90),
    ob("o8", "e-p", "azhaq-ports", "ports", {"prefix": "127.31.0.0/24", "range": True, "open": []}, 95),
    # the root of the name-routed app: two answers (the second later) and a name-less address twin
    ob("o9", "e-wr", "azhaq-http", "application", web("http://wiki.acme.test/", "127.31.0.99", 1000, "Quux Wiki 9.9", "nginx",
                                                      ["Quux Wiki:9.9"]), 1000),
    ob("o10", "e-wr", "azhaq-http", "application", web("http://wiki.acme.test/", "127.31.0.99", 1100, "Quux Wiki 9.9", "nginx",
                                                       ["Quux Wiki:9.9"]), 1100),
    ob("o11", "e-wr", "azhaq-http", "application", web("http://127.31.0.99/", "127.31.0.99", 1050, "Quux Wiki 9.9", "nginx",
                                                       ["Quux Wiki:9.9"]), 1050),
    # a page with no technology, a non-root page, and a stack trace
    ob("o12", "e-n", "azhaq-http", "application", web("http://app1.acme.test:28080/plain", "127.31.0.20", 150, ""), 150),
    ob("o13", "e-g", "azhaq-http", "application", web("http://app1.acme.test:28080/.git/HEAD", "127.31.0.20", 200, "", "Zorbo"), 200),
    ob("o14", "e-z", "azhaq-http", "application", web("http://zzz.acme.test:8080/err", "127.31.0.77", 250, "", "", stack_trace={
        "runtime": "java", "exception": "NullPointerException"}), 250),
    ob("o15", "e-v", "azhaq-verify", "verify", {"kind": "unauthenticated-read", "label": "proved", "severity": "high",
                                               "host": "127.31.0.21", "port": 26379, "target": "127.31.0.21:26379", "service": "redis",
                                               "product": "Flurb DB", "version": "4.0", "request": "INFO server",
                                               "evidence": "redis_version:4.0"}, 600),
    ob("o16", "e-v", "azhaq-advisories", "advisory", {"advisory_id": "GHSA-xxxx-yyyy-zzzz", "target": "127.31.0.20:28080",
                                                     "host": "127.31.0.20", "port": 28080, "product": "Zorbo Server", "version_seen": "2.3.1",
                                                     "label": "affected", "read": "CVE-2099-1111 matches"}, 650),
]
HUNT = [
    {"rank": 1, "score": 70, "key": "http://app1.acme.test:28080/.git/HEAD", "type": "URL",
     "reasons": [{"signal": "exposed-file", "detail": "git repository served"}]},
    {"rank": 2, "score": 45, "key": "http://app1.acme.test:28080/login", "type": "URL", "reasons": [{"signal": "path-auth", "detail": "login"}]},
    {"rank": 3, "score": 30, "key": "http://app1.acme.test:28080/admin", "type": "URL",
     "reasons": [{"signal": "path-admin", "detail": "admin"}, {"signal": "gated", "detail": "401"}]},
    {"type": "summary", "command": "hunt", "results": 3},
]


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def convert(argv):
    with contextlib.redirect_stdout(io.StringIO()):
        return to_leads.main(argv)


def write_jsonl(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def secrets_in(text):
    """The key's products, versions, CVEs, hosts, addresses and ports that text repeats."""
    out = []
    for s in summary.secrets_of(KEY):
        if (re.search(r"(?<![\w.])" + re.escape(s) + r"(?![\w.])", text.lower()) if s.isdigit() else s in text.lower()):
            out.append(s)
    return out


_FX = {}


def fx():
    """The fixture, built once: leads, grade and key files of the synthetic run."""
    if not _FX:
        t = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, t, True)
        export, hunt, key = (os.path.join(t, n) for n in ("export.jsonl", "hunt.jsonl", "key.json"))
        write_jsonl(export, EXPORT)
        write_jsonl(hunt, HUNT)
        with open(key, "w") as f:
            json.dump(KEY, f)
        out = os.path.join(t, "graded")
        convert(["--export", export, "--hunt", hunt, "--out", out, "--start", iso(0), "--end", iso(1500)])
        subprocess.run([sys.executable, "-I", os.path.join(RANGE, "grade.py"), key, out, "--md", os.path.join(t, "g.md")],
                       check=True, capture_output=True)
        _FX.update(export=export, hunt=hunt, key=key, out=out,
                   grade=json.loads(read(os.path.join(out, "grade.json"))),
                   leads=[json.loads(l) for l in read(os.path.join(out, "leads.jsonl")).splitlines()])
    return _FX


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for k, v in fx().items():
            setattr(cls, k, v)


class ToLeads(Fixture):
    def by(self, kind=None, host=None, port=None):
        return [l for l in self.leads if (kind is None or l["kind"] == kind) and (host is None or l["host"] == host) and (port is None or l.get("port") == port)]

    def test_every_lead_has_the_gate_fields(self):
        for l in self.leads:
            for k in ("phase", "time", "kind", "severity", "host", "product", "cve", "title", "evidence", "how"):
                self.assertIn(k, l)
            self.assertEqual(l["phase"], 1)
            self.assertRegex(l["time"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(len(self.leads), 10)

    def test_times_are_the_stored_ones_in_utc_and_sorted(self):
        ts = [to_leads.epoch(l["time"]) - T0 for l in self.leads]
        self.assertEqual(ts, sorted(ts))
        by = {(l["kind"], l["host"], l.get("port"), l["how"]): to_leads.epoch(l["time"]) - T0 for l in self.leads}
        self.assertEqual(by[("takeover", "old.acme.test", None, "azhaq run (names stage)")], 30)
        self.assertEqual(by[("vulnerable-software", "127.31.0.20", 28080, "azhaq run -ports default")], 60)  # a +07:00 stamp with nanoseconds
        self.assertEqual(by[("vulnerable-software", "wiki.acme.test", 80, "azhaq run (web stage)")], 1000)  # the first of three answers

    def test_ports_without_a_product_are_not_leads(self):
        self.assertEqual(self.by(host="127.31.0.99", port=9), [])
        self.assertEqual(len(self.by("vulnerable-software", "127.31.0.99", 80)), 1)

    def test_one_web_lead_for_one_answer_under_a_name_and_an_address(self):
        web_leads = [l for l in self.leads if l.get("how") == "azhaq run (web stage)" and l["kind"] == "vulnerable-software"]
        self.assertEqual([l["host"] for l in web_leads], ["wiki.acme.test"])
        self.assertIn("Quux Wiki 9.9", web_leads[0]["product"])

    def test_takeover_verify_advisory_stack_and_hunt(self):
        self.assertEqual(self.by("takeover")[0]["host"], "old.acme.test")
        self.assertIn("q1w2e3.azurewebsites.net", self.by("takeover")[0]["evidence"])
        v = self.by("unauthenticated-access")[0]
        self.assertEqual((v["host"], v["port"], v["severity"]), ("127.31.0.21", 26379, "high"))
        self.assertEqual(self.by("info-leak")[0]["host"], "zzz.acme.test")
        self.assertEqual(len(self.by("exposed-file")), 1)
        self.assertEqual(len(self.by("exposed-panel")), 1)  # path-admin; a row of route heuristics alone (path-auth) is no lead
        adv = [l for l in self.leads if l["how"] == "azhaq run -advisories"][0]
        self.assertEqual(adv["cve"], "")  # a GHSA id is not a CVE
        self.assertEqual(adv["host"], "127.31.0.20")

    def test_a_cve_advisory_carries_its_cve(self):
        rows = [ob("a", "e", "azhaq-advisories", "advisory", {"advisory_id": "CVE-2024-1234", "target": "h:1", "host": "h", "port": 1,
                                                              "product": "P", "version_seen": "1", "label": "affected"}, 10)]
        with tempfile.TemporaryDirectory() as t:
            write_jsonl(os.path.join(t, "e.jsonl"), rows)
            convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o")])
            self.assertEqual(json.loads(read(os.path.join(t, "o", "leads.jsonl")).splitlines()[0])["cve"], "CVE-2024-1234")

    def test_a_not_affected_advisory_is_no_lead(self):
        rows = [ob("a", "e", "azhaq-advisories", "advisory", {"advisory_id": "CVE-2024-1234", "target": "h:1", "host": "h", "label": "not affected"}, 10)]
        with tempfile.TemporaryDirectory() as t:
            write_jsonl(os.path.join(t, "e.jsonl"), rows)
            convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o")])
            self.assertEqual(read(os.path.join(t, "o", "leads.jsonl")), "")

    def test_phases_and_surface(self):
        self.assertEqual(read(os.path.join(self.out, "phases.log")),
                         "phase 1 start %s\nphase 1 end %s\n" % (iso(0), iso(1500)))
        s = read(os.path.join(self.out, "surface-1.txt")).splitlines()
        self.assertIn("127.31.0.20:28080/tcp http Zorbo Server 2.3.1", s)
        self.assertIn("app1.acme.test:28080/tcp http Zorbo Server 2.3.1", s)  # a name that points at the address
        self.assertIn("wiki.acme.test:80/tcp http nginx", s)
        self.assertIn("app1.acme.test 127.31.0.20", s)

    def test_a_port_with_no_service_is_in_the_surface(self):
        # The second port pass keeps an open port before any service detection names it.
        with tempfile.TemporaryDirectory() as t:
            write_jsonl(os.path.join(t, "e.jsonl"), EXPORT + [ent("p-bare", "Port", "127.31.0.20:50070/tcp", 40)])
            convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o"), "--start", iso(0)])
            s = read(os.path.join(t, "o", "surface-1.txt")).splitlines()
            self.assertIn("127.31.0.20:50070/tcp", s)
            self.assertIn("app1.acme.test:50070/tcp", s)

    def test_a_time_before_the_start_is_held_at_the_start(self):
        with tempfile.TemporaryDirectory() as t:
            write_jsonl(os.path.join(t, "e.jsonl"), EXPORT)
            convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o"), "--start", iso(100)])
            for l in map(json.loads, read(os.path.join(t, "o", "leads.jsonl")).splitlines()):
                self.assertGreaterEqual(to_leads.epoch(l["time"]), T0 + 100)

    def test_without_start_and_end_the_stored_times_bound_the_phase(self):
        with tempfile.TemporaryDirectory() as t:
            write_jsonl(os.path.join(t, "e.jsonl"), EXPORT)
            convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o")])
            ph = read(os.path.join(t, "o", "phases.log"))
            self.assertIn("phase 1 start " + iso(20), ph)

    def test_unreadable_lines_are_skipped(self):
        with tempfile.TemporaryDirectory() as t:
            with open(os.path.join(t, "e.jsonl"), "w") as f:
                f.write("not json\n\n[1]\n" + json.dumps(EXPORT[1]) + "\n")
            self.assertEqual(convert(["--export", os.path.join(t, "e.jsonl"), "--out", os.path.join(t, "o")]), 0)
            self.assertEqual(len(read(os.path.join(t, "o", "leads.jsonl")).splitlines()), 1)


class Graded(Fixture):
    def test_grade_py_reads_the_leads_unchanged(self):
        v = self.grade["phases"][0]["vulns"]
        self.assertEqual((v["identified"], v["of"]), (4, 4))
        self.assertEqual(self.grade["phases"][0]["time"]["first_match_s"], 30)
        self.assertEqual(self.grade["phases"][0]["time"]["start_from"], "phases.log")
        self.assertEqual(self.grade["phases"][0]["leads"]["total"], 10)

    def test_surface(self):
        s = self.grade["phases"][0]["surface"]
        self.assertEqual(s["hosts"][0], 4)  # the three names and the proxy's, the dangling name not counted
        self.assertEqual(s["ports"], [4, 4])


class Summary(Fixture):
    def sample(self):
        return summary.sample(KEY, self.grade, self.leads, 1800)

    def test_numbers(self):
        s = self.sample()
        self.assertEqual(s["key_vulns"], 4)
        self.assertEqual({k: v["count"] for k, v in s["identified"].items()}, {"5m": 2, "15m": 3, "30m": 4, "end": 4})
        self.assertEqual(s["identified"]["5m"]["fraction"], 0.5)
        self.assertEqual(s["first_match_seconds"], 30)
        self.assertEqual(s["precision"], {"matched": 6, "leads": 10, "value": 0.6})
        self.assertEqual(s["surface"]["ports"], {"found": 4, "of": 4, "recall": 1.0})
        self.assertEqual(s["by_kind"]["vulnerable-software"], {"leads": 5, "matched": 4})
        self.assertEqual(s["by_kind"]["takeover"], {"leads": 1, "matched": 1})
        self.assertEqual(s["by_kind"]["info-leak"], {"leads": 1, "matched": 0})
        self.assertEqual(s["by_category"]["cms"], {"identified": 2, "of": 2})  # the host that was down is not in the key
        self.assertNotIn("framework", s["by_category"])

    def test_the_summary_repeats_nothing_of_the_key(self):
        s = self.sample()
        self.assertEqual(secrets_in(json.dumps(s)), [])
        a = summary.agg([s, s])
        self.assertEqual(secrets_in(json.dumps(a)), [])
        self.assertEqual(secrets_in(summary.table(a)), [])
        # and the grade does: it is what stays encrypted
        self.assertNotEqual(secrets_in(json.dumps(self.grade)), [])

    def test_a_summary_that_would_leak_is_refused(self):
        for leak in ("Zorbo Server", "CVE-2099-2222", "wiki.acme.test", "127.31.0.21", "28080", "acme.test"):
            with self.assertRaises(ValueError, msg=leak):
                summary.check_clean({"by_kind": {"x" + leak.lower() + "y" if not leak.isdigit() else leak: {"leads": 1}}}, KEY)

    def test_a_count_equal_to_a_port_is_not_a_leak(self):
        summary.check_clean({"identified": {"end": {"count": 80}}, "n": 28080}, KEY)

    def test_aggregates_over_samples(self):
        a = dict(self.sample())
        b = json.loads(json.dumps(a))
        b["identified"]["end"] = {"count": 2, "fraction": 0.5}
        b["first_match_seconds"] = None
        b["precision"]["value"] = 0.333
        r = summary.agg([a, b])
        self.assertEqual(r["samples"], 2)
        end = r["metrics"]["identified_end"]
        self.assertEqual((end["mean"], end["min"], end["n"]), (3.0, 2, 2))
        first = r["metrics"]["first_match_seconds"]
        self.assertEqual((first["mean"], first["min"], first["n"]), (30, 30, 1))
        self.assertAlmostEqual(r["metrics"]["precision"]["mean"], 0.467, places=3)
        self.assertEqual(r["by_kind"]["takeover"], {"leads": 2, "matched": 2})
        text = summary.table(r)
        self.assertIn("identified at 5 min", text)
        self.assertIn("seconds to the first match", text)

    def test_cli(self):
        t = tempfile.mkdtemp()
        out = os.path.join(t, "s.json")
        gp = os.path.join(t, "grade.json")
        with open(gp, "w") as f:
            json.dump(self.grade, f)
        lp = os.path.join(self.out, "leads.jsonl")
        subprocess.run([sys.executable, "-I", os.path.join(HERE, "summary.py"), "sample", self.key, gp, lp, "--cap-seconds", "1800", "--out", out], check=True)
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "summary.py"), "agg", out, out], check=True, capture_output=True, text=True)
        self.assertIn("2 samples", r.stdout)
        self.assertEqual(secrets_in(r.stdout), [])


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


class Seed(unittest.TestCase):
    SH = os.path.join(HERE, "seed.sh")

    def seed(self, tag, sample, key="k", pool=None):
        env = dict(os.environ, CODEX_AUTH_KEY=key)
        if pool:
            env["POOL"] = pool
        return run(["bash", self.SH, tag, str(sample)], env=env)

    def test_keyed_hash_of_tag_and_sample(self):
        import hashlib
        import hmac
        r = self.seed("parity-x", 2, "secret")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), hmac.new(b"secret", b"parity-x:2", hashlib.sha256).hexdigest())

    def test_samples_and_keys_differ(self):
        a, b = self.seed("parity-x", 1).stdout, self.seed("parity-x", 2).stdout
        self.assertNotEqual(a, b)
        self.assertNotEqual(a, self.seed("parity-x", 1, "other").stdout)

    def test_an_empty_key_fails(self):
        r = self.seed("parity-x", 1, "")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")

    def test_the_real_pool_does_not_collide(self):
        self.assertEqual(self.seed("parity-x", 1).returncode, 0)

    def test_a_pool_entry_derived_estate_is_refused(self):
        with tempfile.TemporaryDirectory() as t:
            pool = os.path.join(t, "pool.json")
            write(pool, json.dumps(["other", "parity-x:1"]))  # the gate would derive the same estate
            r = self.seed("parity-x", 1, pool=pool)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("pool", r.stderr)
            self.assertEqual(r.stdout, "")
            self.assertEqual(self.seed("parity-x", 2, pool=pool).returncode, 0)


STUB = """#!/bin/bash
echo "$*" >> "$STUB_LOG"
case $1 in
export) echo '{"kind":"entity"}' ;;
run) [ -n "${STUB_RUN_EXIT:-}" ] && exit "$STUB_RUN_EXIT" ;;
esac
exit 0
"""


class Replay(unittest.TestCase):
    SH = os.path.join(HERE, "replay.sh")

    def go(self, *args, exit_code=None):
        t = tempfile.mkdtemp()
        stub = os.path.join(t, "azhaq")
        with open(stub, "w") as f:
            f.write(STUB)
        os.chmod(stub, 0o755)
        env = dict(os.environ, AZHAQ=stub, STUB_LOG=os.path.join(t, "log"))
        if exit_code is not None:
            env["STUB_RUN_EXIT"] = str(exit_code)
        r = run(["bash", self.SH, os.path.join(t, "out")] + list(args), env=env)
        log = read(os.path.join(t, "log")).splitlines() if os.path.exists(os.path.join(t, "log")) else []
        return r, log, os.path.join(t, "out")

    def test_the_documented_flow(self):
        r, log, out = self.go("acme.test", "127.31.0.0/24", "127.0.0.1:5301", "7")
        self.assertEqual(r.returncode, 0, r.stderr)
        flags = "-domain acme.test -cidr 127.31.0.0/24 -allow acme.test -allow 127.31.0.0/24 -resolvers 127.0.0.1:5301 -ports default -verify"
        self.assertEqual(log[0], "plan " + flags)
        self.assertEqual(log[1], "run %s -max-time 420s -db %s" % (flags, os.path.join(out, "work", "workspace.db")))
        self.assertEqual([l.split()[0] for l in log], ["plan", "run", "hunt", "hunt", "export", "export"])
        self.assertIn("hunt -db", log[2])
        self.assertNotIn("-limit", log[2])  # the worklist as printed: the default limit
        self.assertIn("-limit 1000", log[3])
        self.assertIn("-format jsonl", log[4])
        self.assertIn("-format findings", log[5])
        meta = json.loads(read(os.path.join(out, "replay.json")))
        self.assertEqual(meta["worklist_exit"], 0)
        self.assertEqual((meta["cap_seconds"], meta["run_exit"]), (420, 0))
        self.assertRegex(meta["start"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertTrue(os.path.exists(os.path.join(out, "export.jsonl")))

    def test_default_cap_is_thirty_minutes(self):
        r, log, out = self.go("acme.test", "127.31.0.0/24", "127.0.0.1:5301")
        self.assertIn("-max-time 1800s", log[1])

    def test_a_cap_stop_is_recorded_not_an_error(self):
        r, log, out = self.go("acme.test", "127.31.0.0/24", "127.0.0.1:5301", "1", exit_code=4)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(json.loads(read(os.path.join(out, "replay.json")))["run_exit"], 4)

    def test_bad_minutes(self):
        for bad in ("0", "x", "-3", "1.5"):
            self.assertEqual(self.go("a.test", "127.0.0.0/24", "127.0.0.1:1", bad)[0].returncode, 2, bad)

    def test_nothing_is_chosen_from_the_estate(self):
        src = read(self.SH)
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        for word in ("key.json", "catalog", "vars.json", "range/", "-rate", "-max-requests", "-dirs", "-ports full", "-ports top"):
            self.assertNotIn(word, code)


class Fetch(unittest.TestCase):
    """fetch.sh against a stand-in curl and age: the aggregate table is all it prints."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.fx = os.path.join(t, "fx")
        for s in ("s1", "s2"):
            d = os.path.join(self.fx, "repo", "parity", "demo", s)
            os.makedirs(d)
            sm = summary.sample(KEY, fx()["grade"], fx()["leads"], 1800)
            write(os.path.join(d, "summary.json.age"), json.dumps(sm))
            write(os.path.join(d, "key.json.age"), json.dumps(KEY))
            pack = os.path.join(t, "pack")
            os.makedirs(pack, exist_ok=True)
            write(os.path.join(pack, "replay.json"), "{}")
            subprocess.run(["tar", "-czf", os.path.join(d, "sample.tgz.age"), "-C", pack, "replay.json"], check=True)
        self.bin = os.path.join(t, "bin")
        os.makedirs(self.bin)
        curl = r'''#!/bin/bash
out=""; url=""
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift 2;; -*) shift;; *) url=$1; shift;; esac; done
if [[ $url == https://api.github.com/repos/*/contents/* ]]; then
  p=${url#*/contents/}; p=${p%%\?*}
  [ -d "$FX/repo/$p" ] || exit 22
  python3 -I - "$FX/repo/$p" <<'PY'
import sys, os, json
d = sys.argv[1]
print(json.dumps([{"name": n, "type": "dir" if os.path.isdir(os.path.join(d, n)) else "file"} for n in sorted(os.listdir(d))]))
PY
elif [[ $url == https://raw.githubusercontent.com/*/ci-results/* ]]; then
  p=${url#*/ci-results/}; [ -f "$FX/repo/$p" ] || exit 22; cp "$FX/repo/$p" "$out"
else exit 6; fi
'''
        age = '''#!/bin/bash
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift 2;; -i) shift 2;; -d) shift;; *) in=$1; shift;; esac; done
cp "$in" "$out"
'''
        for name, body in (("curl", curl), ("age", age)):
            p = os.path.join(self.bin, name)
            write(p, body)
            os.chmod(p, 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def run_fetch(self, name):
        env = dict(os.environ, PATH=self.bin + ":" + os.environ["PATH"], FX=self.fx, AZHAQ_AGE_KEY=os.path.join(self.tmp.name, "key"))
        return run(["bash", os.path.join(HERE, "fetch.sh"), name, os.path.join(self.tmp.name, "dir")], env=env)

    def test_prints_the_table_only_and_keeps_the_rest_on_disk(self):
        r = self.run_fetch("demo")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("2 samples"), r.stdout)
        self.assertEqual(secrets_in(r.stdout), [])
        self.assertNotIn("replay.json", r.stdout)
        d = os.path.join(self.tmp.name, "dir")
        for f in ("s1/key.json", "s1/summary.json", "s1/replay.json", "s2/key.json"):
            self.assertTrue(os.path.exists(os.path.join(d, f)), f)

    def test_an_unknown_run_fails(self):
        self.assertNotEqual(self.run_fetch("nope").returncode, 0)


WORKLIST = [
    {"rank": 1, "score": 90, "key": "127.31.0.5:6379", "type": "Service", "tier": "finding", "kind": "identification",
     "host": "db.acme.test", "port": 6379, "product": "Redis", "version": "6.0.5", "label": "proved", "severity": "high",
     "what": "unauthenticated-read", "evidence": "INFO answered without a password",
     "proof": {"observed_at": iso(200)}, "reasons": []},
    {"rank": 2, "score": 60, "key": "127.31.0.7:8161", "type": "Service", "tier": "identification", "kind": "identification",
     "host": "mq.acme.test", "port": 8161, "product": "Apache ActiveMQ", "version": "5.17.3", "advisory_id": "CVE-2023-46604",
     "label": "version-only", "severity": "info", "proof": {"observed_at": iso(300)}, "reasons": []},
    {"rank": 3, "score": 20, "key": "old.acme.test", "type": "Hostname", "tier": "lead",
     "reasons": [{"signal": "takeover-candidate", "detail": "CNAME to x.cloud.example answered NXDOMAIN"}]},
    {"rank": 4, "score": 70, "key": "http://app1.acme.test:28080/.git/HEAD", "type": "URL", "tier": "finding",
     "reasons": [{"signal": "exposed-file", "detail": "git repository served"}]},
    {"rank": 5, "score": 45, "key": "http://app1.acme.test:28080/login", "type": "URL", "tier": "lead",
     "reasons": [{"signal": "path-auth", "detail": "login"}]},
    {"type": "summary", "command": "hunt", "results": 5},
]


class WorklistView(unittest.TestCase):
    """--worklist: the rows of hunt's default output are the leads, one each, and nothing else is."""

    @classmethod
    def setUpClass(cls):
        t = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, t, True)
        export, wl = os.path.join(t, "export.jsonl"), os.path.join(t, "worklist.jsonl")
        write_jsonl(export, EXPORT)
        write_jsonl(wl, WORKLIST)
        out = os.path.join(t, "graded")
        convert(["--export", export, "--worklist", wl, "--out", out, "--start", iso(0), "--end", iso(1500)])
        cls.leads = [json.loads(l) for l in read(os.path.join(out, "leads.jsonl")).splitlines()]

    def test_one_lead_for_each_row_and_none_from_the_map(self):
        self.assertEqual(len(self.leads), 5)
        self.assertEqual({l["how"] for l in self.leads}, {"azhaq hunt"})

    def test_an_identification_names_its_product_version_and_advisory(self):
        mq = [l for l in self.leads if l["host"] == "mq.acme.test"][0]
        self.assertEqual((mq["kind"], mq["port"], mq["product"], mq["cve"]), ("vulnerable-software", 8161, "Apache ActiveMQ 5.17.3", "CVE-2023-46604"))
        self.assertIn("version-only", mq["title"])
        self.assertEqual(mq["time"], iso(300))
        db = [l for l in self.leads if l["host"] == "db.acme.test"][0]
        self.assertEqual((db["kind"], db["severity"]), ("unauthenticated-access", "high"))

    def test_a_takeover_candidate_keeps_its_words(self):
        t = [l for l in self.leads if l["host"] == "old.acme.test"][0]
        self.assertEqual(t["kind"], "takeover")
        self.assertIn("takeover-candidate", t["title"])
        self.assertIn("NXDOMAIN", t["evidence"])

    def test_hunt_and_worklist_are_one_or_the_other(self):
        with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
            convert(["--export", "x", "--hunt", "a", "--worklist", "b", "--out", "o"])


class Workflow(unittest.TestCase):
    def setUp(self):
        self.text = read(os.path.join(HERE, "..", "..", "workflows", "parity.yml"))

    def test_tags_parallelism_and_secrets(self):
        self.assertIn('tags: ["parity-*"]', self.text)
        self.assertIn("max-parallel: 2", self.text)
        used = re.findall(r"secrets\.([A-Z_]+)", self.text)
        # the seed's key, in the estate step only, and the token the publish step pushes with
        self.assertEqual(sorted(used), ["CODEX_AUTH_KEY", "GITHUB_TOKEN"])
        self.assertEqual(self.text.count("CODEX_AUTH_KEY"), 2)  # the env entry of the estate step: its name and the secret

    def test_the_estate_is_built_as_the_gate_builds_it(self):
        for step in ("vm.max_map_count=262144", "./bench/labdns", "fetch-vulhub.sh", "build.py", "--count 1", "up.py", "--run-as nobody", "seed.sh"):
            self.assertIn(step, self.text)

    def test_results_are_encrypted_and_not_logged(self):
        self.assertIn("parity/${GITHUB_REF_NAME#parity-}/s", self.text)
        for f in ("key.json.age", "sample.tgz.age", "summary.json.age", "summary-worklist.json.age", "--worklist"):
            self.assertIn(f, self.text)
        self.assertNotIn("cat $HOME/parity/out", self.text)

    def test_shell_scripts_parse(self):
        for f in ("replay.sh", "seed.sh", "fetch.sh"):
            self.assertEqual(run(["bash", "-n", os.path.join(HERE, f)]).returncode, 0, f)


if __name__ == "__main__":
    unittest.main()
