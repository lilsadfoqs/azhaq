"""Tests for ident.py: no docker, no network, no azhaq run.
    python3 -m unittest discover -s .github/ci/parity
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ident  # noqa: E402
from test_parity import EXPORT, KEY, ob, web  # noqa: E402


def measure(key, rows):
    return ident.sample(key, [r for r in rows if r.get("kind") == "observation"])


def only(key, name):
    k = copy.deepcopy(key)
    k["estates"][0]["hosts"] = [h for h in k["estates"][0]["hosts"] if h["host"] == name]
    return k


class Ident(unittest.TestCase):
    def test_the_fixture(self):
        # app1 by its port's product, cache by its port and its check, wiki by its page's technology;
        # the host that was down and the infra host are not services to name.
        res, misses = measure(KEY, EXPORT)
        self.assertEqual((res["services"], res["found"], res["product"], res["versioned"], res["version"], res["title_only"]),
                         (3, 3, 3, 3, 3, 0))
        self.assertEqual(misses, [])
        self.assertEqual(res["by_category"]["cms"], {"services": 2, "found": 2, "product": 2, "versioned": 2, "version": 2})

    def test_a_virtual_host_is_not_found_at_its_address(self):
        # The proxy's address answers for every name behind it: only the name counts.
        rows = [ob("x", "e", "azhaq-http", "application", web("http://127.31.0.99/", "127.31.0.99", 1, "", "", ["Quux Wiki:9.9"]), 1)]
        res, _ = measure(only(KEY, "wiki.acme.test"), rows)
        self.assertEqual((res["services"], res["found"], res["product"]), (1, 0, 0))

    def test_a_product_only_in_the_title_is_shown_not_stated(self):
        rows = [ob("x", "e", "azhaq-http", "application", web("http://app1.acme.test:28080/", "127.31.0.20", 1, "Zorbo Server", "Zorbo"), 1)]
        res, misses = measure(only(KEY, "app1.acme.test"), rows)
        self.assertEqual((res["found"], res["product"], res["version"], res["title_only"]), (1, 0, 0, 1))
        self.assertEqual(len(misses), 1)
        self.assertFalse(misses[0]["product_named"])
        self.assertIn("Zorbo Server Zorbo", misses[0]["shown"])

    def test_a_service_name_is_not_the_product(self):
        rows = [ob("x", "e", "azhaq-ports", "ports", {"host": "127.31.0.21", "ip": "127.31.0.21", "open": [26379],
                                                      "services": [{"port": 26379, "service": "redis"}]}, 1)]
        res, misses = measure(only(KEY, "cache.acme.test"), rows)
        self.assertEqual((res["found"], res["product"]), (1, 0))
        self.assertEqual(misses[0]["said"], [])

    def test_a_product_with_another_version_names_the_product_only(self):
        rows = [ob("x", "e", "azhaq-ports", "ports", {"host": "127.31.0.20", "ip": "127.31.0.20", "open": [28080], "services": [
            {"port": 28080, "service": "http", "product": "Zorbo Server", "version": "2.3"}]}, 1)]
        res, misses = measure(only(KEY, "app1.acme.test"), rows)
        self.assertEqual((res["product"], res["versioned"], res["version"]), (1, 1, 0))
        self.assertTrue(misses[0]["product_named"])

    def test_a_key_version_that_is_not_a_version_is_not_counted(self):
        k = only(KEY, "cache.acme.test")
        k["estates"][0]["hosts"][0]["version"] = "latest"
        res, misses = measure(k, EXPORT)
        self.assertEqual((res["product"], res["versioned"], res["version"]), (1, 0, 0))
        self.assertEqual(misses, [])

    def test_open_with_nothing_stated_is_found(self):
        rows = [ob("x", "e", "azhaq-ports", "ports", {"host": "", "ip": "127.31.0.20", "open": [28080]}, 1)]
        res, _ = measure(only(KEY, "app1.acme.test"), rows)
        self.assertEqual((res["found"], res["product"]), (1, 0))

    def test_the_summary_repeats_nothing_of_the_key(self):
        res, _ = measure(KEY, EXPORT)
        ident.sm.check_clean(res, KEY)
        rows = [ob("x", "e", "azhaq-http", "application", web("http://app1.acme.test:28080/", "127.31.0.20", 1, "Zorbo Server"), 1)]
        ident.sm.check_clean(measure(KEY, rows)[0], KEY)

    def test_aggregate(self):
        a, _ = measure(KEY, EXPORT)
        t = ident.agg([a, a])
        self.assertEqual((t["samples"], t["services"], t["found"], t["product"], t["version"]), (2, 6, 6, 6, 6))
        self.assertEqual(t["shares"], {"found": 1.0, "product": 1.0, "version": 1.0})
        self.assertIn("samples 2: services 6, found 6", ident.table(t))

    def test_cli_under_isolated_python(self):
        # CI runs it with python3 -I, which does not put the script's folder on the path.
        with tempfile.TemporaryDirectory() as d:
            key, exp = os.path.join(d, "key.json"), os.path.join(d, "export.jsonl")
            with open(key, "w") as f:
                json.dump(KEY, f)
            with open(exp, "w") as f:
                f.write("".join(json.dumps(r) + "\n" for r in EXPORT) + "not json\n")
            out, misses = os.path.join(d, "ident.json"), os.path.join(d, "misses.jsonl")
            subprocess.run([sys.executable, "-I", os.path.join(HERE, "ident.py"), "sample", key, exp, "--out", out, "--misses", misses],
                           check=True, cwd=d)
            with open(out) as f:
                self.assertEqual(json.load(f)["product"], 3)
            with open(misses) as f:
                self.assertEqual(f.read(), "")
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "ident.py"), "agg", out, out], check=True, cwd=d,
                               capture_output=True, text=True)
            self.assertIn("samples 2", r.stdout)


if __name__ == "__main__":
    unittest.main()
