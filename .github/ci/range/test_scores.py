"""Tests for scores.py, the private history of review scores:
    python3 -m unittest discover -s .github/ci/range
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import scores  # noqa: E402

B_ROWS = [
    ("install and first run", 9), ("docs", 8), ("subdomain recon", 9), ("host and port discovery", 9),
    ("web and api mapping", 9), ("signed-in and multi-role testing", 9),
    ("output and integration (including assistants)", 9),
    ("reliability (crashes, hangs, wrong data, silent failures)", 9),
    ("performance (time, memory and cpu, and the requests it sends to the target for the same result)", 8),
]


def report(rows, overall=9, extra=()):
    lines = ["# Report", "", "| Item | Score | Reasoning |", "|---|---|---|"]
    lines += ["| %s | %d | r |" % r for r in rows]
    lines += ["| overall (this part) | %d | r |" % overall]
    lines += ["| %s | %d | r |" % r for r in extra]
    return "\n".join(lines) + "\n"


def part_b(docs=8, perf=8):
    rows = [(k, v) for k, v in B_ROWS]
    rows[1] = ("docs", docs)
    rows[-1] = (rows[-1][0], perf)
    return report(rows)


class Extract(unittest.TestCase):
    @staticmethod
    def write_file(path, text):
        with open(path, "w") as f:
            f.write(text)

    def test_a_scorecard_becomes_one_record(self):
        r = scores.extract(part_b(), "gate-b", "trial-x", "b1", "v0.14.0", "77", now=0)
        self.assertEqual(r["items"]["docs"], 8)
        self.assertEqual(len(r["items"]), 9)
        self.assertEqual((r["overall"], r["missing"], r["tag"], r["part"], r["time"]), (9, [], "trial-x", "b1", "1970-01-01T00:00:00Z"))

    def test_an_item_the_report_lacks_is_listed_not_guessed(self):
        text = part_b().replace("| docs | 8 | r |\n", "")
        r = scores.extract(text, "gate-b", "t")
        self.assertNotIn("docs", r["items"])
        self.assertEqual(r["missing"], ["docs"])

    def test_a_switch_report_keeps_every_row_but_the_overall(self):
        r = scores.extract("| Item | Score | Reasoning |\n|---|---|---|\n| install | 7 | x |\n| overall | 7 | y |\n", "switch", "t")
        self.assertEqual(r["items"], {"install": 7})
        self.assertEqual(r["overall"], 7)

    def test_extract_command_writes_json_and_refuses_a_report_with_no_scorecard(self):
        with tempfile.TemporaryDirectory() as d:
            rep, out = os.path.join(d, "REPORT.md"), os.path.join(d, "scores.json")
            self.write_file(rep, part_b())
            self.assertEqual(scores.main(["extract", rep, "--kind", "gate-b", "--tag", "t", "--part", "b", "--out", out]), 0)
            with open(out) as f:
                self.assertEqual(json.load(f)["items"]["docs"], 8)
            self.write_file(rep, "no table here\n")
            os.remove(out)
            self.assertEqual(scores.main(["extract", rep, "--kind", "gate-b", "--tag", "t", "--out", out]), 1)
            self.assertFalse(os.path.exists(out))

    def test_it_runs_isolated_as_the_workflow_runs_it(self):
        # python3 -I does not put the script's folder on sys.path: merge_gate is loaded by path.
        with tempfile.TemporaryDirectory() as d:
            rep, out = os.path.join(d, "REPORT.md"), os.path.join(d, "scores.json")
            self.write_file(rep, part_b())
            r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "scores.py"), "extract", rep, "--kind", "gate-b", "--tag", "t", "--out", out],
                               capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stderr), (0, ""))


class History(unittest.TestCase):
    def write(self, root, tag, part, kind, rows, when):
        d = os.path.join(root, "trial", tag, part)
        os.makedirs(d)
        rec = scores.extract(report(rows), kind, tag, part, now=when)
        with open(os.path.join(d, "scores.json"), "w") as f:
            json.dump(rec, f)

    def test_items_across_reviews_with_the_spread_between_samples(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "trial-1", "b1", "gate-b", [("docs", 7), ("subdomain recon", 9)], 100)
            self.write(root, "trial-1", "b2", "gate-b", [("docs", 9), ("subdomain recon", 9)], 101)
            self.write(root, "trial-2", "b1", "gate-b", [("docs", 8), ("subdomain recon", 9)], 200)
            reviews = scores.build(scores.load([root]))
            self.assertEqual([r["tag"] for r in reviews], ["trial-1", "trial-2"])
            rows = scores.table(reviews)
            docs = [r for r in rows if r[0].endswith("docs")][0]
            self.assertEqual(docs[1], "7/9 (spread 2)")
            self.assertEqual(docs[2], "8")
            self.assertEqual(docs[3], "0.0")  # the means, 8 and 8, did not move
            self.assertIn("(spread 2)", scores.render(reviews))

    def test_four_samples_list_every_cell_with_their_spread(self):
        with tempfile.TemporaryDirectory() as root:
            for k, docs in enumerate((6, 7, 5, 8), 1):
                self.write(root, "trial-1", "b%d" % k, "gate-b", [("docs", docs)], 100 + k)
            self.write(root, "trial-2", "b", "gate-b", [("docs", 9)], 200)
            reviews = scores.build(scores.load([root]))
            docs = [r for r in scores.table(reviews) if r[0].endswith("docs")][0]
            self.assertEqual(docs[1], "6/7/5/8 (spread 3)")
            self.assertEqual(docs[2], "9")
            self.assertEqual(docs[3], "2.5")  # the means, 6.5 and 9
            out = scores.render(reviews)
            self.assertIn("6/7/5/8 (spread 3)", out)
            self.assertIn("a1..a4", out)

    def test_samples_stay_in_part_order(self):
        with tempfile.TemporaryDirectory() as root:
            for k in (3, 1, 4, 2):
                self.write(root, "trial-1", "a%d" % k, "gate-a", [("trust", k + 4)], 100 + k)
            reviews = scores.build(scores.load([root]))
            self.assertEqual(scores.table(reviews)[1][1], "5/6/7/8 (spread 3)")

    def test_old_records_with_one_or_two_samples_still_render(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "trial-1", "b1", "gate-b", [("docs", 7)], 100)
            self.write(root, "trial-1", "b2", "gate-b", [("docs", 9)], 101)
            self.write(root, "trial-0", "b", "gate-b", [("docs", 8)], 50)
            out = scores.render(scores.build(scores.load([root])))
            self.assertIn("7/9 (spread 2)", out)
            self.assertRegex(out, r"gate-b: docs\s+8\s+7/9 \(spread 2\)")

    def test_last_keeps_the_newest_reviews(self):
        with tempfile.TemporaryDirectory() as root:
            for i in range(4):
                self.write(root, "trial-%d" % i, "b", "gate-b", [("docs", 7 + i % 2)], 100 + i)
            self.assertEqual([r["tag"] for r in scores.build(scores.load([root]), last=2)], ["trial-2", "trial-3"])

    def test_a_fetched_review_without_a_record_is_read_from_its_report(self):
        with tempfile.TemporaryDirectory() as root:
            d = os.path.join(root, "old-trial", "b")
            os.makedirs(d)
            with open(os.path.join(d, "REPORT.md"), "w") as f:
                f.write(part_b(docs=6))
            reviews = scores.build(scores.load([os.path.join(root, "old-trial")]))
            self.assertEqual(reviews[0]["items"][("gate-b", "docs")], [("b", 6)])

    def test_no_reviews_says_so(self):
        self.assertEqual(scores.render([]), "no scores yet\n")


if __name__ == "__main__":
    unittest.main()
