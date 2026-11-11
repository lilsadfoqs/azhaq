"""Tests for the control kind's brief, merge and records:
    python3 -m unittest discover -s .github/ci/range
"""
import difflib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import merge_gate  # noqa: E402
import render_brief  # noqa: E402
import scores  # noqa: E402

TRIAL = os.path.join(HERE, "..", "trial")
VARS = {"DOMAIN1": "a.test", "NET1": "10.0.0.0/24", "DNS1": "10.0.0.53"}


def gate(part):
    return render_brief.render_gate(part, "v9", VARS, TRIAL, "azhaq").split("\n")


def control(part):
    return render_brief.render_gate(part, "0.1.0", VARS, TRIAL, "azhaq", control=True).split("\n")


class ControlBrief(unittest.TestCase):
    def test_only_the_documented_lines_differ(self):
        # The documented changes (render_brief.py): the name, the first paragraph's claim, where the
        # candidate is, the install-script note and the safety-claim cap. Every other line is the gate's, in order.
        drop = render_brief.CONTROL_DROP[0]
        for part, changed, dropped in (("a", 4, 0), ("b", 6, 1)):
            g, c = gate(part), control(part)
            same = [line for line in g if "azhaq" not in line and not line.startswith(drop)]
            sm = difflib.SequenceMatcher(None, g, c, autojunk=False)
            kept = [line for tag, i1, i2, _, _ in sm.get_opcodes() if tag == "equal" for line in g[i1:i2]]
            self.assertEqual(same, [line for line in kept if "azhaq" not in line], part)
            self.assertEqual(len(g) - len(kept), changed + dropped, "lines of the gate's part %s that changed" % part)
            self.assertEqual(len(c), len(g) - dropped, part)
            # What changed in the gate is only a line naming azhaq, or the cap.
            for tag, i1, i2, _, _ in sm.get_opcodes():
                if tag != "equal":
                    for line in g[i1:i2]:
                        self.assertTrue("azhaq" in line or line.startswith(drop), line[:80])

    def test_the_claim_and_the_name(self):
        for part in ("a", "b"):
            text = "\n".join(control(part))
            self.assertNotIn("azhaq", text)
            self.assertNotIn("lilsadfoqs", text)
            self.assertNotIn("AI assistant", text)
            self.assertNotIn("snapshot build", text)
            self.assertIn("claims it can replace that stack: it is one front end over those same tools", text)
            self.assertIn("orvel (build 0.1.0)", text)

    def test_the_safety_cap_goes_and_nothing_else_of_the_rules(self):
        g, c = "\n".join(gate("b")), "\n".join(control("b"))
        self.assertIn("A safety claim that proves false", g)
        self.assertNotIn("A safety claim", c)
        self.assertNotIn("Safety claims are", c)
        for kept in ("An area cannot score above 6", "Mark each untested capability", "- **Subdomains:**", "- **Engagement controls:**"):
            self.assertIn(kept, c)

    def test_items_anchors_and_scorecard_format_are_the_gates(self):
        for part in ("a", "b"):
            g, c = gate(part), control(part)
            for marker in ("- 10: you would hand the job", "- 9: at least as good as your usual tools", "- 7 to 8:", "- 5 to 6:", "- 3 to 4:", "- 1 to 2:",
                           "columns `| Item | Score | Reasoning |`"):
                self.assertEqual([x for x in g if marker in x], [x for x in c if marker in x], marker)
        self.assertEqual([x for x in gate("a") if x.startswith("7. **Scorecard")], [x for x in control("a") if x.startswith("7. **Scorecard")])

    def test_where_the_candidate_is(self):
        a = "\n".join(control("a"))
        self.assertIn("orvel 0.1.0 is at ./bin/orvel, with the tools it runs installed beside it in ./bin (./bin/orvel-README.md lists them). "
                      "Use it as your main tool.", a)
        b = "\n".join(control("b"))
        self.assertIn("orvel (0.1.0) is at ./bin/orvel, with the tools it runs installed beside it in ./bin", b)
        self.assertIn("Installing it is not part of this review.\n", b)

    def test_a_placeholder_left_over_is_an_error(self):
        with self.assertRaises(ValueError) as e:
            render_brief.render_gate("a", "0.1.0", {}, TRIAL, "azhaq", control=True)
        self.assertIn("__DOMAIN1__", str(e.exception))

    def test_a_reworded_gate_is_noticed(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(TRIAL, "GATE.md"), encoding="utf-8") as f:
                text = f.read().replace("claims it can replace that stack", "says it can replace that stack")
            with open(os.path.join(d, "GATE.md"), "w", encoding="utf-8") as f:
                f.write(text)
            with self.assertRaises(ValueError):
                render_brief.render_gate("a", "1", VARS, d, "azhaq", control=True)

    def run_cli(self, kind, vars_json, extra=()):
        return subprocess.run([sys.executable, "-I", os.path.join(HERE, "render_brief.py"), kind, "0.1.0", vars_json, TRIAL, *extra],
                              capture_output=True, text=True)

    def test_the_cli_renders_both_parts_and_exits_one_on_a_placeholder(self):
        with tempfile.TemporaryDirectory() as d:
            ok, empty = os.path.join(d, "vars.json"), os.path.join(d, "empty.json")
            for path, data in ((ok, VARS), (empty, {})):
                with open(path, "w") as f:
                    json.dump(data, f)
            for kind in ("control-a", "control-b"):
                r = self.run_cli(kind, ok)
                self.assertEqual((r.returncode, r.stderr), (0, ""), kind)
                self.assertIn("orvel", r.stdout)
            r = self.run_cli("control-a", empty)
            self.assertEqual(r.returncode, 1)
            self.assertIn("placeholders left", r.stderr)
            self.assertEqual(self.run_cli("control-b", empty).returncode, 0)  # part B has none of the estate's
            self.assertEqual(self.run_cli("gate-a", ok, ["build"]).returncode, 0)  # the gate path is as it was


GATE_A = """| Item | Score | Reasoning |
|---|---|---|
| findings | 9 | a |
| time to the first finding | 8 | a |
| signal versus noise | 9 | a |
| trust | 9 | a |
| would use on the next engagement | 9 | a |
| overall (this part) | 9 | a |
"""
GATE_B = "| Item | Score | Reasoning |\n|---|---|---|\n" + "".join(
    "| %s | 9 | b |\n" % label for label in merge_gate.PART_B_ITEMS) + "| overall (this part) | 9 | b |\n"


class ControlMerge(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d, True)

    def write(self, name, text, kind=None):
        os.makedirs(os.path.join(self.d, name), exist_ok=True)
        with open(os.path.join(self.d, name, "REPORT.md"), "w") as f:
            f.write(text)
        if kind:
            with open(os.path.join(self.d, name, "scores.json"), "w") as f:
                json.dump({"kind": kind}, f)

    def merge(self, *args):
        r = subprocess.run([sys.executable, os.path.join(HERE, "merge_gate.py"), self.d, *args], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def samples(self, n, a_kind, b_kind):
        for k in range(1, n + 1):
            self.write("a%d" % k, GATE_A.replace("| 8 |", "| %d |" % (7 + k % 3)), a_kind)
            self.write("b%d" % k, GATE_B, b_kind)

    def test_a_control_folder_is_titled_and_has_no_gate_verdict(self):
        self.samples(4, "control-a", "control-b")
        out = self.merge("--samples", "4")
        self.assertTrue(out.startswith("# Control scorecard\n"), out[:60])
        self.assertNotIn("Gate scorecard", out)
        self.assertNotIn("PASS: every sample", out)
        self.assertIn("a measurement of the scale", out)
        self.assertIn("## Per-item medians", out)
        self.assertIn("There is no gate verdict", out)
        self.assertNotIn("the gate needs every one", out)
        for k in (1, 2, 3, 4):
            self.assertIn("## Scorecard (sample %d)" % k, out)

    def test_every_item_at_nine_is_said_plainly(self):
        self.samples(2, "control-a", "control-b")
        for k in (1, 2):
            self.write("a%d" % k, GATE_A.replace("| 8 |", "| 9 |"), "control-a")
        self.assertIn("every sample scored every item at 9 or more", self.merge())

    def test_one_sample_flat_folders_work_too(self):
        self.write("a", GATE_A, "control-a")
        self.write("b", GATE_B, "control-b")
        out = self.merge()
        self.assertTrue(out.startswith("# Control scorecard\n"))
        self.assertIn("| trust | 9 |", out)

    def test_the_control_flag_forces_it_without_records(self):
        self.samples(2, None, None)
        self.assertTrue(self.merge().startswith("# Gate scorecard\n"))
        self.assertTrue(self.merge("--control").startswith("# Control scorecard\n"))

    def test_a_gate_folder_is_unchanged(self):
        self.samples(2, "gate-a", "gate-b")
        out = self.merge()
        self.assertTrue(out.startswith("# Gate scorecard\n"))
        self.assertIn("not a pass", out)

    def test_a_missing_sample_is_still_named(self):
        self.samples(3, "control-a", "control-b")
        shutil.rmtree(os.path.join(self.d, "b2"))
        self.assertIn("sample 2 has part A only", self.merge())


class ControlRecords(unittest.TestCase):
    def write(self, root, tag, part, kind, items, when):
        d = os.path.join(root, "trial", tag, part)
        os.makedirs(d)
        rows = ["| Item | Score | Reasoning |", "|---|---|---|"] + ["| %s | %d | r |" % kv for kv in items] + ["| overall (this part) | 9 | r |"]
        with open(os.path.join(d, "scores.json"), "w") as f:
            json.dump(scores.extract("\n".join(rows) + "\n", kind, tag, part, now=when), f)

    def history(self, root, *args):
        r = subprocess.run([sys.executable, "-I", os.path.join(HERE, "scores.py"), "history", root, *args], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_extract_takes_the_control_kinds(self):
        text = GATE_A
        r = scores.extract(text, "control-a", "trial-c1", "a1")
        self.assertEqual((r["kind"], r["items"]["trust"], r["missing"]), ("control-a", 9, []))
        self.assertEqual(len(scores.extract(GATE_B, "control-b", "t", "b1")["items"]), 9)
        with tempfile.TemporaryDirectory() as d:
            rep, out = os.path.join(d, "REPORT.md"), os.path.join(d, "scores.json")
            with open(rep, "w") as f:
                f.write(GATE_A)
            self.assertEqual(scores.main(["extract", rep, "--kind", "control-a", "--tag", "t", "--out", out]), 0)

    def test_history_leaves_the_control_out_unless_asked(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "trial-gate1", "a1", "gate-a", [("trust", 7)], 100)
            self.write(root, "trial-control1", "a1", "control-a", [("trust", 9)], 200)
            self.write(root, "trial-control1", "b1", "control-b", [("docs", 8)], 201)
            default = self.history(root)
            self.assertIn("trial-gate1", default)
            self.assertNotIn("control", default)
            self.assertNotIn("docs", default)
            shown = self.history(root, "--with-control")
            self.assertIn("trial-control1", shown)
            self.assertIn("control-a: trust", shown)
            self.assertIn("control-b: docs", shown)
            self.assertIn("gate-a: trust", shown)

    def test_a_history_of_only_the_control_says_no_scores(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "trial-control1", "a1", "control-a", [("trust", 9)], 200)
            self.assertEqual(self.history(root), "no scores yet\n")

    def test_the_last_n_counts_gate_reviews_only(self):
        with tempfile.TemporaryDirectory() as root:
            self.write(root, "trial-g1", "a", "gate-a", [("trust", 7)], 100)
            self.write(root, "trial-g2", "a", "gate-a", [("trust", 8)], 200)
            self.write(root, "trial-c1", "a1", "control-a", [("trust", 9)], 300)
            out = self.history(root, "--last", "2")
            self.assertIn("trial-g1", out)
            self.assertIn("trial-g2", out)


if __name__ == "__main__":
    unittest.main()
