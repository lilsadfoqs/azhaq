import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shard  # noqa: E402


class ListTests(unittest.TestCase):
    def test_names(self):
        src = (
            "package x\n"
            "func TestA(t *testing.T) {}\n"
            "func Test_b(t *testing.T) {}\n"
            "func Test9(t *testing.T) {}\n"
            "func Test(t *testing.T) {}\n"
            "func TestÉcole(t *testing.T) {}\n"
            "func ExampleFoo() {}\n"
            "func FuzzBar(f *testing.F) {}\n"
            "func Testing(t *testing.T) {}\n"
            "func testHelper(t *testing.T) {}\n"
            "func TestWithGeneric[T any](t *testing.T) {}\n"
            "func (s *S) TestMethod(t *testing.T) {}\n"
            "  func TestIndented(t *testing.T) {}\n"
        )
        self.assertEqual(
            shard.list_tests(src),
            ["TestA", "Test_b", "Test9", "Test", "TestÉcole", "ExampleFoo", "FuzzBar"],
        )

    def test_package_tests_reads_files_once(self):
        with tempfile.TemporaryDirectory() as d:
            for name, body in (("a_test.go", "func TestA(t *testing.T) {}\n"),
                               ("b_test.go", "func TestA(t *testing.T) {}\nfunc TestB(t *testing.T) {}\n")):
                with open(os.path.join(d, name), "w") as f:
                    f.write(body)
            self.assertEqual(shard.package_tests(d, ["b_test.go", "a_test.go"]), ["TestA", "TestB"])


INV = {
    "big": ["T%d" % i for i in range(10)],
    "small": ["A", "B"],
    "tiny": ["C"],
    "new": ["D", "E"],
}
TIMES = {
    "big": {"T%d" % i: 10.0 for i in range(10)},
    "small": {"A": 3.0, "B": 2.0},
    "tiny": {"C": 0.5},
}


class Plan(unittest.TestCase):
    def test_every_test_once(self):
        for n in (1, 2, 3, 6, 20):
            p = shard.plan(INV, TIMES, n)
            self.assertEqual(shard.check(INV, p), [], n)

    def test_deterministic(self):
        self.assertEqual(shard.plan(INV, TIMES, 4), shard.plan(dict(reversed(INV.items())), TIMES, 4))

    def test_big_package_is_split_small_ones_whole(self):
        p = shard.plan(INV, TIMES, 4)
        split = {k for s in p for k in s["split"]}
        whole = {k for s in p for k in s["whole"]}
        self.assertEqual(split, {"big"})
        self.assertEqual(whole, {"small", "tiny", "new"})

    def test_balanced(self):
        p = shard.plan(INV, TIMES, 4)
        loads = sorted(s["load"] for s in p)
        self.assertLessEqual(loads[-1] - loads[0], 10.0)

    def test_missing_costs(self):
        self.assertEqual(shard.test_cost("nope", "X", TIMES), 1.0)
        self.assertEqual(shard.test_cost("small", "Z", TIMES), 2.5)  # the median
        self.assertEqual(shard.test_cost("small", "A", TIMES), 3.0)

    def test_new_test_in_a_split_package_is_counted(self):
        inv = {"big": INV["big"] + ["New"]}
        p = shard.plan(inv, TIMES, 3)
        self.assertEqual(shard.check(inv, p), [])
        self.assertEqual(sum(s["load"] for s in p), 100.0 + 10.0)

    def test_check_finds_a_lost_and_a_doubled_test(self):
        p = shard.plan(INV, TIMES, 2)
        p[0]["split"]["big"].remove(p[0]["split"]["big"][0])
        self.assertEqual(len(shard.check(INV, p)), 1)
        p[1]["whole"].append("tiny")
        p[0]["whole"].append("tiny")
        self.assertEqual(len(shard.check(INV, p)), 2)


class RunArgs(unittest.TestCase):
    def test_args(self):
        self.assertEqual(shard.run_args(["a", "."]), ["go", "test", "-race", "-json", "./a", "."])
        self.assertEqual(
            shard.run_args(["a"], ["T1", "T2"], fresh=True),
            ["go", "test", "-race", "-json", "-count=1", "-run", "^(T1|T2)$", "./a"],
        )

    def test_batches_cut_by_time_in_name_order(self):
        times = {"p": {"A": 15, "B": 10, "C": 30, "D": 1}}
        self.assertEqual(shard.batches("p", ["D", "C", "B", "A"], times, limit=20),
                         [["A"], ["B"], ["C"], ["D"]])
        self.assertEqual(shard.batches("p", ["A", "D"], times, limit=20), [["A", "D"]])
        self.assertEqual(shard.batches("p", [], times), [])

    def test_relpath(self):
        self.assertEqual(shard.relpath("m/x", "m"), "x")
        self.assertEqual(shard.relpath("m", "m"), ".")


def events(*es):
    return [json.dumps(e) + "\n" for e in es]


class Events(unittest.TestCase):
    def feed(self, lines):
        out = io.StringIO()
        r = shard.Run("m", out)
        for l in lines:
            r.line(l)
        return r, out.getvalue()

    def test_pass_records_times(self):
        r, out = self.feed(events(
            {"Action": "run", "Package": "m/a", "Test": "TestA"},
            {"Action": "output", "Package": "m/a", "Test": "TestA", "Output": "--- PASS: TestA (0.10s)\n"},
            {"Action": "pass", "Package": "m/a", "Test": "TestA", "Elapsed": 0.1},
            {"Action": "pass", "Package": "m/a", "Test": "TestA/sub", "Elapsed": 0.05},
            {"Action": "pass", "Package": "m/a", "Elapsed": 0.4},
            {"Action": "skip", "Package": "m/none", "Elapsed": 0},
        ))
        self.assertFalse(r.failed)
        self.assertEqual(r.tests, {"a": {"TestA": 0.1}})
        self.assertEqual(r.packages, {"a": 0.4})
        self.assertEqual(out, "--- PASS: TestA (0.10s)\n")

    def test_fail_and_build_output(self):
        r, out = self.feed(events(
            {"ImportPath": "m/a [m/a.test]", "Action": "build-output", "Output": "a.go:1: bad\n"},
            {"ImportPath": "m/a [m/a.test]", "Action": "build-fail"},
        ) + ["# m/a\n"])
        self.assertTrue(r.failed)
        self.assertEqual(out, "a.go:1: bad\n# m/a\n")

    def test_test_fail(self):
        r, _ = self.feed(events({"Action": "fail", "Package": "m/a", "Test": "TestA", "Elapsed": 1}))
        self.assertTrue(r.failed)
        self.assertEqual(r.tests["a"]["TestA"], 1)


class Annotations(unittest.TestCase):
    def test_race_frames_first(self):
        log = "\n".join([
            "=== RUN TestX",
            "WARNING: DATA RACE",
            "Write at 0x00c000 by goroutine 8:",
            "  github.com/trannghiach/azhaq/internal/x.f()",
            "      /src/x.go:10 +0x1",
            "Previous read at 0x00c000 by goroutine 7:",
            "--- FAIL: TestX (0.01s)",
            "    x_test.go:12: boom",
            "FAIL",
        ])
        a = shard.annotations(log)
        self.assertEqual(a[0], "::error::Write at 0x00c000 by goroutine 8:")
        self.assertIn("::error::  github.com/trannghiach/azhaq/internal/x.f()", a)
        self.assertIn("::error::--- FAIL: TestX (0.01s)", a)
        self.assertIn("::error::    x_test.go:12: boom", a)
        self.assertLess(a.index("::error::Write at 0x00c000 by goroutine 8:"), a.index("::error::--- FAIL: TestX (0.01s)"))

    def test_escapes_percent(self):
        self.assertEqual(shard.annotations("--- FAIL: 100%\n"), ["::error::--- FAIL: 100%25"])

    def test_none(self):
        self.assertEqual(shard.annotations("ok  \tm/a\t0.1s\n"), [])


class Refresh(unittest.TestCase):
    def test_merges_shards_and_keeps_other_packages(self):
        with tempfile.TemporaryDirectory() as d:
            for i, tests in enumerate(({"big": {"T1": 1.234}}, {"big": {"T2": 2.0}, "other": {"X": 3.0}})):
                os.makedirs(os.path.join(d, "times-%d" % i))
                with open(os.path.join(d, "times-%d" % i, "times-%d.json" % i), "w") as f:
                    json.dump({"shard": i, "packages": {}, "tests": tests}, f)
            path = os.path.join(d, "test-times.json")
            with open(path, "w") as f:
                json.dump({"big": {"Gone": 9}, "kept": {"K": 1}}, f)
            self.assertEqual(shard.refresh(d, path), 0)
            with open(path) as f:
                got = json.load(f)
        self.assertEqual(got, {"big": {"T1": 1.23, "T2": 2.0}, "other": {"X": 3.0}, "kept": {"K": 1}})


if __name__ == "__main__":
    unittest.main()
