import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import bench_plan  # noqa: E402
import bench_times  # noqa: E402

LOG = """bench: building azhaq
bench: default: apps
bench: default: apps took 345s
bench: polite: dirs took 212s
bench: once: dropin took 31s
bench: claims: case 5 took 194s
bench: claims: case 5 took 190s
bench: claims: case 10 took 56s
bench: default: domains
bench: some other took 9s
"""


class TimesTest(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(
            bench_times.parse(LOG),
            {"default:apps": 345, "polite:dirs": 212, "once:dropin": 31, "claims:5": 190, "claims:10": 56},
        )

    def test_base_keeps_untimed_units(self):
        with tempfile.TemporaryDirectory() as d:
            log, base = os.path.join(d, "log"), os.path.join(d, "base.json")
            with open(log, "w") as f:
                f.write(LOG)
            with open(base, "w") as f:
                json.dump({"once:docs": 20, "default:apps": 1}, f)
            out = subprocess.run([sys.executable, os.path.join(HERE, "bench_times.py"), log, "--base", base], capture_output=True, text=True, check=True).stdout
            got = json.loads(out)
            self.assertEqual(got["once:docs"], 20)
            self.assertEqual(got["default:apps"], 345)
            self.assertEqual(list(got), sorted(got))

    def test_committed_times_cover_the_measured_units(self):
        with open(os.path.join(HERE, "bench-times.json")) as f:
            times = json.load(f)
        for u in ("default:apps", "polite:domains", "claims:5"):
            self.assertIn(u, times)
        self.assertTrue(all(isinstance(v, int) and v > 0 for v in times.values()))


class PlanTest(unittest.TestCase):
    def test_longest_first_to_the_least_loaded(self):
        times = {"a": 100, "b": 60, "c": 50, "d": 40, "e": 30}
        # a -> job 1, b -> job 2, c -> job 2 (60 < 100), d -> job 1 (100 < 110), e -> job 2 (110 < 140)
        self.assertEqual(bench_plan.pack(list(times), times, 2), [[140, ["a", "d"]], [140, ["b", "c", "e"]]])

    def test_unknown_unit_counts_sixty(self):
        jobs = bench_plan.pack(["x", "y"], {"x": 10}, 1)
        self.assertEqual(jobs, [[70, ["y", "x"]]])

    def test_never_more_jobs_than_units_or_max(self):
        self.assertEqual(len(bench_plan.pack(["a", "b"], {}, 10)), 2)
        self.assertEqual(len(bench_plan.pack(list("abcdefg"), {}, 3)), 3)

    def test_every_unit_once_and_a_bound_on_the_longest(self):
        times = {f"u{i}": 10 * (i % 7) + 5 for i in range(40)}
        jobs = bench_plan.pack(list(times) + ["u1"], times, 6)  # a repeated name counts once
        packed = [u for _, us in jobs for u in us]
        self.assertEqual(sorted(packed), sorted(times))
        total, biggest = sum(times.values()), max(times.values())
        self.assertLessEqual(jobs[0][0], total / 6 + biggest)  # the LPT guarantee
        self.assertEqual(sum(t for t, _ in jobs), total)

    def test_matrix_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            tf = os.path.join(d, "t.json")
            with open(tf, "w") as f:
                json.dump({"default:apps": 345, "claims:5": 194}, f)
            r = subprocess.run(
                [sys.executable, os.path.join(HERE, "bench_plan.py"), "--times", tf, "--max-parts", "2"],
                input="default:apps\nclaims:5\nonce:docs\n", capture_output=True, text=True, check=True,
            )
            m = json.loads(r.stdout)
            self.assertEqual([p["name"] for p in m], ["p1", "p2"])
            self.assertEqual(m[0], {"name": "p1", "units": "default:apps", "seconds": 345})
            self.assertEqual(m[1]["units"], "claims:5,once:docs")
            self.assertIn("once:docs", r.stderr)
            empty = subprocess.run([sys.executable, os.path.join(HERE, "bench_plan.py"), "--times", tf], input="", capture_output=True, text=True)
            self.assertNotEqual(empty.returncode, 0)


if __name__ == "__main__":
    unittest.main()
