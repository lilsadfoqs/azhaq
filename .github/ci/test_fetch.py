import json
import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

CURL = r"""#!/bin/bash
# A stand-in for curl: the GitHub contents API and raw files, served from $FX/repo.
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
"""

# A stand-in for age: -d -i KEY -o OUT IN copies IN to OUT.
AGE = """#!/bin/bash
while [ $# -gt 0 ]; do case $1 in -o) out=$2; shift 2;; -i) shift 2;; -d) shift;; *) in=$1; shift;; esac; done
cp "$in" "$out"
"""


class FetchGate(unittest.TestCase):
    PARTS = ("a1", "a2", "a3", "a4", "b1", "b2", "b3", "b4")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.fx = os.path.join(t, "fx")
        self.publish(self.PARTS)
        self.bin = os.path.join(t, "bin")
        os.makedirs(self.bin)
        for name, body in (("curl", CURL), ("age", AGE)):
            path = os.path.join(self.bin, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.work = os.path.join(t, "work")
        os.makedirs(self.work)
        os.makedirs(os.path.join(t, "home"))
        open(os.path.join(t, "key"), "w").close()

    def publish(self, parts, name="trial-20"):
        t = self.tmp.name
        for part in parts:
            d = os.path.join(self.fx, "repo", "trial", name, part)
            os.makedirs(d)
            with open(os.path.join(d, "scores.json.age"), "w") as f:
                json.dump({"part": part}, f)
            with open(os.path.join(d, "key.json.age"), "w") as f:
                f.write("{}")
            pack = os.path.join(t, "pack")
            os.makedirs(pack, exist_ok=True)
            with open(os.path.join(pack, "REPORT.md"), "w") as f:
                f.write("report " + part)
            subprocess.run(["tar", "-czf", os.path.join(d, "trial.tgz.age"), "-C", pack, "REPORT.md"], check=True)

    def tearDown(self):
        self.tmp.cleanup()

    def fetch(self, dest, *, tag=None, name="20"):
        env = dict(os.environ, FX=self.fx, HOME=os.path.join(self.tmp.name, "home"),
                   AZHAQ_AGE_KEY=os.path.join(self.tmp.name, "key"),
                   PATH=self.bin + os.pathsep + os.environ["PATH"])
        env.pop("FETCH_TAG", None)
        if tag:
            env["FETCH_TAG"] = tag
        return subprocess.run(["bash", os.path.join(HERE, "fetch.sh"), "trial", name, dest],
                              cwd=self.work, env=env, capture_output=True, text=True)

    def check_parts(self, root, parts=PARTS):
        self.assertEqual(sorted(p for p in os.listdir(root) if os.path.isdir(os.path.join(root, p))), sorted(parts))
        for part in parts:
            d = os.path.join(root, part)
            with open(os.path.join(d, "scores.json")) as f:
                self.assertEqual(json.load(f), {"part": part})  # decrypted as JSON, not unpacked
            with open(os.path.join(d, "REPORT.md")) as f:
                self.assertEqual(f.read(), "report " + part)  # the archive after it is unpacked
            self.assertTrue(os.path.exists(os.path.join(d, "key.json")))

    def test_every_part_into_dir_part(self):
        dest = os.path.join(self.work, "abs")
        r = self.fetch(dest)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_parts(dest)

    def test_one_and_two_samples_bring_back_their_parts_only(self):
        self.publish(("a", "b"), "trial-21")
        self.publish(("a1", "a2", "b1", "b2"), "trial-22")
        for name, parts in (("21", ("a", "b")), ("22", ("a1", "a2", "b1", "b2"))):
            dest = os.path.join(self.work, "t" + name)
            r = self.fetch(dest, name=name)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.check_parts(dest, parts)

    def test_relative_dir_is_not_nested(self):
        r = self.fetch("out")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.check_parts(os.path.join(self.work, "out"))
        self.assertFalse(os.path.exists(os.path.join(self.work, "out", "out")))

    def test_one_part_by_tag(self):
        r = self.fetch("one", tag="trial-20/a4")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(os.path.exists(os.path.join(self.work, "one", "REPORT.md")))


class Watch(unittest.TestCase):
    """watch.sh against a stand-in for ci-results: queued samples must hold a run back from "done"."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = self.tmp.name
        self.fx = os.path.join(t, "fx")
        os.makedirs(os.path.join(t, "bin"))
        with open(os.path.join(t, "bin", "curl"), "w") as f:
            f.write(CURL)
        os.chmod(os.path.join(t, "bin", "curl"), 0o755)

    def tearDown(self):
        self.tmp.cleanup()

    def done(self, *parts):
        for part in parts:
            d = os.path.join(self.fx, "repo", "trial", "trial-30", part)
            os.makedirs(d, exist_ok=True)
            open(os.path.join(d, "trial.tgz.age"), "w").close()

    def watch(self, expect=""):
        env = dict(os.environ, FX=self.fx, POLL="1", DEADLINE="1", WATCH_EXPECT=expect,
                   PATH=os.path.join(self.tmp.name, "bin") + os.pathsep + os.environ["PATH"])
        return subprocess.run(["bash", os.path.join(HERE, "watch.sh"), "trial-30"], env=env, capture_output=True, text=True)

    def test_every_part_of_four_samples_is_seen(self):
        self.done("a1", "a2", "a3", "a4", "b1", "b2", "b3", "b4")
        r = self.watch("a1 a2 a3 a4 b1 b2 b3 b4")
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "trial-30: done"))

    def test_a_queued_sample_keeps_the_run_going(self):
        self.done("a1", "a2", "b1", "b2")  # a3, a4, b3, b4 wait for a free slot
        r = self.watch("a1 a2 a3 a4 b1 b2 b3 b4")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not started yet: a3 a4 b3 b4", r.stdout)

    def test_without_an_expectation_the_parts_seen_decide(self):
        self.done("a", "b")
        r = self.watch()
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "trial-30: done"))


if __name__ == "__main__":
    unittest.main()
