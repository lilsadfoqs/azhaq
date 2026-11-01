import io
import json
import os
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
LATEST = os.path.join(HERE, "latest-artifact.sh")
TOOLS = os.path.join(HERE, "bench-tools.sh")
OLD = 1_600_000_000

STUB = """#!/bin/bash
# a gh that answers the two calls latest-artifact.sh makes
echo "$*" >> "$FAKE/calls"
case "$2" in
*/zip) id=$(basename "$(dirname "$2")"); cat "$FAKE/$id.zip" || exit 1 ;;
*) [ -f "$FAKE/list.json" ] && cat "$FAKE/list.json" || exit 1 ;;
esac
"""


def tar_bytes(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, (data, mode) in files.items():
            ti = tarfile.TarInfo(name)
            ti.size, ti.mode, ti.mtime = len(data), mode, OLD
            t.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def zip_file(path, members):
    with zipfile.ZipFile(path, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)


class LatestArtifactTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.fake = os.path.join(self.tmp.name, "fake")
        bindir = os.path.join(self.tmp.name, "bin")
        os.makedirs(self.fake)
        os.makedirs(bindir)
        gh = os.path.join(bindir, "gh")
        with open(gh, "w") as f:
            f.write(STUB)
        os.chmod(gh, 0o755)
        self.env = {**os.environ, "PATH": bindir + os.pathsep + os.environ["PATH"], "FAKE": self.fake, "GITHUB_REPOSITORY": "o/r"}
        self.dest = os.path.join(self.tmp.name, "dest")

    def listing(self, *arts):
        with open(os.path.join(self.fake, "list.json"), "w") as f:
            json.dump({"artifacts": [{"id": i, "name": n, "expired": e} for i, n, e in arts]}, f)

    def run_script(self, *args):
        return subprocess.run(["bash", LATEST, *args], env=self.env, capture_output=True, text=True)

    def test_arguments_are_required(self):
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertNotEqual(self.run_script("name").returncode, 0)
        env = {k: v for k, v in self.env.items() if k != "GITHUB_REPOSITORY"}
        r = subprocess.run(["bash", LATEST, "n", self.dest], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    def test_newest_unexpired_is_unpacked_with_modes_and_times(self):
        self.listing((9, "bench-ref-x", True), (7, "bench-ref-x", False), (5, "bench-ref-x", False), (8, "other", False))
        good = tar_bytes({"bin/tool": (b"#!/bin/sh\n", 0o755), "k/run.json": (b"{}", 0o644)})
        zip_file(os.path.join(self.fake, "7.zip"), {"artifact.tar": good})
        zip_file(os.path.join(self.fake, "5.zip"), {"artifact.tar": tar_bytes({"bin/old": (b"x", 0o644)})})
        r = self.run_script("bench-ref-x", self.dest)
        self.assertEqual(r.returncode, 0, r.stderr)
        tool = os.path.join(self.dest, "bin", "tool")
        self.assertTrue(os.stat(tool).st_mode & stat.S_IXUSR)
        self.assertEqual(int(os.stat(tool).st_mtime), OLD)
        self.assertFalse(os.path.exists(os.path.join(self.dest, "bin", "old")))
        with open(os.path.join(self.fake, "calls")) as f:
            self.assertIn("actions/artifacts?name=bench-ref-x", f.read())

    def test_a_miss_is_not_a_failure(self):
        for setup in (
            lambda: None,  # the listing call fails
            lambda: self.listing(),  # no artifacts
            lambda: self.listing((3, "n", True)),  # only an expired one
            lambda: self.listing((4, "n", False)),  # the download fails
            lambda: (self.listing((6, "n", False)), zip_file(os.path.join(self.fake, "6.zip"), {"other": b"x"})),  # no tar
            lambda: (self.listing((2, "n", False)), open(os.path.join(self.fake, "2.zip"), "w").write("not a zip")),
        ):
            for f in os.listdir(self.fake):
                os.remove(os.path.join(self.fake, f))
            setup()
            r = self.run_script("n", self.dest)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("going on without it", r.stdout)
            self.assertFalse(os.path.exists(os.path.join(self.dest, "bin")))


class BenchToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = os.path.join(self.tmp.name, "work")
        for p, body in {"bin/katana": "k", "bin/azhaq": "a", "bin/.katana-1": "", "debs/nmap_7_amd64.deb": "d", "arjun-2/bin/arjun": "j", "common.txt": "w", "paths.txt": "not kept"}.items():
            path = os.path.join(self.work, p)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                f.write(body)
        self.env = {**os.environ, "WORK": self.work}

    def sh(self, *args):
        return subprocess.run(["bash", TOOLS, *args], env=self.env, capture_output=True, text=True, cwd=self.tmp.name)

    def test_list_names_what_is_kept(self):
        r = self.sh("list")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.split(), ["arjun-2/bin/arjun", "bin/.katana-1", "bin/katana", "common.txt", "debs/nmap_7_amd64.deb"])

    def test_pack_makes_an_artifact_tar_without_azhaq(self):
        r = self.sh("pack", "out/dir")  # relative to the caller, not to the work folder
        self.assertEqual(r.returncode, 0, r.stderr)
        with tarfile.open(os.path.join(self.tmp.name, "out/dir/artifact.tar")) as t:
            names = sorted(m.name for m in t.getmembers() if m.isfile())
        self.assertEqual(names, ["arjun-2/bin/arjun", "bin/.katana-1", "bin/katana", "common.txt", "debs/nmap_7_amd64.deb"])

    def test_nothing_to_keep_and_usage(self):
        self.env["WORK"] = os.path.join(self.tmp.name, "none")
        self.assertEqual((self.sh("list").returncode, self.sh("list").stdout), (0, ""))
        self.assertEqual(self.sh("bogus").returncode, 2)


if __name__ == "__main__":
    unittest.main()
