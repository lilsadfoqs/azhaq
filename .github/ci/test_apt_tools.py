import os
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "apt-tools.sh")

# dpkg-query reads the installed packages from $FAKE/installed; dpkg -i adds
# a deb's name (the file name up to the first underscore) unless $FAKE/dpkg-fails
# exists; apt-get update and install --download-only write to $FAKE/archives,
# apt-get install adds the packages; every call is logged.
DPKG_QUERY = """#!/bin/bash
grep -qxF "$4" "$FAKE/installed" && printf 'install ok installed' || exit 1
"""
DPKG = """#!/bin/bash
echo "dpkg $*" >> "$FAKE/calls"
[ -e "$FAKE/dpkg-fails" ] && exit 1
shift
for f in "$@"; do b=$(basename "$f"); echo "${b%%_*}" >> "$FAKE/installed"; done
"""
APT = """#!/bin/bash
echo "apt-get $*" >> "$FAKE/calls"
case "$1" in
update) [ -e "$FAKE/update-fails" ] && exit 1 ;;
install)
  shift
  dl=0; pk=()
  for a in "$@"; do case "$a" in --download-only) dl=1 ;; -*) ;; *) pk+=("$a") ;; esac; done
  if [ $dl = 1 ]; then for p in "${pk[@]}"; do echo deb > "$FAKE/archives/${p}_1_amd64.deb"; done
  else printf '%s\\n' "${pk[@]}" >> "$FAKE/installed"; fi ;;
esac
"""


class AptToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = self.tmp.name
        self.fake = os.path.join(t, "fake")
        self.debs = os.path.join(t, "debs")
        os.makedirs(os.path.join(self.fake, "archives"))
        open(os.path.join(self.fake, "installed"), "w").write("bind9-dnsutils\n")
        for name, body in (("dpkg-query", DPKG_QUERY), ("dpkg", DPKG), ("apt-get", APT)):
            path = os.path.join(t, name)
            with open(path, "w") as f:
                f.write(body)
            os.chmod(path, 0o755)
        self.env = {**os.environ, "FAKE": self.fake, "SUDO": "", "DPKG": os.path.join(t, "dpkg"), "APT_GET": os.path.join(t, "apt-get"),
                    "DPKG_QUERY": os.path.join(t, "dpkg-query"), "APT_ARCHIVES": os.path.join(self.fake, "archives")}

    def run_script(self, *args):
        return subprocess.run(["bash", SCRIPT, *args], env=self.env, capture_output=True, text=True)

    def calls(self):
        p = os.path.join(self.fake, "calls")
        return open(p).read().splitlines() if os.path.exists(p) else []

    def installed(self):
        return open(os.path.join(self.fake, "installed")).read().split()

    def test_usage(self):
        self.assertNotEqual(self.run_script().returncode, 0)
        self.assertNotEqual(self.run_script(self.debs).returncode, 0)

    def test_deb_files_install_without_apt(self):
        os.makedirs(self.debs)
        for n in ("nmap", "nmap-common"):
            open(os.path.join(self.debs, n + "_7_amd64.deb"), "w").write("deb")
        r = self.run_script(self.debs, "nmap", "bind9-dnsutils")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c.split()[0] for c in self.calls()], ["dpkg"])
        self.assertIn("nmap", self.installed())

    def test_nothing_to_do_when_installed(self):
        r = self.run_script(self.debs, "bind9-dnsutils")
        self.assertEqual((r.returncode, self.calls()), (0, []))

    def test_without_files_apt_installs_and_keeps_the_debs(self):
        open(os.path.join(self.fake, "archives", "preexisting_1_amd64.deb"), "w").write("old")
        r = self.run_script(self.debs, "nmap", "age")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c.split()[1] for c in self.calls()], ["update", "install", "install"])
        self.assertEqual(sorted(os.listdir(self.debs)), ["age_1_amd64.deb", "nmap_1_amd64.deb"])  # not the image's own
        self.assertTrue({"nmap", "age"} <= set(self.installed()))

    def test_failing_dpkg_falls_back_to_apt(self):
        os.makedirs(self.debs)
        open(os.path.join(self.debs, "nmap_7_amd64.deb"), "w").write("deb")
        open(os.path.join(self.fake, "dpkg-fails"), "w").close()
        r = self.run_script(self.debs, "nmap")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.calls()[0].split()[0], "dpkg")
        self.assertIn("apt-get update -q", self.calls())
        self.assertIn("nmap", self.installed())

    def test_files_that_lack_a_package_fall_back_for_that_package(self):
        os.makedirs(self.debs)
        open(os.path.join(self.debs, "nmap_7_amd64.deb"), "w").write("deb")
        r = self.run_script(self.debs, "nmap", "age")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue({"nmap", "age"} <= set(self.installed()))
        self.assertTrue(any(c.startswith("apt-get install") and c.endswith("age") for c in self.calls()))
        self.assertFalse(any(c.startswith("apt-get install") and "nmap" in c for c in self.calls()))


if __name__ == "__main__":
    unittest.main()
