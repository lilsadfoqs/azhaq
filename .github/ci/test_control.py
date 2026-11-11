"""Tests for the control kind's candidate (control/orvel, install-stack.sh, README.md),
its place in trial.yml and run.sh:
    python3 -m unittest discover -s .github/ci -p "test_*.py"
No real tool is installed or run: stubs stand in for the stack.
"""
import hashlib
import io
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
CONTROL = os.path.join(HERE, "control")
ROOT = os.path.join(HERE, "..", "..")
SUBS = {"subs": "subfinder", "resolve": "dnsx", "probe": "httpx", "crawl": "katana", "fuzz": "ffuf", "params": "arjun",
        "urls": "gau", "ports": "naabu", "scan": "nmap", "vulns": "nuclei", "shots": "gowitness"}


def table(path=os.path.join(CONTROL, "stack.tsv")):
    rows = []
    with open(path) as f:
        for line in f:
            if line.strip() and not line.startswith("#"):
                rows.append(line.rstrip("\n").split("\t"))
    return rows


# A stand-in for every tool: logs its name and arguments, writes $CANNED/NAME to the file after -o,
# exits with $RC_NAME.
FAKE = """#!/bin/sh
n=$(basename "$0")
echo "$n $*" >> "$LOG"
out=""
while [ $# -gt 0 ]; do [ "$1" = -o ] && out=$2; shift; done
[ -n "$out" ] && [ -f "$CANNED/$n" ] && cat "$CANNED/$n" > "$out"
eval "exit \\${RC_$n:-0}"
"""

CANNED = {
    "subfinder": '{"host":"www.example.test","input":"example.test","source":["x"]}\n{"host":"api.example.test","input":"example.test"}\n',
    "dnsx": '{"host":"www.example.test","a":["10.0.0.1"]}\n{"host":"example.test","a":["10.0.0.2"]}\n',
    "naabu": '{"ip":"10.0.0.1","port":80}\n{"host":"example.test","ip":"10.0.0.2","port":8080}\n',
    "httpx": '{"url":"http://10.0.0.1:80","status_code":200}\n{"url":"http://example.test:8080","status_code":404}\n',
    "katana": '{"request":{"endpoint":"http://10.0.0.1:80/a"}}\n',
}


class Orvel(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = os.path.join(self.tmp, "bin")
        os.makedirs(self.bin)
        shutil.copy(os.path.join(CONTROL, "orvel"), self.bin)
        shutil.copy(os.path.join(CONTROL, "stack.tsv"), os.path.join(self.bin, "orvel-stack.tsv"))
        self.canned = os.path.join(self.tmp, "canned")
        os.makedirs(self.canned)
        for name, text in CANNED.items():
            with open(os.path.join(self.canned, name), "w") as f:
                f.write(text)
        self.log = os.path.join(self.tmp, "log")
        for tool in SUBS.values():
            p = os.path.join(self.bin, tool)
            with open(p, "w") as f:
                f.write(FAKE)
            os.chmod(p, 0o755)

    def orvel(self, *args, env=None, cwd=None):
        e = dict(os.environ, LOG=self.log, CANNED=self.canned, PATH="/usr/bin:/bin")
        e.update(env or {})
        return subprocess.run([os.path.join(self.bin, "orvel"), *args], capture_output=True, text=True, env=e, cwd=cwd or self.tmp)

    def calls(self):
        try:
            with open(self.log) as f:
                return f.read().splitlines()
        except OSError:
            return []

    def test_each_subcommand_runs_its_tool_with_the_arguments_unchanged(self):
        for sub, tool in SUBS.items():
            r = self.orvel(sub, "-d", "a b", "--flag=1", "x*")
            self.assertEqual(r.returncode, 0, (sub, r.stderr))
            self.assertEqual(self.calls()[-1], "%s -d a b --flag=1 x*" % tool, sub)

    def test_the_exit_code_is_the_tools(self):
        for rc in (0, 1, 3, 7, 130):
            r = self.orvel("scan", "-sV", env={"RC_nmap": str(rc)})
            self.assertEqual(r.returncode, rc)

    def test_the_tools_beside_it_win_over_the_path(self):
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        with open(os.path.join(other, "dnsx"), "w") as f:
            f.write("#!/bin/sh\necho from-path\n")
        os.chmod(os.path.join(other, "dnsx"), 0o755)
        r = self.orvel("resolve", env={"PATH": other + ":/usr/bin:/bin"})
        self.assertEqual(r.stdout, "")
        self.assertEqual(self.calls(), ["dnsx "])

    def test_a_missing_tool_and_an_unknown_subcommand(self):
        os.remove(os.path.join(self.bin, "ffuf"))
        r = self.orvel("fuzz", "-u", "x")
        self.assertEqual(r.returncode, 127)
        self.assertIn("ffuf is not installed", r.stderr)
        r = self.orvel("nonsense")
        self.assertEqual(r.returncode, 2)
        self.assertIn("unknown subcommand", r.stderr)

    def test_help_and_version_say_what_it_is_and_list_every_tool(self):
        for args in (("help",), ("-h",), ()):
            r = self.orvel(*args)
            self.assertEqual(r.returncode, 0)
            self.assertIn("a front end over the usual recon tools", r.stdout)
            self.assertIn("tools' own documentation applies", r.stdout)
            self.assertIn("no scope enforcement, no request ledger, no\nsafety features", r.stdout)
            for sub, tool in SUBS.items():
                self.assertRegex(r.stdout, r"\n  %s +%s " % (sub, tool))
            self.assertIn("run TARGET...", r.stdout)
        r = self.orvel("version")
        self.assertTrue(r.stdout.startswith("orvel 0.1.0 "), r.stdout)
        for sub, tool, version, *_ in table():
            self.assertRegex(r.stdout, r"\n  %s +%s +%s" % (sub, tool, "" if version == "apt" else re.escape(version)))

    def test_run_chains_the_five_tools_and_writes_each_output(self):
        r = self.orvel("run", "example.test", env={"ORVEL_OUT": "out"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([c.split()[0] for c in self.calls()], ["subfinder", "dnsx", "naabu", "httpx", "katana"])
        calls = self.calls()
        self.assertIn("naabu -list out/resolved.txt -top-ports 100 -silent -json -o out/naabu.jsonl", calls[2])
        out = os.path.join(self.tmp, "out")
        for f in ("subfinder.jsonl", "dnsx.jsonl", "naabu.jsonl", "httpx.jsonl", "katana.jsonl"):
            self.assertGreater(os.path.getsize(os.path.join(out, f)), 0, f)
        with open(os.path.join(out, "hostports.txt")) as f:
            self.assertEqual(f.read().split(), ["10.0.0.1:80", "example.test:8080"])
        with open(os.path.join(out, "hosts.txt")) as f:
            self.assertEqual(f.read().split(), ["api.example.test", "example.test", "www.example.test"])
        with open(os.path.join(out, "urls.txt")) as f:
            self.assertEqual(f.read().split(), ["http://10.0.0.1:80", "http://example.test:8080"])
        self.assertIn("results in out", r.stderr)
        self.assertIn("naabu.jsonl", r.stdout)

    def test_run_names_a_folder_by_the_date_when_none_is_given(self):
        r = self.orvel("run", "example.test")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue([d for d in os.listdir(self.tmp) if d.startswith("orvel-run-")])

    def test_an_address_skips_subfinder_and_goes_to_naabu(self):
        r = self.orvel("run", "10.0.0.0/30", env={"ORVEL_OUT": "out"})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual([c.split()[0] for c in self.calls()], ["naabu", "httpx", "katana"])
        with open(os.path.join(self.tmp, "out", "resolved.txt")) as f:
            self.assertEqual(f.read().split(), ["10.0.0.0/30"])

    def test_a_failing_stage_stops_the_run_with_its_exit_code(self):
        r = self.orvel("run", "example.test", env={"ORVEL_OUT": "out", "RC_dnsx": "3"})
        self.assertEqual(r.returncode, 3)
        self.assertEqual([c.split()[0] for c in self.calls()], ["subfinder", "dnsx"])
        self.assertIn("dnsx exited 3; stopping", r.stderr)

    def test_a_stage_that_finds_nothing_stops_the_run_and_says_so(self):
        os.remove(os.path.join(self.canned, "dnsx"))
        r = self.orvel("run", "example.test", env={"ORVEL_OUT": "out"})
        self.assertEqual(r.returncode, 0)
        self.assertEqual([c.split()[0] for c in self.calls()], ["subfinder", "dnsx"])
        self.assertIn("resolve found nothing; stopping", r.stderr)

    def test_run_without_a_target_is_a_usage_error(self):
        self.assertEqual(self.orvel("run").returncode, 2)

    def test_run_needs_a_missing_tool_to_say_so(self):
        os.remove(os.path.join(self.bin, "katana"))
        r = self.orvel("run", "example.test", env={"ORVEL_OUT": "out"})
        self.assertEqual(r.returncode, 127)
        self.assertIn("katana is not installed", r.stderr)


class Stack(unittest.TestCase):
    def test_the_table_has_every_subcommand_once(self):
        rows = table()
        self.assertEqual({r[0]: r[1] for r in rows}, SUBS)
        for r in rows:
            self.assertEqual(len(r), 6, r)

    def test_the_pins_are_the_bench_pins(self):
        # The control's stack is the one the bench compares azhaq with: same versions, same checksums.
        with open(os.path.join(ROOT, "bench", "tools.go")) as f:
            go = f.read()
        pins = {m[0]: m[1:] for m in re.findall(r'\{"(\w+)", "([\d.]+)", "[^"]+", "[^"]+", "([0-9a-f]{64})"\}', go)}
        rows = {r[1]: r for r in table()}
        for tool in ("katana", "subfinder", "httpx", "dnsx", "naabu", "gau", "ffuf", "gowitness"):
            self.assertEqual((rows[tool][2], rows[tool][5]), pins[tool], tool)
        with open(os.path.join(ROOT, "bench", "params.go")) as f:
            self.assertIn('const arjunVersion = "%s"' % rows["arjun"][2], f.read())

    def test_every_download_is_pinned_to_a_checksum_and_a_version_in_its_url(self):
        for sub, tool, version, kind, source, sha in table():
            if kind in ("zip", "tgz", "bin"):
                self.assertRegex(sha, r"^[0-9a-f]{64}$", tool)
                self.assertIn(version, source, tool)
                self.assertTrue(source.startswith("https://github.com/"), tool)

    def test_the_readme_lists_the_same_versions(self):
        with open(os.path.join(CONTROL, "README.md")) as f:
            readme = f.read()
        for sub, tool, version, kind, source, sha in table():
            row = re.search(r"^\| `%s` \| %s \| (.*) \|$" % (sub, tool), readme, re.M)
            self.assertIsNotNone(row, "%s is not in the README's table" % sub)
            if version != "apt":
                self.assertTrue(row.group(1).startswith(version), (tool, row.group(1)))
        for claim in ("front end", "tools' own documentation applies", "no scope enforcement", "no request\nledger", "no safety features"):
            self.assertIn(claim, readme)

    def test_the_shell_scripts_parse(self):
        for f in ("orvel", "install-stack.sh"):
            self.assertEqual(subprocess.run(["bash", "-n", os.path.join(CONTROL, f)]).returncode, 0, f)


def zip_of(name, data):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        z.writestr("LICENSE", "x")
        z.writestr(name, data)
    return b.getvalue()


def tgz_of(name, data):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w:gz") as t:
        for n, d in (("README", b"x"), (name, data)):
            info = tarfile.TarInfo(n)
            info.size = len(d)
            t.addfile(info, io.BytesIO(d))
    return b.getvalue()


class InstallStack(unittest.TestCase):
    """install-stack.sh against a table of local files (file:// URLs), no network."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.dir = os.path.join(self.tmp, "bin")

    def fixture(self, wrong=None):
        rows = []
        for sub, tool, kind, pack in (("subs", "subfinder", "zip", zip_of), ("fuzz", "ffuf", "tgz", tgz_of), ("shots", "gowitness", "bin", lambda n, d: d)):
            blob = pack(tool, b"#!/bin/sh\necho %s 1.2.3\n" % tool.encode())
            path = os.path.join(self.tmp, "%s.%s" % (tool, kind))
            with open(path, "wb") as f:
                f.write(blob)
            sha = hashlib.sha256(blob).hexdigest() if tool != wrong else "0" * 64
            rows.append("\t".join((sub, tool, "1.2.3", kind, "file://" + path, sha)))
        table_path = os.path.join(self.tmp, "stack.tsv")
        with open(table_path, "w") as f:
            f.write("# a table\n" + "\n".join(rows) + "\n")
        return table_path

    def install(self, table_path):
        return subprocess.run(["bash", os.path.join(CONTROL, "install-stack.sh"), self.dir], capture_output=True, text=True,
                              env=dict(os.environ, STACK=table_path))

    def test_installs_the_tools_orvel_its_readme_and_the_table(self):
        r = self.install(self.fixture())
        self.assertEqual(r.returncode, 0, r.stderr)
        for tool in ("subfinder", "ffuf", "gowitness", "orvel"):
            self.assertTrue(os.access(os.path.join(self.dir, tool), os.X_OK), tool)
        for f in ("orvel-README.md", "orvel-stack.tsv"):
            self.assertTrue(os.path.exists(os.path.join(self.dir, f)), f)
        self.assertEqual(subprocess.run([os.path.join(self.dir, "ffuf")], capture_output=True, text=True).stdout, "ffuf 1.2.3\n")
        self.assertTrue(r.stdout.startswith("install-stack: subfinder 1.2.3"), r.stdout)
        self.assertIn("orvel 0.1.0", r.stdout)
        with open(os.path.join(self.dir, "orvel-README.md")) as f, open(os.path.join(CONTROL, "README.md")) as g:
            self.assertEqual(f.read(), g.read())

    def test_a_checksum_that_does_not_match_stops_the_install(self):
        r = self.install(self.fixture(wrong="ffuf"))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ffuf: checksum mismatch", r.stderr)
        self.assertFalse(os.path.exists(os.path.join(self.dir, "ffuf")))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "orvel")))

    def test_no_directory_is_a_usage_error(self):
        self.assertNotEqual(subprocess.run(["bash", os.path.join(CONTROL, "install-stack.sh")], capture_output=True).returncode, 0)

    def test_the_real_table_is_what_it_reads_by_default(self):
        with open(os.path.join(CONTROL, "install-stack.sh")) as f:
            self.assertIn('stack=${STACK:-$here/stack.tsv}', f.read())


class RunSh(unittest.TestCase):
    """run.sh trial NAME control samples=4 tags the commit with the words as the tag's first line."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        t = self.tmp
        self.git_env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "init", "-q", "--bare", os.path.join(t, "origin.git")], check=True)
        subprocess.run(["git", "init", "-q", os.path.join(t, "work")], check=True)
        for cmd in (["remote", "add", "origin", os.path.join(t, "origin.git")], ["commit", "-q", "--allow-empty", "-m", "x"]):
            subprocess.run(["git", "-C", os.path.join(t, "work"), *cmd], check=True, env=self.git_env)
        os.makedirs(os.path.join(t, "stub"))
        with open(os.path.join(t, "stub", "age"), "w") as f:  # age -a -r KEY FILE: the file, armored by a stub
            f.write("#!/bin/sh\nfor a; do f=$a; done\ncat \"$f\"\n")
        os.chmod(os.path.join(t, "stub", "age"), 0o755)
        os.makedirs(os.path.join(t, "codex"))
        with open(os.path.join(t, "codex", "auth.json"), "w") as f:
            f.write("{}\n")

    def run_sh(self, *args):
        env = dict(self.git_env, PATH=os.path.join(self.tmp, "stub") + ":" + os.environ["PATH"], CODEX_HOME=os.path.join(self.tmp, "codex"))
        return subprocess.run(["bash", os.path.join(HERE, "run.sh"), *args], capture_output=True, text=True, env=env, cwd=os.path.join(self.tmp, "work"))

    def tag_subject(self, tag):
        r = subprocess.run(["git", "-C", os.path.join(self.tmp, "origin.git"), "for-each-ref", "--format=%(contents:subject)", "refs/tags/" + tag],
                           capture_output=True, text=True)
        return r.stdout.strip()

    def test_control_is_an_allowed_trial_kind(self):
        r = self.run_sh("trial", "control1", "control", "samples=4")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tag_subject("trial-control1"), "control samples=4")

    def test_the_other_kinds_still_work_and_an_unknown_one_does_not(self):
        for kind in ("gate", "baseline", "switch", "research", "hunter"):
            self.assertEqual(self.run_sh("trial", "k-" + kind, kind).returncode, 0, kind)
        r = self.run_sh("trial", "bad", "controls")
        self.assertEqual(r.returncode, 2)
        self.assertIn("control", r.stderr)


class Workflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(os.path.join(ROOT, ".github", "workflows", "trial.yml")) as f:
            cls.text = f.read()
        parts = re.split(r"^  ([a-z][\w-]*):\n", cls.text.split("\njobs:\n", 1)[1], flags=re.M)
        cls.jobs = dict(zip(parts[1::2], parts[2::2]))

    def test_the_kind_job_maps_control(self):
        self.assertIn("control) kind=control ;;", self.jobs["kind"])
        self.assertIn("1 | 2 | 3 | 4)", self.jobs["kind"])  # samples=N as for gate

    def test_the_gate_jobs_run_for_control_and_build_does_not(self):
        self.assertIn("needs.kind.outputs.kind == 'gate'", self.jobs["build"])
        self.assertNotIn("control", self.jobs["build"])
        for job in ("gate-a", "gate-b"):
            body = self.jobs[job]
            cond = re.search(r"^    if: (.*)$", body, re.M).group(1)
            self.assertIn("needs.kind.outputs.kind == 'gate'", cond)
            self.assertIn("needs.kind.outputs.kind == 'control'", cond)
            self.assertIn("needs.build.result == 'skipped'", cond)  # build is skipped for control
            self.assertIn("needs.build.result == 'success'", cond)  # and a failed build still stops the gate
            self.assertNotIn("!=", cond)
            self.assertIn("max-parallel: 2", body)
            self.assertIn("samples_json", body)

    def test_the_gate_steps_run_for_gate_only_and_orvel_for_control_only(self):
        for job in ("gate-a", "gate-b"):
            body = self.jobs[job]
            steps = re.split(r"^      - ", body.split("\n    steps:\n", 1)[1], flags=re.M)[1:]
            by = {}
            for st in steps:
                m = re.match(r"(?:name: (.+)|uses: (.+))\n", st)
                by[m.group(1) or m.group(2)] = st
            for gate_only in ("azhaq", "actions/download-artifact@v7", "sigstore/cosign-installer@v3"):
                self.assertIn("if: needs.kind.outputs.kind == 'gate'", by[gate_only], (job, gate_only))
            self.assertIn("if: needs.kind.outputs.kind == 'control'", by["orvel"])
            self.assertIn(".github/ci/control/install-stack.sh \"$HOME/trial/bin\"", by["orvel"])
            order = list(by)
            self.assertLess(order.index("orvel"), order.index("codex"))
            self.assertLess(order.index("orvel"), order.index("isolate"))
            for shared in ("codex", "part", "heartbeat", "isolate", "remove the source", "review", "publish"):
                self.assertNotIn("if: needs.kind", by[shared].split("run:")[0].split("env:")[0], (job, shared))

    def test_the_review_and_the_records_use_the_control_kinds(self):
        for job, part in (("gate-a", "a"), ("gate-b", "b")):
            body = self.jobs[job]
            self.assertIn('render_brief.py" control-%s "$(cat "$HOME/ci/orvel.version")"' % part, body)
            self.assertIn('render_brief.py" gate-%s "$(cat "$HOME/ci/azhaq.version")"' % part, body)
            self.assertIn("cand=azhaq; kind=gate-%s" % part, body)
            self.assertIn("cand=orvel; kind=control-%s" % part, body)
            self.assertIn('name=%s$([ "$SAMPLES" != 1 ]' % part, body)  # the same part names and publish paths
            self.assertIn('"trial/$GITHUB_REF_NAME/${{ steps.part.outputs.name }}"', body)
        # part B's lab source is the gate's, untouched by kind
        lab = self.jobs["gate-b"].split("- name: lab source")[1].split("- name: part")[0]
        self.assertNotIn("KIND", lab)
        self.assertNotIn("control", lab)

    def test_the_job_names_stay_gate_and_say_control_for_control(self):
        for job, part in (("gate-a", "a"), ("gate-b", "b")):
            self.assertIn("name: ${{ needs.kind.outputs.kind == 'control' && 'control-%s' || 'gate-%s' }} (${{ matrix.sample }})" % (part, part), self.jobs[job])


if __name__ == "__main__":
    unittest.main()
