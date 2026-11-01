#!/usr/bin/env python3
"""render_brief.py KIND VERSION VARS.json TRIAL_DIR: prints the brief for KIND
with its placeholders filled: the release under test (already installed in
./bin, except gate's part B which installs nothing), each client's domain,
address range and resolver (from build.py's vars.json), and what each phase
may use. Exits 1 when a placeholder is left over.

KIND is research or hunter (two phases, RESEARCH.md/HUNTER.md, kept for
older trials), or one of the gate's kinds (GATE.md, one estate from
.github/ci/range/pool.json):
  gate-a    part A, the engagement, with azhaq as the main tool
  gate-b    part B, the head-to-head on the local labs
  baseline  the same engagement as gate-a, usual tools only, azhaq off
"""
import json
import os
import re
import sys

USUAL = "your usual tools only."
# azhaq is in ./bin before the review starts (trial.yml), so installing it is not part of the timed work.
HAVE = ("azhaq __VERSION__ is installed at ./bin/azhaq (by the release's install script, with the checksum and "
        "signature checked; you may verify it again).")
AZHAQ = (HAVE + " Use it as your main tool. "
         "Use other tools only where it cannot do the job, and log each such fallback with the reason in ./notes/fallbacks.md.")

PHASES = {
    # kind: (template, phase 1 tools, phase 2 tools)
    "research": ("RESEARCH.md",
                 USUAL + " " + HAVE + " Do not run it in phase 1.",
                 AZHAQ),
    "hunter": ("HUNTER.md",
               AZHAQ,
               USUAL + " azhaq must not be used in this session."),
}

GATE_FILE = "GATE.md"
GATE_AZHAQ_TOOLS = AZHAQ
GATE_USUAL_TOOLS = USUAL + " azhaq is not installed here and must not be used."


def render(kind, version, variables, trial_dir):
    if kind not in PHASES:
        raise ValueError("kind must be research or hunter, not %r" % kind)
    name, p1, p2 = PHASES[kind]
    with open(os.path.join(trial_dir, name), encoding="utf-8") as f:
        text = f.read()
    values = dict(variables)
    values.update({"VERSION": version, "PHASE1_TOOLS": p1.replace("__VERSION__", version),
                   "PHASE2_TOOLS": p2.replace("__VERSION__", version)})
    for k, v in values.items():
        text = text.replace("__%s__" % k, v)
    left = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if left:
        raise ValueError("placeholders left in %s: %s" % (name, ", ".join(left)))
    return text


_GATE_MARKER = re.compile(r"^<!-- GATE:(PART-A|PART-B) -->[ \t]*\n", re.M)


def gate_part(text, part):
    """The shared preamble (before the first marker) plus PART ("a" or "b")
    of GATE.md; the other part's block is dropped."""
    pieces = _GATE_MARKER.split(text)
    shared = pieces[0]
    blocks = dict(zip(pieces[1::2], pieces[2::2]))
    want = "PART-A" if part == "a" else "PART-B"
    if want not in blocks:
        raise ValueError("GATE.md has no %s section" % want)
    return shared + blocks[want]


def render_gate(part, version, variables, trial_dir, tools):
    """PART "a" or "b" of GATE.md, TOOLS "azhaq" or "usual" for part a's
    engagement (part b always has azhaq already installed)."""
    with open(os.path.join(trial_dir, GATE_FILE), encoding="utf-8") as f:
        text = gate_part(f.read(), part)
    values = dict(variables)
    values["VERSION"] = version
    if part == "a":
        tool_text = GATE_AZHAQ_TOOLS if tools == "azhaq" else GATE_USUAL_TOOLS
        values["ENGAGEMENT_TOOLS"] = tool_text.replace("__VERSION__", version)
    for k, v in values.items():
        text = text.replace("__%s__" % k, v)
    left = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if left:
        raise ValueError("placeholders left in GATE.md (part %s): %s" % (part, ", ".join(left)))
    return text


def main(argv):
    if len(argv) != 5:
        print(__doc__, file=sys.stderr)
        return 2
    kind, version, trial_dir = argv[1], argv[2], argv[4]
    with open(argv[3], encoding="utf-8") as f:
        variables = json.load(f)
    try:
        if kind == "gate-a":
            text = render_gate("a", version, variables, trial_dir, "azhaq")
        elif kind == "gate-b":
            text = render_gate("b", version, variables, trial_dir, "azhaq")
        elif kind == "baseline":
            text = render_gate("a", version, variables, trial_dir, "usual")
        else:
            text = render(kind, version, variables, trial_dir)
        sys.stdout.write(text)
    except ValueError as e:
        print("render_brief.py: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
