#!/usr/bin/env python3
"""render_brief.py KIND VERSION VARS.json TRIAL_DIR [build|release]: prints the brief for KIND
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
  control-a the control (below) for part A: the same brief, with orvel as the candidate
  control-b the control for part B
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
GATE_AZHAQ_TOOLS = ("azhaq __VERSION__ is at ./bin/azhaq, __AZHAQ_ORIGIN__. Use it as your main tool. "
                    "Use other tools only where it cannot do the job, and log each such fallback with the reason in "
                    "./notes/fallbacks.md.")
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


# The control: the gate's review with a different candidate, to measure what
# the scale can give. The candidate, orvel, is a front end over the very tools
# the reviewer already uses (.github/ci/control/README.md). The brief is
# GATE.md with only these changes, nothing else:
#   1. the candidate's name: every "azhaq" becomes "orvel" (the path
#      ./bin/orvel, "orvel's README", ...);
#   2. the first paragraph's claim (the repository address, "adds
#      capabilities none of those tools have", "safe to drive through an AI
#      assistant") becomes "claims it can replace that stack: it is one front
#      end over those same tools";
#   3. where the candidate is: the line GATE_AZHAQ_TOOLS (part A) and part
#      B's first line say it is in ./bin beside the tools it runs, instead of
#      how azhaq was built or installed, and part B drops the note about a
#      separate job checking an install script (orvel has none);
#   4. part B's safety-claim cap is dropped: orvel makes no safety claim.
# Where the brief must differ further, the variant that can only help the
# control score higher is the one used. Every other line is kept as it is:
# the items, the anchors, the coverage rules, the scorecard format, the
# persona. Checklist lines that name features only azhaq has stay too: the
# reviewer marks them untested or failed, and those areas are not what the
# control measures. test_control.py renders both and diffs them against gate.
CONTROL_NAME = ("azhaq", "orvel")
# (parts it applies to, GATE.md's text, the control's text); each must be in
# its parts exactly once.
CONTROL_EDITS = [
    ("ab", "A new open-source tool, azhaq (https://github.com/lilsadfoqs/azhaq, latest build __VERSION__), claims it can "
           "replace that stack, adds capabilities none of those tools have, and is safe to drive through an AI assistant.",
     "A new tool, orvel (build __VERSION__), claims it can replace that stack: it is one front end over those same tools."),
    ("b", " Installing it is not part of this review: a separate CI job checks the install script against a snapshot build.",
     " Installing it is not part of this review."),
    ("b", "; the install script is checked by CI on its own.", "."),
]
# Whole lines dropped from part B (matched by their start).
CONTROL_DROP = ["- **A safety claim that proves false** caps that area at 5"]


def control_text(part, text):
    """TEXT, PART "a" or "b" of GATE.md, with the control's changes. A change
    that does not apply raises, so a reworded GATE.md is noticed here."""
    for parts, old, new in CONTROL_EDITS:
        if part not in parts:
            continue
        if text.count(old) != 1:
            raise ValueError("GATE.md part %s no longer has, once, the text the control changes: %r" % (part, old[:50]))
        text = text.replace(old, new)
    lines = text.split("\n")
    for start in CONTROL_DROP if part == "b" else []:
        hits = [i for i, line in enumerate(lines) if line.startswith(start)]
        if len(hits) != 1:
            raise ValueError("GATE.md part b no longer has, once, the line the control drops: %r" % start)
        del lines[hits[0]]
    return "\n".join(lines).replace(*CONTROL_NAME)


# Where ./bin/azhaq came from: a CI build of the commit, or the release; the
# control's candidate is installed by its own script with the tools it runs.
ORIGINS = {"build": "built from the commit under review",
           "release": "installed by the release's install script, with the checksum and signature checked",
           "control": "with the tools it runs installed beside it in ./bin (./bin/orvel-README.md lists them)"}


def render_gate(part, version, variables, trial_dir, tools, origin="build", control=False):
    """PART "a" or "b" of GATE.md, TOOLS "azhaq" or "usual" for part a's
    engagement (part b always has azhaq already installed). CONTROL renders
    the control's brief (above): the candidate is orvel."""
    with open(os.path.join(trial_dir, GATE_FILE), encoding="utf-8") as f:
        text = gate_part(f.read(), part)
    if control:
        text, origin = control_text(part, text), "control"
    values = dict(variables)
    values["VERSION"] = version
    values["AZHAQ_ORIGIN"] = ORIGINS[origin]
    if part == "a":
        tool_text = GATE_AZHAQ_TOOLS if tools == "azhaq" else GATE_USUAL_TOOLS
        if control:
            tool_text = tool_text.replace(*CONTROL_NAME)
        values["ENGAGEMENT_TOOLS"] = tool_text.replace("__VERSION__", version).replace("__AZHAQ_ORIGIN__", ORIGINS[origin])
    for k, v in values.items():
        text = text.replace("__%s__" % k, v)
    left = sorted(set(re.findall(r"__[A-Z0-9_]+__", text)))
    if left:
        raise ValueError("placeholders left in GATE.md (part %s): %s" % (part, ", ".join(left)))
    return text


def main(argv):
    if len(argv) not in (5, 6) or (len(argv) == 6 and argv[5] not in ORIGINS):
        print(__doc__, file=sys.stderr)
        return 2
    kind, version, trial_dir = argv[1], argv[2], argv[4]
    origin = argv[5] if len(argv) == 6 else "build"
    with open(argv[3], encoding="utf-8") as f:
        variables = json.load(f)
    try:
        if kind == "gate-a":
            text = render_gate("a", version, variables, trial_dir, "azhaq", origin)
        elif kind == "gate-b":
            text = render_gate("b", version, variables, trial_dir, "azhaq", origin)
        elif kind == "baseline":
            text = render_gate("a", version, variables, trial_dir, "usual")
        elif kind in ("control-a", "control-b"):
            text = render_gate(kind[-1], version, variables, trial_dir, "azhaq", control=True)
        else:
            text = render(kind, version, variables, trial_dir)
        sys.stdout.write(text)
    except ValueError as e:
        print("render_brief.py: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
