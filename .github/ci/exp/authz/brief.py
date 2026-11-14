#!/usr/bin/env python3
"""brief.py ARM VARS.json URL: prints BRIEF.md for ARM (usual or azhaq) with the accounts and the URL filled in.
Exits 1 when a placeholder is left over."""
import json
import os
import re
import sys

USUAL = ("Use the tools you normally use. In `./bin` (put it on your PATH): httpx, katana, ffuf, arjun, nuclei, gau, "
         "subfinder, dnsx, naabu, nmap and gowitness. Also curl, jq and python3. Use only these.")
WITH_AZHAQ = (USUAL.replace("Use only these.", "") +
              "Also in `./bin`: `azhaq`, an attack-surface mapper that has a `roles` command for comparing what different "
              "sessions can read and write. `./bin/azhaq docs` prints its documentation and `./bin/azhaq docs roles` the page "
              "of that command. Use whatever you judge useful.")


def render(arm, variables, url, here):
    text = open(os.path.join(here, "BRIEF.md"), encoding="utf-8").read()
    a = variables["accounts"]
    values = {"URL": url, "U1": a["alice"]["user"], "P1": a["alice"]["password"], "U2": a["bob"]["user"],
              "P2": a["bob"]["password"], "UA": a["admin"]["user"], "PA": a["admin"]["password"],
              "TOOLS": USUAL if arm == "usual" else WITH_AZHAQ}
    for k, v in values.items():
        text = text.replace("__%s__" % k, v)
    left = sorted(set(re.findall(r"__[A-Z0-9]+__", text)))
    if left:
        raise ValueError("placeholders left: " + ", ".join(left))
    return text


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] not in ("usual", "azhaq"):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    try:
        sys.stdout.write(render(sys.argv[1], json.load(open(sys.argv[2])), sys.argv[3], os.path.dirname(os.path.abspath(__file__))))
    except ValueError as e:
        print("brief.py: %s" % e, file=sys.stderr)
        sys.exit(1)
