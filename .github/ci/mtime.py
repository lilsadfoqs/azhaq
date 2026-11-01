#!/usr/bin/env python3
"""mtime.py: sets each tracked file's modification time to the time of the
last commit that changed it, and each directory's to the newest file under it.

go test keeps a test's result while the files it opened keep their size and
modification time; a fresh checkout stamps every file with the clone's time,
so nothing is kept. With commit times, a file is newer only when a commit
changed it. Needs the whole history (fetch-depth: 0).
"""
import os
import subprocess
import sys


def main():
    root = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
    os.chdir(root)
    tracked = set(subprocess.check_output(["git", "ls-files", "-z"]).decode().split("\0")) - {""}
    log = subprocess.Popen(
        ["git", "log", "--format=%x01%ct", "--name-only", "--no-renames", "--diff-merges=first-parent", "-z"],
        stdout=subprocess.PIPE,
    )
    when = {}
    t = None
    for tok in log.stdout.read().decode(errors="surrogateescape").split("\0"):
        tok = tok.strip("\n")
        if tok.startswith("\x01"):
            t = int(tok[1:])
            continue
        if tok in tracked and tok not in when:
            when[tok] = t
            if len(when) == len(tracked):
                log.kill()
                break
    log.wait()
    dirs = {}
    for path, t in when.items():
        if os.path.islink(path) or not os.path.exists(path):
            continue
        os.utime(path, (t, t))
        d = os.path.dirname(path)
        while True:
            dirs[d or "."] = max(dirs.get(d or ".", 0), t)
            if not d:
                break
            d = os.path.dirname(d)
    for d, t in dirs.items():
        os.utime(d, (t, t))
    missing = len(tracked) - len(when)
    print("mtime.py: %d files, %d directories set%s" % (
        len(when), len(dirs), ", %d without a commit" % missing if missing else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
