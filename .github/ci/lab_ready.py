#!/usr/bin/env python3
"""lab_ready.py [--vampi URL] [--dvwa URL]: puts the two training apps that
need a first-run step into the state a user who read their instructions has:
VAmPI's database created (its documented GET /createdb) and DVWA's database
set up (the create/reset button of its setup page). Each is then checked by
a login: VAmPI's name1/pass1, DVWA's admin/password. Nothing else changes.
Exits 1 when an app does not answer a login within --wait seconds.
"""
import argparse
import http.client
import http.cookiejar
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

VAMPI_USER = {"username": "name1", "password": "pass1"}
DVWA_USER = ("admin", "password")


def opener():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def fetch(op, url, data=None, headers=None, timeout=15):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with op.open(req, timeout=timeout) as r:
            return r.status, r.geturl(), r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, url, e.read().decode("utf-8", "replace")


def vampi_login(base):
    status, _, body = fetch(opener(), base + "/users/v1/login", json.dumps(VAMPI_USER).encode(),
                            {"Content-Type": "application/json"})
    return status == 200 and "auth_token" in body


def vampi_ready(base):
    """True once the database exists and name1 can sign in."""
    if vampi_login(base):
        return True
    fetch(opener(), base + "/createdb")
    return vampi_login(base)


def dvwa_token(body):
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)", body)
    return m.group(1) if m else ""


def dvwa_login(base):
    op = opener()
    _, _, page = fetch(op, base + "/login.php")
    form = {"username": DVWA_USER[0], "password": DVWA_USER[1], "Login": "Login", "user_token": dvwa_token(page)}
    status, final, body = fetch(op, base + "/login.php", urllib.parse.urlencode(form).encode())
    return status == 200 and "logout" in body.lower() and urllib.parse.urlparse(final).path.endswith("index.php")


def dvwa_ready(base):
    """True once the database is set up and admin can sign in."""
    if dvwa_login(base):
        return True
    op = opener()
    _, _, page = fetch(op, base + "/setup.php")
    token = dvwa_token(page)
    if token:
        form = {"create_db": "Create / Reset Database", "user_token": token}
        fetch(op, base + "/setup.php", urllib.parse.urlencode(form).encode(), timeout=60)
    return dvwa_login(base)


def wait_for(name, check, base, wait, sleep=time.sleep, clock=time.time):
    """Runs check(base) until it holds or `wait` seconds pass (the database server starts after the page)."""
    end = clock() + wait
    while True:
        try:
            if check(base):
                print("lab %s: ready, a login answers" % name)
                return True
        except (OSError, http.client.HTTPException) as e:
            last = e
        else:
            last = None
        if clock() >= end:
            print("lab %s: no login answers after %ds%s" % (name, wait, " (%s)" % last if last else ""), file=sys.stderr)
            return False
        sleep(3)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--vampi", default="")
    ap.add_argument("--dvwa", default="")
    ap.add_argument("--wait", type=int, default=120)
    a = ap.parse_args(argv)
    ok = True
    if a.vampi:
        ok = wait_for("vampi", vampi_ready, a.vampi.rstrip("/"), a.wait) and ok
    if a.dvwa:
        ok = wait_for("dvwa", dvwa_ready, a.dvwa.rstrip("/"), a.wait) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
