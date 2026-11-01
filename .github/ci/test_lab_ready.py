import http.server
import json
import os
import sys
import threading
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import lab_ready  # noqa: E402


class Fake:
    """VAmPI and DVWA as they come up: no database until the first-run step."""

    def __init__(self):
        self.db = {"vampi": False, "dvwa": False}
        self.calls = []
        self.tokens = {}
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def send(self, code, body="", headers=None):
                self.send_response(code)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body.encode())))
                self.end_headers()
                self.wfile.write(body.encode())

            def session(self):
                for part in self.headers.get("Cookie", "").split(";"):
                    if part.strip().startswith("PHPSESSID="):
                        return part.strip()[10:], {}
                sid = "s%d" % len(fake.tokens)
                return sid, {"Set-Cookie": "PHPSESSID=%s; path=/" % sid}

            def form(self):
                n = int(self.headers.get("Content-Length") or 0)
                return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}

            def page(self, sid, hdr, title):
                fake.tokens[sid] = "tok-" + sid
                self.send(200, "<form>%s <input type='hidden' name='user_token' value='%s' /></form>" % (title, fake.tokens[sid]), hdr)

            def do_GET(self):
                fake.calls.append(("GET", self.path))
                if self.path == "/createdb":
                    fake.db["vampi"] = True
                    return self.send(200, '{"message": "Database populated."}')
                sid, hdr = self.session()
                if self.path == "/login.php":
                    return self.page(sid, hdr, "login")
                if self.path == "/setup.php":
                    return self.page(sid, hdr, "setup")
                if self.path == "/index.php":
                    return self.send(200, "<a href=logout.php>Logout</a>")
                self.send(404)

            def do_POST(self):
                fake.calls.append(("POST", self.path))
                if self.path == "/users/v1/login":
                    ok = fake.db["vampi"]
                    return self.send(200 if ok else 500, '{"auth_token": "x"}' if ok else "no such table: users")
                sid, hdr = self.session()
                f = self.form()
                if f.get("user_token") != fake.tokens.get(sid):
                    return self.send(200, "CSRF token is incorrect", hdr)
                if self.path == "/setup.php" and "create_db" in f:
                    fake.db["dvwa"] = True
                    return self.send(200, "Setup successful !", hdr)
                if self.path == "/login.php":
                    if fake.db["dvwa"] and f.get("username") == "admin" and f.get("password") == "password":
                        return self.send(302, "", dict(hdr, Location="index.php"))
                    return self.send(302, "", dict(hdr, Location="login.php"))
                self.send(404)

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d" % self.srv.server_address[1]

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()


class LabReady(unittest.TestCase):
    def setUp(self):
        self.f = Fake()
        self.addCleanup(self.f.close)

    def test_vampi_gets_its_database_and_a_login_answers(self):
        self.assertFalse(lab_ready.vampi_login(self.f.base))
        self.assertTrue(lab_ready.vampi_ready(self.f.base))
        self.assertTrue(self.f.db["vampi"])
        self.assertIn(("GET", "/createdb"), self.f.calls)

    def test_dvwa_gets_its_database_through_the_setup_page_and_a_login_answers(self):
        self.assertFalse(lab_ready.dvwa_login(self.f.base))
        self.assertTrue(lab_ready.dvwa_ready(self.f.base))
        self.assertTrue(self.f.db["dvwa"])
        self.assertIn(("POST", "/setup.php"), self.f.calls)

    def test_a_ready_app_is_left_alone(self):
        self.f.db.update(vampi=True, dvwa=True)
        self.assertTrue(lab_ready.vampi_ready(self.f.base))
        self.assertTrue(lab_ready.dvwa_ready(self.f.base))
        self.assertNotIn(("GET", "/createdb"), self.f.calls)
        self.assertNotIn(("POST", "/setup.php"), self.f.calls)
        self.assertNotIn(("GET", "/setup.php"), self.f.calls)

    def test_main_succeeds_and_fails_on_the_login(self):
        self.assertEqual(lab_ready.main(["--vampi", self.f.base, "--dvwa", self.f.base]), 0)
        self.assertEqual(lab_ready.main(["--vampi", "http://127.0.0.1:9", "--wait", "0"]), 1)

    def test_it_waits_for_a_database_server_that_starts_late(self):
        n = []
        clock = iter(range(0, 1000, 3))

        def late(base):
            n.append(1)
            return len(n) >= 3

        self.assertTrue(lab_ready.wait_for("x", late, "b", 60, sleep=lambda s: None, clock=lambda: next(clock)))
        self.assertEqual(len(n), 3)
        self.assertFalse(lab_ready.wait_for("x", lambda b: False, "b", 9, sleep=lambda s: None, clock=lambda: next(clock)))


if __name__ == "__main__":
    unittest.main()
