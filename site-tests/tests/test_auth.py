"""Tests du gestionnaire avec des requêtes HTTP et un transport en mémoire."""

from concurrent.futures import ThreadPoolExecutor
from functools import partial
import http.client
from importlib.util import module_from_spec, spec_from_file_location
from io import BytesIO
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from urllib.parse import urlencode

from auth import AuthStore
from qr import QREncoder
from server import VerifyHandler

GENERATOR = Path(__file__).resolve().parents[2] / "generateur-totp" / "totp.py"
spec = spec_from_file_location("standalone_generator", GENERATOR)
generator = module_from_spec(spec)
spec.loader.exec_module(generator)
PASSWORD = "Un mot de passe de test"


class TestHandler(VerifyHandler):
    def auth_now(self):
        return self.config.now

    def log_message(self, *args):
        pass


class HTTPStream:
    def __init__(self, incoming=b""):
        self.incoming = BytesIO(incoming)
        self.outgoing = BytesIO()

    def sendall(self, data):
        self.outgoing.write(data)

    def makefile(self, *args):
        return self.incoming


class HTTPTransport(HTTPStream):
    def __init__(self, handler):
        super().__init__()
        self.handler = handler

    def makefile(self, *args):
        server = HTTPStream(self.outgoing.getvalue())
        self.handler(server, ("127.0.0.1", 0), None)
        return BytesIO(server.outgoing.getvalue())

    def close(self):
        pass


class Client:
    def __init__(self, handler):
        self.handler = handler
        self.cookie = ""

    def request(self, path, fields=None):
        connection = http.client.HTTPConnection("localhost")
        connection.sock = HTTPTransport(self.handler)
        headers = {"Cookie": self.cookie}
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            connection.request("GET" if fields is None else "POST", path,
                               None if fields is None else urlencode(fields), headers)
            response = connection.getresponse()
            body = response.read()
            cookie = response.getheader("Set-Cookie")
            if cookie:
                self.cookie = cookie.split(";", 1)[0]
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def get_form(self, path):
        response = self.request(path)
        if response[0] == 303 and response[1].get("Location") == path:
            response = self.request(path)
        if response[0] != 200:
            raise AssertionError(response)
        return re.search(rb'name="csrf" value="([^"]+)"', response[2])[1].decode()


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="totp-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.config = SimpleNamespace(auth=AuthStore(root / "accounts.sqlite3"), qr=QREncoder(),
                                      now=1710000005, secret_file=root / "standalone",
                                      digits=6, at=59, algorithm="sha1", window=0)
        self.handler = partial(TestHandler, config=self.config)
        self.client = Client(self.handler)

    def register(self, username="alice", client=None):
        client = client or self.client
        csrf = client.get_form("/register")
        response = client.request("/register", {"csrf": csrf, "username": username, "password": PASSWORD})
        self.assert_redirect(response, "/setup")
        return client.get_form("/setup")

    def account(self, username="alice"):
        with self.config.auth.database() as db:
            return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    def code(self, offset=0, username="alice"):
        return generator.generate(self.account(username)["secret"], self.config.now + offset)

    def assert_redirect(self, response, path):
        self.assertEqual((response[0], response[1].get("Location")), (303, path))

    def login(self, client=None, username="alice", password=PASSWORD):
        client = client or self.client
        csrf = client.get_form("/login")
        return client.request("/login", {"csrf": csrf, "username": username, "password": password})

    def logout(self, client=None):
        client = client or self.client
        csrf = client.get_form("/account")
        return client.request("/logout", {"csrf": csrf})

    def test_registration_requires_confirmation_and_provisions_unique_secret(self):
        self.assert_redirect(self.client.request("/account"), "/login")
        self.assert_redirect(self.client.request("/setup/qr.png"), "/login")
        csrf = self.register()
        setup_page = self.client.request("/setup")[2].decode()
        self.assertIn("Set up Microsoft Authenticator", setup_page)
        self.assertIn("Other account", setup_page)
        alice = self.account()
        self.assertFalse(alice["active"])
        self.assertEqual(len(alice["secret"]), 20)
        self.assertNotEqual(alice["password"], PASSWORD.encode())
        self.assertEqual(len(alice["salt"]), 16)
        status, headers, png = self.client.request("/setup/qr.png")
        self.assertEqual((status, headers["Content-Type"], headers["Cache-Control"]),
                         (200, "image/png", "no-store"))
        self.assertTrue(png.startswith(b"\x89PNG\r\n\x1a\n"))
        self.assert_redirect(self.client.request("/account"), "/login")
        self.assertEqual(self.client.request("/setup", {"csrf": csrf, "code": "nope"})[0], 401)
        self.assertFalse(self.account()["active"])
        partial_cookie = self.client.cookie
        self.assert_redirect(self.client.request("/setup", {"csrf": csrf, "code": self.code()}), "/account")
        self.assertTrue(self.account()["active"])
        self.assertNotEqual(self.client.cookie, partial_cookie)
        self.assert_redirect(self.client.request("/setup/qr.png"), "/login")
        self.register("bob", Client(self.handler))
        bob = self.account("bob")
        self.assertNotEqual(alice["secret"], bob["secret"])
        self.assertNotEqual(alice["salt"], bob["salt"])
        self.assertNotEqual(alice["password"], bob["password"])

    def test_login_logout_and_session_protection(self):
        csrf = self.register()
        self.client.request("/setup", {"csrf": csrf, "code": self.code()})
        self.assert_redirect(self.logout(), "/login")
        self.config.now += 30
        self.assert_redirect(self.login(), "/login/totp")
        self.assert_redirect(self.client.request("/account"), "/login")
        self.assert_redirect(self.client.request("/setup/qr.png"), "/login")
        partial_cookie = self.client.cookie
        self.assertIn(b"Microsoft Authenticator", self.client.request("/login/totp")[2])
        csrf = self.client.get_form("/login/totp")
        self.assert_redirect(self.client.request("/login/totp", {"csrf": csrf, "code": self.code()}), "/account")
        self.assertNotEqual(partial_cookie, self.client.cookie)
        self.assertIn(b"alice", self.client.request("/account")[2])
        csrf = self.client.get_form("/account")
        self.assertEqual(self.client.request("/logout", {"csrf": "incorrect"})[0], 403)
        self.assertEqual(self.client.request("/account")[0], 200)
        authenticated_cookie = self.client.cookie
        self.assert_redirect(self.client.request("/logout", {"csrf": csrf}), "/login")
        self.client.cookie = authenticated_cookie
        self.assert_redirect(self.client.request("/account"), "/login")

    def test_invalid_credentials_and_password_limit(self):
        self.register()
        guest = Client(self.handler)
        for index in range(10):
            username = "unknown" if index == 0 else "alice"
            self.assertEqual(self.login(guest, username, "mot de passe incorrect")[0], 401)
        self.assertEqual(self.login(guest)[0], 429)
        self.assert_redirect(guest.request("/account"), "/login")
        self.config.now += 60
        self.assert_redirect(self.login(guest), "/setup")

    def test_invalid_expired_and_reused_codes_and_attempt_limit(self):
        csrf = self.register()
        enrolled_code = self.code()
        self.client.request("/setup", {"csrf": csrf, "code": enrolled_code})
        self.logout()
        self.login()
        csrf = self.client.get_form("/login/totp")
        def submit(code):
            return self.client.request("/login/totp", {"csrf": csrf, "code": code})
        self.assertEqual(submit(enrolled_code)[0], 401)
        self.config.now += 30
        self.assertEqual(submit(enrolled_code)[0], 401)
        wrong = f"{(int(self.code()) + 1) % 1000000:06d}"
        self.assertEqual(submit(wrong)[0], 401)
        self.assertEqual(submit(wrong)[0], 401)
        self.assertEqual(submit(self.code())[0], 429)
        self.config.now += 30
        self.assert_redirect(submit(self.code()), "/account")

    def test_concurrent_attempts_cannot_reuse_same_code(self):
        csrf = self.register()
        self.client.request("/setup", {"csrf": csrf, "code": self.code()})
        self.logout()
        self.config.now += 30
        other = Client(self.handler)
        for client in (self.client, other):
            self.assert_redirect(self.login(client), "/login/totp")
        requests = [(client, client.get_form("/login/totp")) for client in (self.client, other)]
        token = self.code()
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(lambda pair: pair[0].request(
                "/login/totp", {"csrf": pair[1], "code": token})[0], requests))
        self.assertEqual(sorted(statuses), [303, 401])

    def test_partial_session_expires(self):
        csrf = self.register()
        self.client.request("/setup", {"csrf": csrf, "code": self.code()})
        self.logout()
        self.login()
        csrf = self.client.get_form("/login/totp")
        self.config.now += 300
        self.assert_redirect(self.client.request("/login/totp", {"csrf": csrf, "code": self.code()}), "/login")

    def test_standalone_generator_and_verifier(self):
        code = subprocess.check_output([
            "python3", str(GENERATOR), "--secret-file", str(self.config.secret_file), "--at", "59"
        ], text=True).strip()
        status, _, body = self.client.request("/verify", {"code": code})
        self.assertEqual(status, 200)
        self.assertIn(b"Code accepted.", body)
        self.assertEqual(self.client.request("/.totp-secret")[0], 404)
