"""Sert le formulaire local et vérifie les codes TOTP côté serveur."""

import argparse
from functools import partial
import hmac
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import struct
import time
from urllib.parse import parse_qs

from auth import AuthStore
from auth_pages import AuthPages, FORMS
from qr import QREncoder

STATIC = Path(__file__).resolve().parent / "dist"
DEFAULT_SECRET = STATIC.parent.parent / ".totp-secret"
DEFAULT_DB = STATIC.parent / "accounts.sqlite3"
AUTH_GET = {"/register", "/login", "/setup", "/setup/qr.png", "/login/totp", "/account"}


def verify(key, code, timestamp, digits, algorithm, window):
    step = timestamp // 30
    offsets = (0, -1, 1) if window else (0,)
    for offset in offsets:
        counter = step + offset
        if not 0 <= counter < 2**64:
            continue
        digest = hmac.new(key, struct.pack(">Q", counter), algorithm).digest()
        start = digest[-1] % 16
        number = struct.unpack_from(">I", digest, start)[0] % (1 << 31)
        expected = f"{number % 10**digits:0{digits}d}"
        if hmac.compare_digest(expected, code):
            return True
    return False


class VerifyHandler(AuthPages, BaseHTTPRequestHandler):
    def __init__(self, request, address, server, *, config):
        self.config = config
        self.auth = config.auth
        super().__init__(request, address, server)

    def auth_now(self):
        return int(time.time())

    def verify_account_totp(self, secret, code, now):
        return verify(secret, code, now, 6, "sha1", 0)

    def respond(self, status, content_type, body, *, headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def page(self, message="", valid=False, status=200):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        html = html.replace("{{digits}}", str(self.config.digits))
        html = html.replace("{{quantifier}}", f"{{{self.config.digits}}}")
        html = html.replace("{{message}}", message).replace("{{valid}}", str(valid).lower())
        self.respond(status, "text/html; charset=utf-8", html.encode("utf-8"))

    def do_GET(self):
        if self.path in AUTH_GET:
            self.auth_get()
        elif self.path == "/":
            self.page()
        elif self.path == "/style.css":
            self.respond(200, "text/css; charset=utf-8", (STATIC / "style.css").read_bytes())
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path in FORMS:
            self.auth_post()
            return
        if self.path != "/verify":
            self.send_error(404)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 128:
                raise ValueError
            fields = parse_qs(self.rfile.read(length).decode("ascii"), max_num_fields=1)
        except ValueError:
            self.page("Invalid request.", status=400)
            return

        digits = self.config.digits
        code = fields.get("code", [""])[0]
        if len(code) != digits or not code.isascii() or not code.isdecimal():
            self.page(f"Enter a {digits}-digit code.", status=400)
            return

        try:
            key = self.config.secret_file.read_bytes()
        except FileNotFoundError:
            self.page("Run the generator once to enable verification.", status=503)
            return
        except OSError:
            self.page("The TOTP configuration is unavailable.", status=503)
            return
        if len(key) != 20:
            self.page("The TOTP configuration file is invalid.", status=503)
            return

        timestamp = int(time.time()) if self.config.at is None else self.config.at
        valid = verify(key, code, timestamp, digits, self.config.algorithm, self.config.window)
        self.page("Code accepted." if valid else "Code rejected. Get the current code from the generator.", valid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--secret-file", type=Path, default=DEFAULT_SECRET)
    parser.add_argument("--at", type=int, help="Horodatage Unix en secondes pour les tests.")
    parser.add_argument("--digits", choices=(6, 8), type=int, default=6)
    parser.add_argument("--algorithm", choices=("sha1", "sha256", "sha512"), default="sha1")
    parser.add_argument("--window", type=int, choices=(0, 1), default=0)
    args = parser.parse_args()
    if args.at is not None and not 0 <= args.at // 30 < 2**64:
        parser.error("Horodatage Unix hors limites.")
    try:
        args.qr = QREncoder()
        args.auth = AuthStore(args.db)
    except (OSError, RuntimeError, sqlite3.Error) as error:
        parser.error(str(error))
    handler = partial(VerifyHandler, config=args)
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), handler)
    except OSError as error:
        parser.error(f"Impossible d’ouvrir le port local {args.port} ({error}).")
    with server:
        print(f"Site de test disponible sur http://127.0.0.1:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
