"""Pages et routes du parcours de connexion."""

from hmac import compare_digest
from html import escape
import re
from urllib.parse import parse_qs

from auth import USERNAME, enrollment_uri

OTP = re.compile(r"[0-9]{6}")
FORMS = {
    "/register": ("guest", "Create an account"),
    "/login": ("guest", "Sign in"),
    "/setup": ("setup", "Set up Microsoft Authenticator"),
    "/login/totp": ("challenge", "Verify your sign-in"),
    "/logout": ("full", "Sign out"),
}


def form(path, label, fields, session):
    csrf = escape(session["csrf"], quote=True)
    return (f'<form action="{path}" method="post">'
            f'<input type="hidden" name="csrf" value="{csrf}">{fields}'
            f'<button type="submit">{label}</button></form>')


def cookie(token):
    return f"totp_session={token}; Path=/; HttpOnly; SameSite=Strict"


class AuthPages:
    def html_page(self, title, content, *, status=200, message=""):
        notice = f"<output role='status'>{escape(message)}</output>" if message else ""
        html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title} · Atelier TOTP</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body><main>
<nav aria-label="Navigation"><a href="/login">Sign in</a>
<a href="/register">Sign up</a><a href="/">TOTP verifier</a></nav>
<h1>{title}</h1>
{notice}
{content}
</main></body></html>"""
        self.respond(status, "text/html; charset=utf-8", html.encode("utf-8"))

    def redirect(self, location, token=None, *, clear=False):
        headers = {"Location": location}
        if token:
            headers["Set-Cookie"] = cookie(token)
        if clear:
            headers["Set-Cookie"] = cookie("") + "; Max-Age=0"
        self.respond(303, "text/plain; charset=utf-8", b"", headers=headers)

    def form_page(self, path, session, *, status=200, message=""):
        _, title = FORMS[path]
        if path in ("/login", "/register"):
            signing_up = path == "/register"
            autocomplete = "new-password" if signing_up else "current-password"
            minimum = ' minlength="12"' if signing_up else ""
            fields = f"""
<label for="username">Username</label>
<input id="username" name="username" maxlength="32" autocomplete="username" required>
<label for="password">Password</label>
<input id="password" name="password" type="password" maxlength="128"{minimum}
       autocomplete="{autocomplete}" required>
"""
            instructions = ("<p>Use 3 to 32 characters for your username (ASCII letters, digits, "
                            "periods, hyphens, or underscores) and at least 12 characters for your password.</p>"
                            if signing_up else "")
            label = title
        else:
            fields = """
<label for="code">Six-digit code</label>
<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"
       pattern="[0-9]{6}" maxlength="6" required>
"""
            instructions = (
                "<ol>"
                "<li>Open Microsoft Authenticator on your phone.</li>"
                "<li>Tap <strong>+</strong>, then choose <strong>Other account</strong>.</li>"
                "<li>Scan the QR code below, then enter the six-digit code shown for your Atelier TOTP account.</li>"
                "</ol>"
                '<img class="qr" src="/setup/qr.png" alt="QR code to set up your Atelier TOTP account">'
                '<p><a href="https://support.microsoft.com/en-us/authenticator/how-to-add-your-accounts-to-microsoft-authenticator">Microsoft Authenticator help</a></p>'
                if path == "/setup" else
                "<p>Find your Atelier TOTP account in Microsoft Authenticator "
                "and enter the six-digit code.</p>"
            )
            label = "Enable two-factor authentication" if path == "/setup" else "Verify code"
        self.html_page(title, instructions + form(path, label, fields, session),
                       status=status, message=message)

    def auth_get(self):
        now = self.auth_now()
        session = self.auth.session(self.headers.get("Cookie", ""), now)
        path = self.path
        phase = session["phase"] if session else None
        if path in ("/login", "/register"):
            destinations = {"setup": "/setup", "challenge": "/login/totp", "full": "/account"}
            if phase in destinations:
                self.redirect(destinations[phase])
            elif session:
                self.form_page(path, session)
            else:
                self.redirect(path, self.auth.guest(now))
        elif path == "/account" and phase == "full":
            message = f'<p>You are signed in as <strong>{escape(session["username"])}</strong>.</p>'
            self.html_page("Protected account page", message + form("/logout", "Sign out", "", session))
        elif path == "/setup/qr.png" and phase == "setup":
            uri = enrollment_uri(session["username"], session["secret"])
            self.respond(200, "image/png", self.config.qr.png(uri))
        elif path in ("/setup", "/login/totp") and phase == FORMS[path][0]:
            self.form_page(path, session)
        else:
            self.redirect("/login")

    def auth_post(self):
        now = self.auth_now()
        path = self.path
        expected, _ = FORMS[path]
        session = self.auth.session(self.headers.get("Cookie", ""), now)
        if not session or session["phase"] != expected:
            self.redirect("/login")
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 4096 or self.headers.get_content_type() != "application/x-www-form-urlencoded":
                raise ValueError
            fields = parse_qs(self.rfile.read(length).decode("ascii"), max_num_fields=3,
                              errors="strict", strict_parsing=True)
            if any(len(values) != 1 for values in fields.values()):
                raise ValueError
            values = {name: value[0] for name, value in fields.items()}
        except ValueError:
            self.html_page("Invalid request", "", status=400)
            return

        csrf = values.get("csrf", "")
        if not csrf.isascii() or not compare_digest(csrf, session["csrf"]):
            self.html_page("Request denied", "", status=403)
            return
        if path == "/logout":
            self.auth.logout(session, now)
            self.redirect("/login", clear=True)
        elif path in ("/login", "/register"):
            self.credentials(path, session, values, now)
        else:
            self.second_factor(path, session, values.get("code", ""), now)

    def credentials(self, path, session, values, now):
        username = values.get("username", "").strip().lower()
        password = values.get("password", "")
        address = self.client_address[0]
        registration = path == "/register"
        scope = "register" if registration else "password"
        permitted = self.auth.allow_attempt(scope, address, 5 if registration else 10, 60, now)
        if not registration and USERNAME.fullmatch(username) and permitted:
            permitted = self.auth.allow_attempt("password-account", username, 10, 60, now)
        if not permitted:
            self.form_page(path, session, status=429, message="Too many attempts. Try again in one minute.")
        elif registration:
            if not USERNAME.fullmatch(username) or not 12 <= len(password) <= 128:
                self.form_page(path, session, status=400, message="Check your username and password against the requirements.")
                return
            token = self.auth.register(session, username, password, now)
            if token:
                self.redirect("/setup", token)
            else:
                self.form_page(path, session, status=409, message="This username is unavailable.")
        else:
            result = (self.auth.login(session, username, password, now)
                      if USERNAME.fullmatch(username) and 0 < len(password) <= 128 else None)
            if not result:
                self.form_page(path, session, status=401, message="Incorrect username or password.")
                return
            token, phase = result
            self.redirect("/setup" if phase == "setup" else "/login/totp", token)

    def second_factor(self, path, session, code, now):
        allowed = self.auth.allow_attempt("totp", str(session["user_id"]), 5, 60, now)
        if not allowed:
            self.form_page(path, session, status=429, message="Too many attempts. Try again in one minute.")
            return
        step = now // 30
        token = None
        if OTP.fullmatch(code) and self.verify_account_totp(session["secret"], code, now):
            token = self.auth.complete(session, step, now)
        if token:
            self.redirect("/account", token)
        else:
            self.form_page(path, session, status=401,
                           message="This code is incorrect, expired, or already used. Try the next code.")
