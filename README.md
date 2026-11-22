# Atelier TOTP and Two-Factor Authentication

Atelier TOTP provides a two-factor sign-up and sign-in flow, plus a standalone verifier for the command-line generator.

The site requires Python 3, SQLite 3.35 or later, and **libqrencode** to generate QR codes locally. On Debian and Ubuntu, the package is called `libqrencode4`. The standalone generator uses only the Python standard library.

## Run the site

From the project root, start the server and open <http://127.0.0.1:8000>.

```sh
python3 site-tests/server.py
```

## Sign up and sign in with two-factor authentication

1. Select **Sign up** and choose a username and a password of at least 12 characters.
2. In Microsoft Authenticator, tap **+**, choose **Other account**, and scan the QR code shown on the site. Enter the six-digit code for **Atelier TOTP** to enable two-factor authentication and open the protected account page.
3. Sign out to try the login flow. Enter your username and password, then enter a fresh code from Microsoft Authenticator. Each code can be accepted only once, including the code used during setup. If needed, wait for the next code.

The server stores accounts, sessions, and rate limits in `site-tests/accounts.sqlite3` by default. Use `--db` to select a different database file.

## Standalone generator and verifier

In a second terminal, run the generator and paste the displayed code into the **TOTP verifier** on the site's home page. The generator creates a shared secret on its first run. Each registered account has its own secret configured in Microsoft Authenticator.

```sh
python3 generateur-totp/totp.py
```

Run the command again to get the current code. The generator and server use their system clocks. By default, each code has six digits and is valid for the current 30-second period.

## Reproducible tests

To test at a fixed time, run the server and generator with the same Unix timestamp. The verifier form still takes only the code.

```sh
python3 site-tests/server.py --at 59
python3 generateur-totp/totp.py --at 59
```

Both programs accept `--digits`, `--algorithm`, and `--secret-file`. By default, they use SHA-1 and the private `.totp-secret` file in the project root. If the projects are moved to separate directories on the same machine, pass the same absolute path to both programs with `--secret-file`. The server listens on the loopback interface.

The server's fixed timestamp, verification window, and algorithm options apply to the standalone verifier. Account authentication uses the current time, SHA-1, six digits, and the current 30-second period.

## Automated tests

From the project root, run the HTTP flow and standalone generator tests.

```sh
PYTHONPATH=site-tests python3 -m unittest discover -s site-tests/tests -v
```
