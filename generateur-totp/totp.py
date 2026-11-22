"""Génère un code TOTP à partir du secret configuré localement."""

import argparse
import hmac
from pathlib import Path
import secrets
import tempfile
import time

DEFAULT_SECRET = Path(__file__).resolve().parent.parent / ".totp-secret"


def load_or_create_secret(path):
    try:
        key = path.read_bytes()
    except FileNotFoundError:
        # Le lien publie un fichier complet sans écraser une création concurrente.
        with tempfile.NamedTemporaryFile(dir=path.parent) as temporary:
            temporary.write(secrets.token_bytes(20))
            temporary.flush()
            try:
                path.hardlink_to(temporary.name)
            except FileExistsError:
                pass
        key = path.read_bytes()
    if len(key) != 20:
        raise ValueError("Le fichier de configuration TOTP est invalide.")
    return key


def generate(key, timestamp, digits=6, algorithm="sha1"):
    counter = timestamp // 30
    if not 0 <= counter < 2**64:
        raise ValueError("Horodatage Unix hors limites.")
    digest = hmac.digest(key, counter.to_bytes(8, "big"), algorithm)
    offset = digest[-1] & 15
    value = int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff
    return str(value % 10**digits).zfill(digits)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=("code",), default="code")
    parser.add_argument("--secret-file", type=Path, default=DEFAULT_SECRET)
    parser.add_argument("--at", type=int, help="Horodatage Unix en secondes pour les tests.")
    parser.add_argument("--digits", choices=(6, 8), type=int, default=6)
    parser.add_argument("--algorithm", choices=("sha1", "sha256", "sha512"), default="sha1")
    args = parser.parse_args()

    try:
        key = load_or_create_secret(args.secret_file)
        timestamp = int(time.time()) if args.at is None else args.at
        print(generate(key, timestamp, args.digits, args.algorithm))
    except (ValueError, OSError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
