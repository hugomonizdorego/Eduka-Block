#!/usr/bin/python3
"""Recover the Eduka-Block parent/teacher account from a terminal.

Usage (as root):
    sudo eduka-block-reset                  show the username and set a new password
    sudo eduka-block-reset --show-username  only print the stored username
    sudo eduka-block-reset --remove         delete the account; the next start
                                            of Eduka-Block asks to create a new one

Knowing the operating-system administrator (sudo) password is what entitles
someone to recover the account, exactly like the "Forgot username or
password?" button on the sign-in screen. Protection rules are not changed.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import tempfile
from pathlib import Path

LIB_DIR = Path("/usr/lib/eduka-block")
SOURCE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE_DIR if (SOURCE_DIR / "eduka_block_common.py").is_file() else LIB_DIR))

from eduka_block_common import (  # noqa: E402
    CREDENTIALS_PATH,
    ValidationError,
    create_credentials_text,
    read_credentials,
    validate_account,
)

ERRORS = {
    "err_username": "The username must have 3-64 characters and cannot contain '='.",
    "err_password_length": "The password must have at least 5 characters.",
}


def stored_username(path: Path = CREDENTIALS_PATH) -> str:
    try:
        return read_credentials(path)["username"]
    except ValidationError:
        return ""


def write_credentials(username: str, password: str, path: Path = CREDENTIALS_PATH) -> None:
    """Atomically replace the credentials file (root-owned, mode 0644)."""
    text = create_credentials_text(username, password)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass


def ask_new_account(current: str) -> tuple[str, str]:
    prompt = f"New username [{current}]: " if current else "New username: "
    while True:
        username = input(prompt).strip() or current
        password = getpass.getpass("New password (minimum 5 characters): ")
        if password != getpass.getpass("Repeat the new password: "):
            print("The passwords do not match. Try again.\n")
            continue
        try:
            validate_account(username, password)
        except ValidationError as exc:
            print(ERRORS.get(exc.code, exc.code) + " Try again.\n")
            continue
        return username, password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="eduka-block-reset",
        description="Recover the Eduka-Block parent/teacher account (requires root).",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--show-username", action="store_true", help="only print the stored username")
    group.add_argument("--remove", action="store_true", help="delete the account so a new one can be created")
    args = parser.parse_args(argv)

    if os.geteuid() != 0:
        print("Run this command as root: sudo eduka-block-reset", file=sys.stderr)
        return 1

    current = stored_username() if CREDENTIALS_PATH.is_file() else ""
    if args.show_username:
        if not current:
            print("No Eduka-Block account exists yet. Open Eduka-Block to create one.")
            return 1
        print(current)
        return 0
    if args.remove:
        if not CREDENTIALS_PATH.exists():
            print("No Eduka-Block account exists.")
            return 0
        if input("Delete the Eduka-Block account? Type 'yes' to confirm: ").strip().lower() != "yes":
            print("Cancelled.")
            return 1
        CREDENTIALS_PATH.unlink()
        print("Account deleted. The next start of Eduka-Block asks to create a new account.")
        return 0

    print("Eduka-Block account recovery")
    print(f"Current username: {current}" if current else "No valid account is stored; a new one will be created.")
    try:
        username, password = ask_new_account(current)
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        return 1
    write_credentials(username, password)
    print(f"Saved. Sign in to Eduka-Block as '{username}' with the new password.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
