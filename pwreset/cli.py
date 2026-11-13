"""Command-line interface: python -m pwreset {reset,unlock} USERNAME"""
import argparse
import sys

from ldap3.core.exceptions import LDAPException

from . import ad, audit
from .config import load_config


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pwreset", description="Reset or unlock student/faculty AD accounts."
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("reset", "set a new temporary password (user must change it at next logon)"),
        ("unlock", "unlock a locked-out account"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("username", help="sAMAccountName, e.g. jsmith")
        p.add_argument("--reason", default="",
                       help="ticket number or short reason")
        p.add_argument("-y", "--yes", action="store_true",
                       help="skip confirmation")
        if name == "reset":
            p.add_argument("--unlock", action="store_true",
                           help="also unlock the account")
    return parser


def _confirm(action: str, user: dict) -> bool:
    answer = input(f"{action} {user['sam']} ({
                   user['name'] or 'no display name'})? [y/N] ")
    return answer.strip().lower() == "y"


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = load_config()
    target, reason = args.username, args.reason

    try:
        conn = ad.connect(cfg)
    except LDAPException as exc:
        print(f"Could not connect or bind to the directory: {
              exc}", file=sys.stderr)
        return 2

    try:
        try:
            user = ad.find_user(conn, cfg, args.username)
        except ad.ADError as exc:
            audit.log_event(args.command, target, f"refused: {exc}", reason)
            print(f"Refused: {exc}", file=sys.stderr)
            return 1
        if user is None:
            audit.log_event(args.command, target,
                            "not found in allowed OUs", reason)
            print(f"No account {
                  target!r} found in the allowed OUs.", file=sys.stderr)
            return 1

        if not args.yes and not _confirm(args.command, user):
            audit.log_event(args.command, target, "cancelled", reason)
            print("Cancelled.")
            return 1

        try:
            if args.command == "reset":
                new_password = cfg.temp_password
                ad.reset_password(conn, user["dn"], new_password)
                if args.unlock:
                    ad.unlock_account(conn, user["dn"])
                action = "reset+unlock" if args.unlock else "reset"
                audit.log_event(action, target, "success", reason)
                print(f"Temporary password for {user['sam']}: {new_password}")
                print(
                    "The user must change it at next logon. It is not stored anywhere.")
            else:
                ad.unlock_account(conn, user["dn"])
                audit.log_event("unlock", target, "success", reason)
                print(f"Unlocked {user['sam']}.")
        except (ad.ADError, LDAPException) as exc:
            audit.log_event(args.command, target, f"error: {exc}", reason)
            print(f"Operation failed: {exc}", file=sys.stderr)
            return 1
        return 0
    finally:
        conn.unbind()
