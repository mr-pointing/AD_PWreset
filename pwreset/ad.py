"""Active Directory operations, with guardrails applied before any change."""
import re
import ssl

from ldap3 import MODIFY_REPLACE, SUBTREE, Connection, Server, Tls
from ldap3.utils.conv import escape_filter_chars

from .config import Config

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,20}$")  # sAMAccountName max is 20
ATTRS = ["sAMAccountName", "displayName", "adminCount"]


class ADError(Exception):
    """An Active Directory operation failed."""


class InvalidUsername(ADError):
    """The supplied username is not a plausible sAMAccountName."""


class RefusedError(ADError):
    """A guardrail blocked the operation."""


def validate_username(username: str) -> str:
    if not USERNAME_RE.fullmatch(username):
        raise InvalidUsername(f"invalid username: {username!r}")
    return username


def connect(cfg: Config) -> Connection:
    """Open an encrypted (LDAPS) connection with full certificate validation."""
    tls = Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=cfg.ca_file)
    server = Server(cfg.server, port=cfg.port, use_ssl=True, tls=tls)
    return Connection(server, user=cfg.user, password=cfg.password, auto_bind=True)


def _first(value):
    if isinstance(value, list):
        return value[0] if value else None
    return value


def find_user(conn: Connection, cfg: Config, username: str) -> dict | None:
    """Look up a user, searching ONLY inside the allowed OUs.

    Accounts elsewhere in the directory (admins, service accounts) are
    invisible to this tool. Accounts flagged adminCount=1 (members of
    privileged groups) are refused even if they sit inside an allowed OU.
    """
    username = validate_username(username)
    flt = (
        "(&(objectCategory=person)(objectClass=user)"
        f"(sAMAccountName={escape_filter_chars(username)}))"
    )
    for base in cfg.allowed_dns:
        conn.search(base, flt, search_scope=SUBTREE, attributes=ATTRS, size_limit=2)
        hits = [r for r in (conn.response or []) if r.get("type") == "searchResEntry"]
        if len(hits) > 1:
            raise RefusedError(f"{username!r} matched more than one account")
        if hits:
            attrs = hits[0]["attributes"]
            if str(_first(attrs.get("adminCount"))) == "1":
                raise RefusedError(f"{username!r} is a protected (privileged) account")
            return {
                "dn": hits[0]["dn"],
                "sam": _first(attrs.get("sAMAccountName")) or username,
                "name": _first(attrs.get("displayName")) or "",
            }
    return None


def _check(conn: Connection, what: str) -> None:
    if conn.result["result"] != 0:
        raise ADError(f"{what} failed: {conn.result.get('message') or conn.result}")


def reset_password(conn: Connection, dn: str, new_password: str) -> None:
    """Set a new password and force a change at next logon."""
    if not conn.extend.microsoft.modify_password(dn, new_password):
        raise ADError(f"password reset failed: {conn.result.get('message')}")
    conn.modify(dn, {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
    _check(conn, "forcing password change at next logon")


def unlock_account(conn: Connection, dn: str) -> None:
    conn.modify(dn, {"lockoutTime": [(MODIFY_REPLACE, [0])]})
    _check(conn, "unlock")
