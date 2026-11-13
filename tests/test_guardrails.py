from unittest.mock import MagicMock

import pytest

from pwreset.ad import InvalidUsername, RefusedError, find_user, validate_username
from pwreset.config import Config

CFG = Config(
    server="dc01.lab.local",
    port=636,
    base_dn="DC=lab,DC=local",
    user="LAB\\svc_pwreset",
    password="x",
    ca_file=None,
    allowed_ous=("Students",),
)


def conn_returning(*entries):
    conn = MagicMock()
    conn.response = list(entries)
    return conn


def entry(admin_count=None):
    return {
        "type": "searchResEntry",
        "dn": "CN=S One,OU=Students,DC=lab,DC=local",
        "attributes": {
            "sAMAccountName": "student1",
            "displayName": "S One",
            "adminCount": admin_count,
        },
    }


@pytest.mark.parametrize("bad", ["", "a b", "x)(objectClass=*", "a" * 21, "bob*"])
def test_rejects_suspicious_usernames(bad):
    with pytest.raises(InvalidUsername):
        validate_username(bad)


def test_search_is_limited_to_allowed_ou():
    conn = conn_returning(entry())
    find_user(conn, CFG, "student1")
    assert conn.search.call_args.args[0] == "OU=Students,DC=lab,DC=local"


def test_finds_user_in_allowed_ou():
    user = find_user(conn_returning(entry()), CFG, "student1")
    assert user["sam"] == "student1"
    assert user["dn"].startswith("CN=S One")


def test_unknown_user_returns_none():
    assert find_user(conn_returning(), CFG, "nobody") is None


def test_refuses_privileged_account():
    with pytest.raises(RefusedError):
        find_user(conn_returning(entry(admin_count=1)), CFG, "student1")


def test_refuses_ambiguous_match():
    with pytest.raises(RefusedError):
        find_user(conn_returning(entry(), entry()), CFG, "student1")
