# pwreset

A small command-line tool that lets IT staff reset passwords and unlock accounts for student and faculty users in Active Directory, safely and with an audit trail. Built and tested against a lab domain (`lab.local`).

## Why it exists

Password resets are the most common help-desk request in a school (or at least at mine they are). Doing them by hand in ADUC is slow and leaves no record. This tool makes them one command, limits what the operator can touch, and logs every action.

## Design

```
operator --> CLI (argparse) --> guardrails --> LDAPS (636, cert validated) --> Domain Controller
                  |                                   ^
                  +--> audit log (JSON lines)         +-- least-privilege service account
```

- **Least privilege:** runs as a dedicated service account that has only "reset password" and "read/write lockoutTime" delegated on the Students and Faculty OUs. It is not a domain admin.
- **Scoped search:** accounts are looked up only inside the allowed OUs, so admin and service accounts outside them cannot be found or modified.
- **Privileged-account refusal:** accounts with `adminCount=1` are refused even inside an allowed OU.
- **Input validation:** usernames are checked against a strict pattern and LDAP-escaped before use, preventing filter injection.
- **Encrypted transport:** LDAPS with full certificate validation.
- **Secrets:** credentials come from environment variables / `.env`, never code.
- **Audit log:** who, what, which account, when, outcome, and reason. Passwords are never logged.

## Usage

```bash
python -m pwreset reset student1 --unlock --reason "ticket 1234"
python -m pwreset unlock student2
```

## Setup

1. `python -m venv .venv && source .venv/bin/activate`
2. `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill in your values.
4. Put your domain's root CA certificate (PEM) at the path in `AD_CA_FILE`.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest

