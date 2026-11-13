"""Configuration loaded from environment variables (optionally via a .env file)."""
import os
from dataclasses import dataclass

from dotenv import load_dotenv

REQUIRED = ("AD_SERVER", "AD_BASE_DN", "AD_USER", "AD_PASSWORD")


@dataclass(frozen=True)
class Config:
    server: str
    port: int
    base_dn: str
    user: str
    password: str
    ca_file: str | None
    allowed_ous: tuple[str, ...]
    temp_password: str | None = None

    @property
    def allowed_dns(self) -> tuple[str, ...]:
        """Full DNs of the only OUs this tool may touch."""
        return tuple(f"OU={ou},{self.base_dn}" for ou in self.allowed_ous)


def load_config() -> Config:
    load_dotenv()
    missing = [key for key in REQUIRED if not os.environ.get(key)]
    if missing:
        raise SystemExit(
            f"Missing required settings: {
                ', '.join(missing)} (see .env.example)"
        )
    ous = tuple(
        ou.strip()
        for ou in os.environ.get("AD_ALLOWED_OUS", "Students").split(";")
        if ou.strip()
    )
    return Config(
        server=os.environ["AD_SERVER"],
        port=int(os.environ.get("AD_PORT", "636")),
        base_dn=os.environ["AD_BASE_DN"],
        user=os.environ["AD_USER"],
        password=os.environ["AD_PASSWORD"],
        ca_file=os.environ.get("AD_CA_FILE") or None,
        allowed_ous=ous,
        temp_password=os.environ.get("AD_TEMP_PASSWORD") or None,
    )
