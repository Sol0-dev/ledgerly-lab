"""Day-scoped lab configuration.

Each calendar day gets a deterministic seed (date + reset counter). From that
seed we derive:

  * which 3 vulnerability classes are active today
  * a tech-stack fingerprint (framework identity, cookie name, API prefix,
    accent hue) so each day presents as a different deploy
  * feature toggles (which surfaces are visible today)
  * per-day secrets (admin password, internal token) used by the vulns
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from datetime import date
from typing import Any


# Valid by construction: each class maps to a real, server-verified exploit.
VULN_POOL = ["sqli", "idor", "ssti", "ssrf", "mass_assignment", "logic", "nosqli"]

ACTIVE_PER_DAY = 3

# Framework fingerprints. Each day picks one so headers, cookies and URL
# conventions change while the product stays the same.
TECH_VARIANTS = [
    {
        "id": "flask",
        "server": "gunicorn/21.2.0",
        "powered": "flask",
        "cookie": "session",
        "api": "/api/v1",
        "hue": 218,
    },
    {
        "id": "express",
        "server": "node",
        "powered": "express",
        "cookie": "connect.sid",
        "api": "/api/v2",
        "hue": 165,
    },
    {
        "id": "django",
        "server": "gunicorn/20.1.0",
        "powered": "django",
        "cookie": "sessionid",
        "api": "/api/v1",
        "hue": 262,
    },
    {
        "id": "rails",
        "server": "puma/6.4.2",
        "powered": "phusion-passenger",
        "cookie": "_ledgerly_session",
        "api": "/v1",
        "hue": 12,
    },
    {
        "id": "fastapi",
        "server": "uvicorn/0.29.0",
        "powered": None,
        "cookie": "ledgerly_sid",
        "api": "/api/v1",
        "hue": 95,
    },
]

# Feature toggles varied per day. A feature that is off is simply not exposed
# in the navigation, mirroring how real teams ship behind feature flags.
FEATURE_TOGGLES = [
    "webhooks_enabled",
    "api_keys_enabled",
    "notifications_enabled",
    "team_roles_enabled",
]

LOGIN_COPY = [
    "Sign in to run your billing",
    "Welcome back. Pick up where you left off",
    "Sign in to Ledgerly",
]


class DayContext:
    """Everything the lab knows about today."""

    def __init__(self, day: str, reset_count: int) -> None:
        self.day = day
        self.reset_count = reset_count
        self.seed = hashlib.sha256(f"{day}:{reset_count}".encode()).hexdigest()
        rng = random.Random(self.seed)

        self.active_vulns = sorted(rng.sample(VULN_POOL, ACTIVE_PER_DAY))
        self.tech = TECH_VARIANTS[rng.randrange(len(TECH_VARIANTS))]
        self.toggles = {k: bool(rng.getrandbits(1)) for k in FEATURE_TOGGLES}
        self.admin_password = _random_password(rng, 12)
        self.internal_token = _random_hex(rng, 16)
        self.api_key = "lk_live_" + _random_hex(rng, 10)
        # One generic capture flag per active class, index-aligned with
        # active_vulns. Content is opaque on purpose: a flag never says which
        # class it belongs to. Slot labels (1..3) are positional only.
        self.flags = [f"FLAG{{{_random_hex(rng, 12)}}}" for _ in range(ACTIVE_PER_DAY)]
        self.login_copy = LOGIN_COPY[rng.randrange(len(LOGIN_COPY))]
        self.version = f"2.{rng.randrange(0, 9)}.{rng.randrange(0, 9)}"

    @property
    def internal_port(self) -> int:
        return int(os.environ.get("LEDGERLY_PORT", "5001"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "day": self.day,
            "reset_count": self.reset_count,
            "active_vulns": self.active_vulns,
            "tech": self.tech,
            "toggles": self.toggles,
            "version": self.version,
            "login_copy": self.login_copy,
            "internal_token": self.internal_token,
            "api_key": self.api_key,
            "flags": self.flags,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DayContext":
        obj = cls.__new__(cls)
        obj.day = data["day"]
        obj.reset_count = data["reset_count"]
        obj.seed = hashlib.sha256(f"{obj.day}:{obj.reset_count}".encode()).hexdigest()
        obj.active_vulns = data["active_vulns"]
        obj.tech = data["tech"]
        obj.toggles = data["toggles"]
        obj.version = data["version"]
        obj.login_copy = data["login_copy"]
        obj.admin_password = data.get("admin_password")
        obj.internal_token = data["internal_token"]
        obj.api_key = data.get("api_key", "lk_live_unset")
        obj.flags = data.get("flags")
        if not obj.flags or len(obj.flags) != len(obj.active_vulns):
            # Back-compat for contexts serialized before flags existed:
            # regenerate deterministically from the same seed.
            rng = random.Random(obj.seed)
            obj.flags = [f"FLAG{{{_random_hex(rng, 12)}}}" for _ in range(len(obj.active_vulns))]
        return obj

    def fingerprint_headers(self) -> dict[str, str]:
        headers = {"Server": self.tech["server"], "X-Powered-By": self.tech["powered"]} if self.tech["powered"] else {"Server": self.tech["server"]}
        return headers


def _random_password(rng: random.Random, length: int) -> str:
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789"
    return "".join(rng.choice(alphabet) for _ in range(length))


def _random_hex(rng: random.Random, bytes_len: int) -> str:
    return rng.randbytes(bytes_len).hex()


def today_iso() -> str:
    return date.today().isoformat()


def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
