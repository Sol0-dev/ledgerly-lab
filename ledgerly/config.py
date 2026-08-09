"""Day-scoped lab configuration.

Each calendar day gets a deterministic seed (date + reset counter). From that
seed we derive:

  * which 3 vulnerability classes are active today (drawn so that at least
    one pair maps to a chain recipe - the compound vulnerability)
  * a tech-stack fingerprint (framework identity, cookie name, API prefix,
    accent hue) so each day presents as a different deploy
  * feature toggles (which surfaces are visible today)
  * per-day secrets (admin password, internal token, coupon, chain) used by
    the vulns

Everything a hunter sees is a normal-looking product surface: nothing on any
page, header, or payload names a vulnerability class or hints at the draw.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
from datetime import date
from typing import Any

from . import chain as chainmod

# Valid by construction: each class maps to a real, server-verified exploit.
# The surface each lives on is a normal product feature (sign-in, invoice
# detail, export, import, theme, partner sign-in, ...) - the class never
# appears on the page itself.
VULN_POOL = [
    # original 7
    "sqli", "idor", "ssti", "ssrf", "mass_assignment", "logic", "nosqli",
    # 17 added - hidden behind normal-looking product features
    "xss", "csrf", "cors", "open_redirect", "clickjacking",
    "jwt", "oauth",
    "deser", "lfi", "cmdi", "xxe",
    "race", "redos",
    "infoleak", "graphql", "prototype_pollution", "token_mgmt",
]

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
        "hue": 200,
    },
    {
        "id": "express",
        "server": "node",
        "powered": "express",
        "cookie": "connect.sid",
        "api": "/api/v2",
        "hue": 208,
    },
    {
        "id": "django",
        "server": "gunicorn/20.1.0",
        "powered": "django",
        "cookie": "sessionid",
        "api": "/api/v1",
        "hue": 214,
    },
    {
        "id": "rails",
        "server": "puma/6.4.2",
        "powered": "phusion-passenger",
        "cookie": "_ledgerly_session",
        "api": "/v1",
        "hue": 205,
    },
    {
        "id": "fastapi",
        "server": "uvicorn/0.29.0",
        "powered": None,
        "cookie": "ledgerly_sid",
        "api": "/api/v1",
        "hue": 198,
    },
]

# Feature toggles varied per day. A feature that is off is simply not exposed
# in the navigation, mirroring how real teams ship behind feature flags.
# A toggle MUST be forced on whenever the day draws a vuln class that lives on
# that surface - otherwise the flag would be unreachable.
SURFACE_TOGGLES: dict[str, str] = {
    "ssrf": "webhooks_enabled",
    "ssti": "notifications_enabled",
    "jwt": "api_keys_enabled",
    "token_mgmt": "api_keys_enabled",
}

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

# Normal-looking surfaces for the 17 added classes. Docs/API pages reference
# these as ordinary product endpoints. Only used for matching + analytics.
NEW_SURFACES = {
    "xss": "team/profile",
    "csrf": "invoice status",
    "cors": "clients api",
    "open_redirect": "billing return",
    "clickjacking": "account",
    "jwt": "api keys",
    "oauth": "partner sign-in",
    "deser": "backup restore",
    "lfi": "documents",
    "cmdi": "export",
    "xxe": "import",
    "race": "coupons",
    "redos": "search",
    "infoleak": "health",
    "graphql": "graphql",
    "prototype_pollution": "theme",
    "token_mgmt": "api key rotation",
}


class DayContext:
    """Everything the lab knows about today."""

    def __init__(self, day: str, reset_count: int) -> None:
        self.day = day
        self.reset_count = reset_count
        self.seed = hashlib.sha256(f"{day}:{reset_count}".encode()).hexdigest()
        rng = random.Random(self.seed)

        # Draw the chain recipe (its components are today's compound chain),
        # but every class in the pool is active every day - the full lab is
        # open, not a 2-4 class subset. The chain recipe only decides which
        # classes the compound recovery surface requires.
        recipe = chainmod.pick_recipe(rng)
        self.chain_recipe = recipe["id"]
        active = sorted(set(VULN_POOL))
        self.active_vulns = active

        self.tech = TECH_VARIANTS[rng.randrange(len(TECH_VARIANTS))]
        self.toggles = {k: True for k in FEATURE_TOGGLES}
        for cls in self.active_vulns:
            needed = SURFACE_TOGGLES.get(cls)
            if needed:
                self.toggles[needed] = True
        self.admin_password = _random_password(rng, 12)
        self.internal_token = _random_hex(rng, 16)
        self.api_key = "lk_live_" + _random_hex(rng, 10)
        # One generic capture flag per active class, index-aligned with
        # active_vulns. Content is opaque on purpose: a flag never says which
        # class it belongs to. Slot labels are positional only.
        self.flags = [f"FLAG{{{_random_hex(rng, 12)}}}" for _ in range(len(self.active_vulns))]
        # Chain: the 4th, compound flag. Its two factors reference the two
        # surfaces the hunter must combine.
        self.chain_flag = f"FLAG{{{_random_hex(rng, 12)}}}"
        # Surface secrets used by the new primitives.
        self.coupon_code = "PROMO-" + _random_hex(rng, 5).upper()
        self.jwt_secret = "ledgerly-signing-" + _random_hex(rng, 4)
        self.partner_client_id = "partner-" + _random_hex(rng, 4)
        self.login_copy = LOGIN_COPY[rng.randrange(len(LOGIN_COPY))]
        self.version = f"2.{rng.randrange(0, 9)}.{rng.randrange(0, 9)}"
        self.theme_json = json.dumps({
            "name": self.tech["id"],
            "accent": f"hsl({self.tech['hue']} 58% 45%)",
            "radius": 12,
            "density": "compact",
        })

    @property
    def internal_port(self) -> int:
        return int(os.environ.get("LEDGERLY_PORT", "5001"))

    @property
    def chain_factors(self) -> list[str]:
        recipe = next(r for r in chainmod.CHAIN_RECIPES if r["id"] == self.chain_recipe)
        return recipe["factors"]

    @property
    def chain_pair(self) -> list[str]:
        recipe = next(r for r in chainmod.CHAIN_RECIPES if r["id"] == self.chain_recipe)
        return list(recipe["components"])

    def chain_code_expected(self) -> str:
        flags = [self._flag_for(c) for c in self.chain_pair]
        return chainmod.chain_code(flags)

    def _flag_for(self, cls: str) -> str | None:
        if cls not in self.active_vulns:
            return None
        return self.flags[self.active_vulns.index(cls)]

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
            "chain": {
                "id": self.chain_recipe,
                "pair": self.chain_pair,
                "components": self.chain_pair,
                "flag": self.chain_flag,
                "factors": self.chain_factors,
            },
            "coupon_code": self.coupon_code,
            "jwt_secret": self.jwt_secret,
            "partner_client_id": self.partner_client_id,
            "theme_json": self.theme_json,
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
            rng = random.Random(obj.seed)
            obj.flags = [f"FLAG{{{_random_hex(rng, 12)}}}" for _ in range(len(obj.active_vulns))]
        chain = data.get("chain") or {}
        obj.chain_recipe = chain.get("id")
        if not obj.chain_recipe or not any(r["id"] == obj.chain_recipe for r in chainmod.CHAIN_RECIPES):
            rng = random.Random(obj.seed + ":chain")
            obj.chain_recipe = chainmod.pick_recipe(rng)["id"]
        obj.chain_flag = chain.get("flag")
        if not obj.chain_flag:
            rng = random.Random(obj.seed + ":chainflag")
            obj.chain_flag = f"FLAG{{{_random_hex(rng, 12)}}}"
        obj.coupon_code = data.get("coupon_code", "PROMO-RESET")
        obj.jwt_secret = data.get("jwt_secret", "ledgerly-signing-reset")
        obj.partner_client_id = data.get("partner_client_id", "partner-reset")
        obj.theme_json = data.get("theme_json") or json.dumps({"accent": "#0a5", "radius": 12})
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
