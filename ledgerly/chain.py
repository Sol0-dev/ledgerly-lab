"""Chain engine: compound primitives drawn per day.

The chain is the lab's "complex chained vulnerability". Each day the draw
pins one recipe - a chain of 2-4 primitives that must ALL fire before the
compound surface unlocks. Unlocking is server-verified: the hunter must
present the flag outputs of every component together, proving the outputs of
one primitive were carried into the next surface.

Recipes are named after real attack chains (see chain-hunt skill):
  * forge_read         JWT alg:none + IDOR                    -> mass read of any ledger
  * hook_leak          SSRF + config leak                     -> webhook fetches internal secrets
  * cross_write_exec   CSRF + stored XSS + prototype pollution -> cross-site profile write that
                                                                  executes for the reviewer
  * redirect_token     open redirect + OAuth + token lifecycle -> token forwarded to attacker
  * price_race         negative-price logic + coupon race + mass assignment -> balance printed
  * xml_shell          XXE + command injection + path traversal -> file entity reaches the shell
  * server_hold        SQLi + deserialization + SSTI + JWT    -> full stack compromise

The chain surface is presented as a normal product page ("Security &
recovery" -> account ownership verification) - nothing names a class or
mentions chaining.
"""

from __future__ import annotations

from typing import Any

# Each recipe: id, an ordered-ish tuple of 2-4 vulnerability types (order
# irrelevant), and one cryptic but business-sounding factor descriptor per
# component. Factors reference the *features* (surfaces), never the class
# names, so the page stays normal-looking.
CHAIN_RECIPES: list[dict[str, Any]] = [
    {
        "id": "forge_read",
        "components": ("jwt", "idor"),
        "factors": [
            "A credential minted at the API keys desk",
            "A ledger opened from the invoice counter",
        ],
        "recovery_name": "Issuer recovery code",
    },
    {
        "id": "hook_leak",
        "components": ("ssrf", "infoleak"),
        "factors": [
            "A webhook line that calls home",
            "A status panel that talks about itself",
        ],
        "recovery_name": "Relay recovery code",
    },
    {
        "id": "cross_write_exec",
        "components": ("csrf", "xss", "prototype_pollution"),
        "factors": [
            "A form that moves without being asked",
            "A profile field that runs on read",
            "A theme that spreads without being told",
        ],
        "recovery_name": "Scripted recovery code",
    },
    {
        "id": "redirect_token",
        "components": ("open_redirect", "oauth", "token_mgmt"),
        "factors": [
            "A return path that trusts its tail",
            "A partner handshake without a handshake",
            "A key that survives its own rotation",
        ],
        "recovery_name": "Handoff recovery code",
    },
    {
        "id": "price_race",
        "components": ("logic", "race", "mass_assignment"),
        "factors": [
            "A line item priced below zero",
            "A promo that double-spends",
            "A role granted without a raise",
        ],
        "recovery_name": "Ledger recovery code",
    },
    {
        "id": "xml_shell",
        "components": ("xxe", "cmdi", "lfi"),
        "factors": [
            "A document that reads files for you",
            "An export that echoes commands",
            "A download that walks directories",
        ],
        "recovery_name": "Document recovery code",
    },
    {
        "id": "server_hold",
        "components": ("sqli", "deser", "ssti", "jwt"),
        "factors": [
            "A sign-in that trusts its query",
            "A restore that runs packaged objects",
            "A preview that renders your text",
            "A token minted with no signature",
        ],
        "recovery_name": "Root recovery code",
    },
]

CHAIN_JOINER = "||"


def pick_recipe(rng) -> dict[str, Any]:
    """Deterministically choose today's chain recipe."""
    return dict(CHAIN_RECIPES[rng.randrange(len(CHAIN_RECIPES))])


def chain_code(flags: list[str]) -> str:
    """The compound code the hunter must present to the recovery surface.
    Component order is normalised so any submission order verifies."""
    return CHAIN_JOINER.join(sorted(flags))


def parse_chain_code(code: str) -> list[str] | None:
    if not code or CHAIN_JOINER not in code:
        return None
    parts = [p.strip() for p in code.split(CHAIN_JOINER) if p.strip()]
    if not parts:
        return None
    return parts
