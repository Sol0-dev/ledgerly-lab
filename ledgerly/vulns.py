"""Vulnerability registry, report quality scoring, analytics computation.

The registry is metadata only. The actual vulnerable behaviour lives in
web.py route handlers, which call store.mark_exploited once the real
primitive fires. Triage decides whether a REPORT is valid, never whether the
vulnerability exists: every seeded class is valid and exploitable by design.
"""

from __future__ import annotations

from typing import Any

from . import store

# Metadata per class. Skills path matches .opencode/skills/<class>-hunt/SKILL.md.
# `feature` is the normal-looking product surface where the flag hides - it is
# never shown to the hunter as a hint. `skill` drives analytics + match hints.
REGISTRY: dict[str, dict[str, Any]] = {
    "sqli": {
        "label": "SQL injection",
        "feature": "Sign in",
        "hint": "Auth query built from raw input",
        "skill": "injection-hunt",
        "severity": "critical",
        "example_payload": "administrator'--",
    },
    "idor": {
        "label": "Insecure direct object reference",
        "feature": "Invoice detail",
        "hint": "Object id taken from the path with no ownership check",
        "skill": "auth-hunt",
        "severity": "high",
        "example_payload": "GET /invoices/4",
    },
    "ssti": {
        "label": "Server-side template injection",
        "feature": "Notification preview",
        "hint": "Editor input rendered as a template",
        "skill": "injection-hunt",
        "severity": "critical",
        "example_payload": "{{7*7}}",
    },
    "ssrf": {
        "label": "Server-side request forgery",
        "feature": "Webhook test",
        "hint": "Outbound fetch driven by user URL",
        "skill": "injection-hunt",
        "severity": "high",
        "example_payload": "http://127.0.0.1:5001/internal/secret",
    },
    "mass_assignment": {
        "label": "Mass assignment",
        "feature": "Team settings API",
        "hint": "Request body merged into the user object",
        "skill": "logic-hunt",
        "severity": "high",
        "example_payload": '{"role":"admin"}',
    },
    "logic": {
        "label": "Business logic flaw",
        "feature": "Invoice lines",
        "hint": "Negative or zero price / quantity accepted",
        "skill": "logic-hunt",
        "severity": "high",
        "example_payload": '{"qty":-5,"unit_price":50}',
    },
    "nosqli": {
        "label": "NoSQL injection",
        "feature": "Client list filter",
        "hint": "JSON filter operators accepted verbatim",
        "skill": "injection-hunt",
        "severity": "medium",
        "example_payload": '{"access":{"$ne":"__none__"}}',
    },
    "xss": {
        "label": "Cross-site scripting",
        "feature": "Team / profile",
        "hint": "Stored field rendered without escaping",
        "skill": "clientside-hunt",
        "severity": "high",
        "example_payload": "<script>alert(1)</script>",
    },
    "csrf": {
        "label": "Cross-site request forgery",
        "feature": "Invoice status",
        "hint": "State change with no token or origin check",
        "skill": "clientside-hunt",
        "severity": "medium",
        "example_payload": "POST /invoices/3/status",
    },
    "cors": {
        "label": "CORS misconfiguration",
        "feature": "Clients API",
        "hint": "Reflected origin with credentials",
        "skill": "clientside-hunt",
        "severity": "medium",
        "example_payload": "Origin: https://evil.example",
    },
    "open_redirect": {
        "label": "Open redirect",
        "feature": "Billing return",
        "hint": "Unvalidated redirect target",
        "skill": "clientside-hunt",
        "severity": "low",
        "example_payload": "/billing/return?to=https://evil.example",
    },
    "clickjacking": {
        "label": "Clickjacking",
        "feature": "Account page",
        "hint": "No frame-busting headers on sensitive page",
        "skill": "clientside-hunt",
        "severity": "low",
        "example_payload": "<iframe src=/account>",
    },
    "jwt": {
        "label": "JWT weakness",
        "feature": "API keys",
        "hint": "alg:none accepted on signed tokens",
        "skill": "auth-hunt",
        "severity": "high",
        "example_payload": "alg=none forged token",
    },
    "oauth": {
        "label": "OAuth flow flaw",
        "feature": "Partner sign-in",
        "hint": "Missing state / unverified code exchange",
        "skill": "auth-hunt",
        "severity": "high",
        "example_payload": "/auth/partner?state=",
    },
    "deser": {
        "label": "Insecure deserialization",
        "feature": "Backup restore",
        "hint": "Untrusted blob unpickled",
        "skill": "injection-hunt",
        "severity": "critical",
        "example_payload": "pickle RCE payload",
    },
    "lfi": {
        "label": "Path traversal",
        "feature": "Documents",
        "hint": "Filename used in open() unchecked",
        "skill": "injection-hunt",
        "severity": "high",
        "example_payload": "/documents/../../etc/passwd",
    },
    "cmdi": {
        "label": "Command injection",
        "feature": "Export",
        "hint": "User input reaches a shell command",
        "skill": "injection-hunt",
        "severity": "critical",
        "example_payload": "; id",
    },
    "xxe": {
        "label": "XML external entity",
        "feature": "Import",
        "hint": "DOCTYPE entity expanded from user XML",
        "skill": "injection-hunt",
        "severity": "high",
        "example_payload": "<!DOCTYPE xxe [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>",
    },
    "race": {
        "label": "Race condition",
        "feature": "Coupons",
        "hint": "Check-then-act without a lock",
        "skill": "logic-hunt",
        "severity": "high",
        "example_payload": "parallel redeem burst",
    },
    "redos": {
        "label": "ReDoS",
        "feature": "Search",
        "hint": "User pattern compiled into a regex",
        "skill": "logic-hunt",
        "severity": "medium",
        "example_payload": "^(a+)+$",
    },
    "infoleak": {
        "label": "Sensitive info disclosure",
        "feature": "Health",
        "hint": "Runtime config exposed by status endpoint",
        "skill": "infodisclosure-hunt",
        "severity": "medium",
        "example_payload": "GET /api/v1/health",
    },
    "graphql": {
        "label": "GraphQL flaw",
        "feature": "GraphQL console",
        "hint": "Introspection on, authorization off",
        "skill": "injection-hunt",
        "severity": "high",
        "example_payload": "{__schema{types{name}}}",
    },
    "prototype_pollution": {
        "label": "Prototype pollution",
        "feature": "Theme",
        "hint": "JSON merge walks __proto__",
        "skill": "clientside-hunt",
        "severity": "high",
        "example_payload": '{"__proto__":{"isAdmin":true}}',
    },
    "token_mgmt": {
        "label": "Token lifecycle gap",
        "feature": "API key rotation",
        "hint": "Rotated key keeps working",
        "skill": "auth-token-mgmt",
        "severity": "high",
        "example_payload": "rotate then reuse old key",
    },
    "chain": {
        "label": "Chained attack",
        "feature": "Security / recovery",
        "hint": "Two primitives combined on a compound surface",
        "skill": "chain-hunt",
        "severity": "critical",
        "example_payload": "chain code on recovery surface",
    },
}

SEVERITIES = ["critical", "high", "medium", "low"]

# Reference priors, aligned with the repo's solve-rate-by-class.md estimates.
# Used by analytics to show where the player is below expectation.
WIKI_ESTIMATES: dict[str, float] = {
    "sqli": 0.95,
    "idor": 0.95,
    "ssti": 0.85,
    "ssrf": 0.90,
    "mass_assignment": 0.90,
    "logic": 0.80,
    "nosqli": 0.80,
    "xss": 0.85,
    "csrf": 0.80,
    "cors": 0.75,
    "open_redirect": 0.90,
    "clickjacking": 0.90,
    "jwt": 0.85,
    "oauth": 0.80,
    "deser": 0.70,
    "lfi": 0.95,
    "cmdi": 0.85,
    "xxe": 0.80,
    "race": 0.65,
    "redos": 0.60,
    "infoleak": 0.90,
    "graphql": 0.75,
    "prototype_pollution": 0.60,
    "token_mgmt": 0.75,
    "chain": 0.40,
}


def score_report(fields: dict[str, Any], actual_class: str | None) -> int:
    """0-100 quality score for a submitted report.

    Quality covers completeness, accuracy of the claimed class and severity,
    and reproducibility. Accuracy components only count when the report can be
    matched to an actual class.
    """
    score = 0

    completeness = [
        bool(fields.get("title")),
        bool(fields.get("endpoint")),
        bool(fields.get("payload")),
        bool(fields.get("impact")),
        bool(fields.get("fix")),
    ]
    score += int(sum(completeness) / len(completeness) * 40)

    repro_steps = [s.strip() for s in (fields.get("repro") or "").splitlines() if s.strip()]
    score += min(20, len(repro_steps) * 7)

    if actual_class:
        claimed = (fields.get("class") or "").strip()
        if claimed and claimed.lower() == actual_class:
            score += 20
        elif claimed:
            score += 5  # correct feature, wrong class label

        claimed_sev = (fields.get("severity") or "").strip()
        expected = REGISTRY[actual_class]["severity"]
        sev_order = {s: i for i, s in enumerate(SEVERITIES)}
        if claimed_sev == expected:
            score += 15
        elif claimed_sev in sev_order and expected in sev_order:
            gap = abs(sev_order[claimed_sev] - sev_order[expected])
            score += max(0, 15 - gap * 7)
    else:
        score += min(15, score)  # base for class/severity section when unmatchable

    return min(100, score)


def match_report(fields: dict[str, Any], day: str, ctx: dict[str, Any]) -> str | None:
    """Best-effort match of a report to an exploited active class.

    Matching is by claimed class first, then by the exploit detail free-text.
    A report never matches a class that was not actually exploited.
    """
    claimed = (fields.get("class") or "").strip().lower()
    active = ctx["active_vulns"]

    if claimed and claimed in active:
        if store.vuln_status(day, claimed) in ("exploited", "reported", "validated"):
            return claimed

    # Fall back to keyword scan of the exploit detail / endpoint text.
    endpoint = (fields.get("endpoint") or "").lower()
    for cls in active:
        meta = REGISTRY[cls]
        endpoint = endpoint or ""
        if meta["feature"].lower() in endpoint or cls in endpoint:
            if store.vuln_status(day, cls) in ("exploited", "reported", "validated"):
                return cls
    return None


def compute_analytics(ctx: dict[str, Any]) -> dict[str, Any]:
    """Assemble the analytics dashboard payload from persisted state."""
    day = ctx["day"]
    active = ctx["active_vulns"]
    start = store.get_day_state(day)["started_at"] if store.get_day_state(day) else None

    vulns = {v["class"]: v for v in store.day_vuln_rows(day)}
    reports = store.list_reports(day=day)
    history = store.all_history()
    flags = store.list_flags()

    per_class: dict[str, Any] = {}
    for cls in sorted(set(list(vulns) + active)):
        state = vulns.get(cls, {"status": "active"})
        exploitable = cls in active or cls == "chain"
        found = state["status"] in ("exploited", "reported", "validated")
        t_found = state.get("exploited_at")
        matched = [r for r in reports if r["matched_class"] == cls]
        validated = state["status"] == "validated"
        t_found = state.get("exploited_at")
        per_class[cls] = {
            "active": exploitable,
            "found": found,
            "exploited_at": t_found,
            "ttv": (t_found - start) if (t_found and start) else None,
            "validated": validated,
            "reports": len(matched),
            "best_score": max([r["score"] for r in matched], default=0),
            "triage_ok": sum(1 for r in matched if r["triage_status"] == "accepted"),
        }

    found_total = sum(1 for v in per_class.values() if v["active"] and v["found"])
    active_total = sum(1 for v in per_class.values() if v["active"])
    validated_total = sum(1 for v in per_class.values() if v["active"] and v["validated"])

    t_founds = [v["exploited_at"] - start for v in per_class.values() if v["active"] and v["exploited_at"] and start]

    scores = [r["score"] for r in reports]
    class_accurate = sum(
        1 for r in reports if r["matched_class"] and (r["class"] or "").lower() == r["matched_class"]
    )
    sev_accurate = sum(
        1 for r in reports if r["matched_class"]
        and (r["severity"] or "").lower() == REGISTRY[r["matched_class"]]["severity"]
    )

    completed = bool(store.get_day_state(day)["completed"])

    history_rows = []
    for h in history:
        if h["day"] == day:
            continue
        history_rows.append(h)

    # ---- Hunter-centric analytics (reporting desk only) --------------------
    captures = store.day_captures(day)
    captures.sort(key=lambda c: c["captured_at"])
    chain_slot = len(active) + 1
    sev_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def _slot_class(slot: int) -> str:
        if slot == chain_slot:
            return "chain"
        if 1 <= slot <= len(active):
            return active[slot - 1]
        return "?"

    speed_rows: list[dict[str, Any]] = []
    for c in captures:
        cls = _slot_class(c["slot"])
        ttf = (c["captured_at"] - start) if start else None
        weight = sev_weight.get(REGISTRY[cls]["severity"], 2) if cls in REGISTRY else 4
        speed_rows.append({
            "slot": c["slot"],
            "class": cls,
            "label": REGISTRY[cls]["label"] if cls in REGISTRY else "Chain",
            "severity": REGISTRY[cls]["severity"] if cls in REGISTRY else "critical",
            "weight": weight,
            "ttf": ttf,
            "ttf_min": round(ttf / 60, 1) if ttf is not None else None,
        })

    flags_found = len(captures)
    ttfs = [r["ttf"] for r in speed_rows if r["ttf"] is not None]
    fastest_find = round(min(ttfs), 1) if ttfs else None
    mean_find = round(sum(ttfs) / len(ttfs), 1) if ttfs else None
    # Speed meter: faster flags score higher (0s = 100, 15min+ = 0).
    speed_score = (
        round(max(0, min(100, 100 * (1 - fastest_find / 900)))) if fastest_find is not None else 0
    )

    available_weight = sum(
        sev_weight.get(REGISTRY[c]["severity"], 2) for c in active
    ) + (4 if ctx.get("chain") else 0)
    captured_weight = sum(r["weight"] for r in speed_rows)
    impact = round(captured_weight / available_weight * 100) if available_weight else 0
    complexity_index = round(captured_weight / len(speed_rows), 2) if speed_rows else 0.0
    complexity_pct = round(complexity_index / 4 * 100) if speed_rows else 0

    chain_done = (
        "chain" in per_class and per_class["chain"]["found"]
    ) or any(r["class"] == "chain" for r in speed_rows)
    explored = store.touched_surfaces(day)
    creativity = min(100, (60 if chain_done else 0) + min(len(explored) * 8, 40))

    # Persona level - deliberately generous, never harsh.
    persona_points = flags_found * 2
    persona_points += len(reports)
    if fastest_find is not None:
        persona_points += 2 if fastest_find <= 300 else 1
    if chain_done:
        persona_points += 2
    if completed:
        persona_points += 1
    persona = _persona_level(persona_points)

    return {
        "day": day,
        "active_vulns": active,
        "active_total": active_total,
        "found_total": found_total,
        "validated_total": validated_total,
        "completed": completed,
        "capability": round(found_total / active_total, 2) if active_total else 0,
        "effective_mean_t_find": round(sum(t_founds) / len(t_founds), 1) if t_founds else None,
        "report_count": len(reports),
        "mean_report_score": round(sum(scores) / len(scores), 1) if scores else None,
        "class_accuracy": round(class_accurate / len(reports), 2) if reports else None,
        "severity_accuracy": round(sev_accurate / len(reports), 2) if reports else None,
        "per_class": per_class,
        "flags": len(flags),
        "history": history_rows,
        "estimates": WIKI_ESTIMATES,
        "gaps": _gaps(per_class, active),
        "tips": build_tips(per_class, reports, active, t_founds),
        # hunter-centric stats
        "flags_found": flags_found,
        "fastest_find": fastest_find,
        "mean_find": mean_find,
        "speed_score": speed_score,
        "impact": impact,
        "complexity_index": complexity_index,
        "complexity_pct": complexity_pct,
        "complexity_total": captured_weight,
        "creativity": creativity,
        "chain_done": chain_done,
        "explored_count": len(explored),
        "persona": persona,
        "speed_rows": speed_rows,
    }


def _persona_level(points: int) -> dict[str, Any]:
    """Map hunter effort into a persona level. Deliberately encouraging:
    every tier reads positively and thresholds are forgiving so the desk
    never sounds harsh about a hunter's pace or count."""
    tiers = [
        (0,  "First Steps",  "Every hunt starts with one small find. Momentum builds from here."),
        (2,  "Curious Hunter", "You are poking surfaces and reading the lab. Keep going."),
        (4,  "Observer",       "Solid reconnaissance instincts. The flags will follow."),
        (6,  "Researcher",     "You are turning exploration into confirmed findings. Nice rhythm."),
        (8,  "Operator",       "Reproducible impact across surfaces - dependable and careful."),
        (10, "Specialist",     "Fast reads, clean confirmations. You clearly know your classes."),
        (12, "Expert",         "Precision hunting with strong report quality. Impressive focus."),
        (14, "Elite",          "Elite-level speed and coverage. The ledger respects your work."),
    ]
    name = "First Steps"
    blurb = tiers[0][2]
    for threshold, tname, ttext in reversed(tiers):
        if points >= threshold:
            name, blurb = tname, ttext
            break
    next_tier = None
    for threshold, tname, ttext in tiers:
        if threshold > points:
            next_tier = {"name": tname, "needed": threshold - points}
            break
    return {
        "name": name,
        "blurb": blurb,
        "points": points,
        "next": next_tier,
    }


def _gaps(per_class: dict[str, Any], active: list[str]) -> list[dict[str, Any]]:
    """Classes that are active but not found, with wiki prior for context."""
    gaps = []
    for cls in active:
        v = per_class.get(cls, {})
        if not v.get("active"):
            continue
        if not v.get("found"):
            gaps.append({
                "class": cls,
                "label": REGISTRY[cls]["label"],
                "feature": REGISTRY[cls]["feature"],
                "hint": REGISTRY[cls]["hint"],
                "estimate": WIKI_ESTIMATES.get(cls),
            })
    return gaps


def build_tips(
    per_class: dict[str, Any],
    reports: list[dict[str, Any]],
    active: list[str],
    t_founds: list[float],
) -> list[str]:
    """Rule-based improvement suggestions from today's data."""
    tips: list[str] = []

    missing = [cls for cls in active if per_class.get(cls, {}).get("active") and not per_class[cls]["found"]]
    if missing:
        labels = ", ".join(REGISTRY[c]["label"] for c in missing)
        tips.append(
            f"You left {len(missing)} active issue unconfirmed ({labels}). "
            "Retest each surface with the payload hints and the matching class skill before you stop."
        )

    slow = [cls for cls in active if per_class.get(cls, {}).get("exploited_at")]
    if slow and t_founds:
        avg = sum(t_founds) / len(t_founds)
        for cls in slow:
            t = per_class[cls]["exploited_at"]
            if t and t > avg * 1.5:
                tips.append(
                    f"You confirmed {REGISTRY[cls]['label']} but it took longer than your average. "
                    "Next time check that feature early with a minimal probe."
                )

    for r in reports:
        if r["matched_class"] and (r["class"] or "").lower() != r["matched_class"]:
            tips.append(
                f"Report {r['id']} claimed class '{r['class']}' but the issue was "
                f"{REGISTRY[r['matched_class']]['label']}. Read the class skills before labelling."
            )
        if r["matched_class"] and (r["severity"] or "").lower() != REGISTRY[r["matched_class"]]["severity"]:
            tips.append(
                f"Report {r['id']} severity '{r['severity']}' does not match the reference "
                f"severity for {REGISTRY[r['matched_class']]['label']}. Justify severity with impact."
            )
        if not r["payload"]:
            tips.append(f"Report {r['id']} has no payload. A valid PoC needs the exact request.")
        steps = len([s for s in (r["repro"] or "").splitlines() if s.strip()])
        if steps < 3:
            tips.append(
                f"Report {r['id']} has {steps} reproduction step(s). Triage needs at least 3 "
                "to re-run the finding from your writeup alone."
            )

    if not tips:
        tips.append(
            "Solid day. Cover the remaining classes and tighten report accuracy to move "
            "the capability index past 1.0 across days."
        )
    return tips[:8]
