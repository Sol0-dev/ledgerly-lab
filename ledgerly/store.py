"""SQLite persistence for day state, vuln tracking, reports, flags, history."""

from __future__ import annotations

import json
import os
import sqlite3
import time
import uuid
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "lab.sqlite")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    day        TEXT NOT NULL,
    username   TEXT NOT NULL,
    email      TEXT NOT NULL,
    password   TEXT,
    role       TEXT NOT NULL DEFAULT 'user',
    display    TEXT,
    UNIQUE(day, username)
);
CREATE TABLE IF NOT EXISTS clients (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    day      TEXT NOT NULL,
    name     TEXT NOT NULL,
    access   TEXT NOT NULL DEFAULT 'public',
    owner_id INTEGER NOT NULL,
    note     TEXT
);
CREATE TABLE IF NOT EXISTS invoices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    day          TEXT NOT NULL,
    number       TEXT NOT NULL,
    owner_id     INTEGER NOT NULL,
    client       TEXT NOT NULL,
    amount_cents INTEGER NOT NULL DEFAULT 0,
    status       TEXT NOT NULL DEFAULT 'draft',
    lines        TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS day_state (
    day          TEXT PRIMARY KEY,
    reset_count  INTEGER NOT NULL DEFAULT 0,
    ctx          TEXT NOT NULL,
    started_at   REAL NOT NULL,
    completed    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS vuln_state (
    day          TEXT NOT NULL,
    class        TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'active',
    exploited_at REAL,
    detail       TEXT,
    PRIMARY KEY (day, class)
);
CREATE TABLE IF NOT EXISTS reports (
    id            TEXT PRIMARY KEY,
    day           TEXT NOT NULL,
    ts            REAL NOT NULL,
    title         TEXT NOT NULL,
    class         TEXT,
    severity      TEXT,
    endpoint      TEXT,
    parameter     TEXT,
    payload       TEXT,
    repro         TEXT,
    impact        TEXT,
    fix           TEXT,
    notes         TEXT,
    matched_class TEXT,
    score         INTEGER NOT NULL DEFAULT 0,
    triage_status TEXT NOT NULL DEFAULT 'pending',
    triage_note   TEXT,
    triaged_at    REAL,
    flag_id       TEXT
);
CREATE TABLE IF NOT EXISTS flags (
    id         TEXT PRIMARY KEY,
    day        TEXT NOT NULL,
    class      TEXT NOT NULL,
    report_id  TEXT,
    awarded_at REAL NOT NULL,
    claimed    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS captures (
    day         TEXT NOT NULL,
    slot        INTEGER NOT NULL,
    captured_at REAL NOT NULL,
    polled      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, slot)
);
CREATE TABLE IF NOT EXISTS history (
    day     TEXT NOT NULL,
    class   TEXT NOT NULL,
    found   INTEGER NOT NULL DEFAULT 0,
    t_found REAL,
    score   INTEGER,
    PRIMARY KEY (day, class)
);
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    day    TEXT NOT NULL,
    ts     REAL NOT NULL,
    kind   TEXT NOT NULL,
    class  TEXT,
    detail TEXT
);
"""


def _connect() -> sqlite3.Connection:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(_SCHEMA)


# --------------------------------------------------------------------------
# day state
# --------------------------------------------------------------------------

def get_day_state(day: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            "SELECT day, reset_count, ctx, started_at, completed FROM day_state WHERE day=?",
            (day,),
        ).fetchone()
    if row is None:
        return None
    return {
        "day": row["day"],
        "reset_count": row["reset_count"],
        "ctx": json.loads(row["ctx"]),
        "started_at": row["started_at"],
        "completed": bool(row["completed"]),
    }


def ensure_day_state(day: str, ctx: dict[str, Any]) -> dict[str, Any]:
    existing = get_day_state(day)
    if existing is not None:
        return existing
    state = {
        "day": day,
        "reset_count": ctx["reset_count"],
        "ctx": ctx,
        "started_at": time.time(),
        "completed": False,
    }
    with _connect() as conn:
        conn.execute(
            "INSERT INTO day_state (day, reset_count, ctx, started_at, completed) VALUES (?,?,?,?,?)",
            (day, ctx["reset_count"], json.dumps(ctx), state["started_at"], 0),
        )
        for cls in ctx["active_vulns"]:
            conn.execute(
                "INSERT OR IGNORE INTO vuln_state (day, class) VALUES (?,?)", (day, cls)
            )
    return state


def complete_day(day: str) -> None:
    with _connect() as conn:
        conn.execute("UPDATE day_state SET completed=1 WHERE day=?", (day,))


def reset_day(day: str, ctx: dict[str, Any]) -> None:
    """Re-seed the day with a fresh draw: new context, all tracking wiped."""
    with _connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO day_state (day, reset_count, ctx, started_at, completed) "
            "VALUES (?,?,?,?,0)",
            (day, ctx["reset_count"], json.dumps(ctx), time.time()),
        )
        for table in ("vuln_state", "reports", "flags", "captures", "events", "history",
                      "users", "clients", "invoices"):
            conn.execute(f"DELETE FROM {table} WHERE day=?", (day,))
        for cls in ctx["active_vulns"]:
            conn.execute("INSERT INTO vuln_state (day, class) VALUES (?,?)", (day, cls))


# --------------------------------------------------------------------------
# vuln state
# --------------------------------------------------------------------------

def vuln_status(day: str, cls: str) -> str:
    with _connect() as conn:
        row = conn.execute(
            "SELECT status FROM vuln_state WHERE day=? AND class=?", (day, cls)
        ).fetchone()
    return row["status"] if row else "active"


def set_vuln_status(day: str, cls: str, status: str, detail: str | None = None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO vuln_state (day, class, status, detail) VALUES (?,?,?,?) "
            "ON CONFLICT(day, class) DO UPDATE SET status=excluded.status, "
            "detail=COALESCE(excluded.detail, vuln_state.detail)",
            (day, cls, status, detail),
        )


def mark_exploited(day: str, cls: str, detail: str) -> bool:
    """Mark a class exploited if it is still active. Returns True on transition."""
    now = time.time()
    with _connect() as conn:
        cur = conn.execute(
            "UPDATE vuln_state SET status='exploited', exploited_at=?, detail=? "
            "WHERE day=? AND class=? AND status='active'",
            (now, detail[:500], day, cls),
        )
        conn.execute(
            "INSERT INTO events (day, ts, kind, class, detail) VALUES (?,?,'exploited',?,?)",
            (day, now, cls, detail[:500]),
        )
        return cur.rowcount > 0


def day_vuln_rows(day: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT class, status, exploited_at, detail FROM vuln_state WHERE day=?",
            (day,),
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------

def insert_report(day: str, fields: dict[str, Any], matched_class: str | None, score: int) -> str:
    rid = f"R-{uuid.uuid4().hex[:8].upper()}"
    with _connect() as conn:
        conn.execute(
            "INSERT INTO reports (id, day, ts, title, class, severity, endpoint, parameter, "
            "payload, repro, impact, fix, notes, matched_class, score) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                rid,
                day,
                time.time(),
                fields["title"],
                fields.get("class"),
                fields.get("severity"),
                fields.get("endpoint"),
                fields.get("parameter"),
                fields.get("payload"),
                fields.get("repro"),
                fields.get("impact"),
                fields.get("fix"),
                fields.get("notes"),
                matched_class,
                score,
            ),
        )
    return rid


def list_reports(day: str | None = None, pending_only: bool = False) -> list[dict[str, Any]]:
    q = "SELECT * FROM reports"
    conds, args = [], []
    if day:
        conds.append("day=?")
        args.append(day)
    if pending_only:
        conds.append("triage_status='pending'")
    if conds:
        q += " WHERE " + " AND ".join(conds)
    q += " ORDER BY ts"
    with _connect() as conn:
        rows = conn.execute(q, args).fetchall()
    return [dict(r) for r in rows]


def get_report(rid: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
    return dict(row) if row else None


def set_report_triage(rid: str, status: str, note: str | None, flag_id: str | None) -> None:
    with _connect() as conn:
        conn.execute(
            "UPDATE reports SET triage_status=?, triage_note=?, triaged_at=?, flag_id=? WHERE id=?",
            (status, note, time.time(), flag_id, rid),
        )


# --------------------------------------------------------------------------
# flags
# --------------------------------------------------------------------------

def award_flag(day: str, cls: str, report_id: str) -> str:
    fid = f"FLAG-{uuid.uuid4().hex[:8].upper()}"
    with _connect() as conn:
        conn.execute(
            "INSERT INTO flags (id, day, class, report_id, awarded_at) VALUES (?,?,?,?,?)",
            (fid, day, cls, report_id, time.time()),
        )
    return fid


def pending_flags() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM flags WHERE claimed=0 ORDER BY awarded_at"
        ).fetchall()
    return [dict(r) for r in rows]


def claim_flags() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM flags WHERE claimed=0").fetchall()
        if rows:
            conn.execute("UPDATE flags SET claimed=1 WHERE claimed=0")
    return [dict(r) for r in rows]


def list_flags() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM flags ORDER BY awarded_at").fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# captures (player-submitted flags)
# --------------------------------------------------------------------------

def captured_slots(day: str) -> set[int]:
    with _connect() as conn:
        rows = conn.execute("SELECT slot FROM captures WHERE day=?", (day,)).fetchall()
    return {r["slot"] for r in rows}


def claim_captures(day: str) -> list[dict[str, Any]]:
    """Return the day's captures that have not been polled yet (slot only -
    no class disclosure), then mark them polled so the confetti bursts once."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT slot, captured_at FROM captures WHERE day=? AND polled=0 ORDER BY captured_at",
            (day,),
        ).fetchall()
        if rows:
            conn.execute(
                "UPDATE captures SET polled=1 WHERE day=? AND polled=0", (day,)
            )
    return [dict(r) for r in rows]


def capture_flag(day: str, ctx: dict[str, Any], flag: str) -> dict[str, Any]:
    """Validate a submitted flag against today's draw and record the capture.

    A flag only captures when (a) it is one of today's flags and (b) the class
    behind it has actually been exploited server-side. Both keep the lab honest:
    the interface is the player's ledger, the server still decides.
    """
    active = ctx.get("active_vulns", [])
    flags = ctx.get("flags", [])
    flag = (flag or "").strip()
    if not flag:
        return {"ok": False, "error": "A flag is required."}
    if flag not in flags:
        return {"ok": False, "error": "No active issue matches that flag. Verify it on the surface where you found it."}
    idx = flags.index(flag)
    if idx >= len(active):
        return {"ok": False, "error": "No active issue matches that flag."}
    cls = active[idx]
    if vuln_status(day, cls) == "active":
        return {"ok": False, "error": "The issue behind this flag has not been confirmed yet."}
    slot = idx + 1
    with _connect() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO captures (day, slot, captured_at) VALUES (?,?,?)",
            (day, slot, time.time()),
        )
    return {"ok": True, "slot": slot}


def capture_rows(day: str) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT slot, captured_at FROM captures WHERE day=? ORDER BY slot", (day,)
        ).fetchall()
    return [dict(r) for r in rows]


# --------------------------------------------------------------------------
# history + events
# --------------------------------------------------------------------------

def upsert_history(day: str, cls: str, found: int, t_found: float | None, score: int | None) -> None:
    with _connect() as conn:
        conn.execute(
            "INSERT INTO history (day, class, found, t_found, score) VALUES (?,?,?,?,?) "
            "ON CONFLICT(day, class) DO UPDATE SET found=excluded.found, "
            "t_found=excluded.t_found, score=excluded.score",
            (day, cls, found, t_found, score),
        )


def all_history() -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM history ORDER BY day").fetchall()
    return [dict(r) for r in rows]


def recent_events(day: str, limit: int = 50) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM events WHERE day=? ORDER BY id DESC LIMIT ?", (day, limit)
        ).fetchall()
    return [dict(r) for r in rows]


def export_reports(day: str) -> str:
    """Persist submitted reports as a JSON artifact for the record."""
    payload = list_reports(day=day)
    path = os.path.join(BASE_DIR, "reports", f"{day}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return path
