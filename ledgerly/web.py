"""Flask application: routes, feature surfaces, and the vulnerable sinks.

Every vuln is gated on today's active set. When a class is not active its
endpoint behaves safely; when it is active the primitive is real and the
handler calls store.mark_exploited only after the exploitation actually fired.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import pickle
import random
import re
import secrets
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from datetime import date
from typing import Any
from urllib.parse import urlparse

from flask import (
    Flask,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import chain as chainmod
from . import store, vulns
from .config import DayContext, today_iso

PORT = int(os.environ.get("LEDGERLY_PORT", "5001"))
HOST = os.environ.get("LEDGERLY_HOST", "127.0.0.1")
META_PORT = int(os.environ.get("LEDGERLY_META_PORT", "5002"))

SQLI_MARKERS = ("'--", "' --", "#'", "'#", "' or '", "' OR '", "union select", "union all")

_PRIVATE_NETS = [
    ("127.0.0.0", 8),
    ("10.0.0.0", 8),
    ("172.16.0.0", 12),
    ("192.168.0.0", 16),
    ("169.254.0.0", 16),
    ("0.0.0.0", 8),
]


class RedirectAbort(Exception):
    """Control-flow helper: a view asks to redirect (used by guards)."""

    def __init__(self, location: str) -> None:
        self.location = location


def create_app(meta: bool = False) -> Flask:
    """App factory.

    Two processes serve the same product from the same sqlite state:
      * the main app (LEDGERLY_PORT, default 5001) runs the product surface
      * the meta app (LEDGERLY_META_PORT, default 5002) runs the reporting
        desk: Reports, Flags, Analytics, Triage, Complete.
    Both share the session secret and cookie name, so a login on the product
    port authenticates the reporting desk (cookies are port-agnostic). The
    nav cross-links the two ports so they read as one product.
    """
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("LEDGERLY_SECRET", "dev-secret-change-me")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.is_meta = meta
    _prime_day(app)

    @app.template_filter("money")
    def money_filter(cents: int) -> str:
        return f"${cents / 100:,.2f}"

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "found_active": _found_active_count,
            "captured_total": _captured_total,
            "max_slots": _max_slots,
            "lab_total_vulns": _lab_total_vulns,
            "lab_confirmed_vulns": _lab_confirmed_vulns,
            "lab_total_flags": _lab_total_flags,
            "registry": vulns.REGISTRY,
            "ctx": getattr(g, "ctx", None) or _fallback_ctx(),
            "meta_base": _peer_url("", META_PORT),
            "meta_port": META_PORT,
            "route_url": _route,
            "is_meta": bool(getattr(current_app, "is_meta", False)),
        }

    _register_hooks(app)
    if meta:
        _register_meta_routes(app)
    else:
        _register_main_routes(app)
    _register_error_handlers(app)
    return app


def _found_active_count() -> int:
    """Class flags banked (slots 1..N). The chain slot is excluded from the
    nav pill so it reads as class progress only."""
    captured = store.captured_slots(g.day)
    return sum(
        1 for i in range(1, len(g.ctx.active_vulns) + 1) if i in captured
    )


def _lab_total_vulns() -> int:
    """Every vulnerability class the lab covers, including the compound chain."""
    return len(vulns.REGISTRY)


def _lab_total_flags() -> int:
    """Total flags across the whole lab: one per registered class plus the
    compound chain flag. Used wherever a count reads N/25."""
    return len(vulns.REGISTRY)


def _lab_confirmed_vulns() -> int:
    """Distinct classes ever confirmed (exploited) across all days, capped at
    the registry size so the stat always reads N/M."""
    return min(len(store.exploited_classes_all_days()), _lab_total_vulns())


def _captured_total() -> int:
    """All banked slots including the chain slot - the reporting desk pill
    reads the full lab."""
    return len(store.captured_slots(g.day))


def _max_slots() -> int:
    """Total bankable slots: one per active class plus the compound chain."""
    return len(g.ctx.active_vulns) + (1 if g.ctx.chain_recipe else 0)


def _flag_for(cls: str) -> str | None:
    """Today's capture flag for a class, or None if the class is not drawn.
    Flags are opaque (FLAG{...}) and never encode the class name."""
    active = g.ctx.active_vulns
    if cls not in active:
        return None
    return g.ctx.flags[active.index(cls)]


def _fallback_ctx() -> DayContext:
    return DayContext(today_iso(), 0)


def _prime_day(app: Flask) -> None:
    day = today_iso()
    ctx = DayContext(day, _current_reset_count(day))
    app.config["DAY_CTX"] = ctx
    app.config["SESSION_COOKIE_NAME"] = ctx.tech["cookie"]


def _current_reset_count(day: str) -> int:
    state = store.get_day_state(day)
    return state["reset_count"] if state else 0


# --------------------------------------------------------------------------
# request lifecycle
# --------------------------------------------------------------------------

def _register_hooks(app: Flask) -> None:
    @app.before_request
    def load_day() -> None:
        g.day = today_iso()
        if g.day != app.config["DAY_CTX"].day:
            _prime_day(app)
        g.ctx: DayContext = app.config["DAY_CTX"]
        store.ensure_day_state(g.day, g.ctx.to_dict())
        _seed_fixtures()
        g.user = _current_user()
        g.api = g.ctx.tech["api"]

    @app.after_request
    def fingerprint(resp):
        for k, v in g.ctx.fingerprint_headers().items():
            resp.headers.setdefault(k, v)
        return resp


def _current_user() -> dict[str, Any] | None:
    uid = session.get("uid")
    if not uid:
        return None
    with store._connect() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, display FROM users WHERE id=? AND day=?",
            (uid, today_iso()),
        ).fetchone()
    return dict(row) if row else None


def _peer_url(endpoint: str, port: int) -> str:
    """Absolute URL on a specific port of the current host. Used to cross-link
    the product port and the reporting desk port."""
    host = request.host.split(":")[0]
    return f"{request.scheme}://{host}:{port}/{endpoint}".rstrip("/")


def _route(endpoint: str) -> str:
    """URL for an endpoint, preferring this app if it owns the route and
    crossing to the peer port otherwise (product <-> reporting desk)."""
    if current_app.view_functions.get(endpoint) is not None:
        return url_for(endpoint)
    peer = PORT if getattr(current_app, "is_meta", False) else META_PORT
    return _peer_url(endpoint, peer)


def _require_login() -> None:
    if g.user is None:
        raise RedirectAbort(url_for("login", next=request.path))


def _require_admin() -> None:
    if g.user is None or g.user["role"] != "admin":
        abort(403)


def _completed() -> bool:
    active = set(g.ctx.active_vulns)
    if not active:
        return False
    if len(store.captured_slots(g.day)) != _max_slots():
        return False
    store.complete_day(g.day)
    return True


def _lock_guard() -> None:
    """Send the player to the completion screen once the day is solved.
    The report area stays open so detailed writeups can still be submitted."""
    if _completed():
        public = {"complete", "analytics", "logout", "flags_api", "static",
                  "reports", "report_new", "flags", "flags_reset"}
        if request.endpoint not in public:
            raise RedirectAbort(_route("complete"))


def _mark(cls: str, detail: str) -> None:
    if cls in g.ctx.active_vulns:
        store.mark_exploited(g.day, cls, detail)


def _day_rng() -> random.Random:
    return random.Random(g.ctx.seed)


# --------------------------------------------------------------------------
# seeding
# --------------------------------------------------------------------------

def _seed_fixtures() -> None:
    with store._connect() as conn:
        if conn.execute("SELECT 1 FROM users WHERE day=? LIMIT 1", (g.day,)).fetchone():
            return
        ctx = g.ctx
        store.seed_api_key(g.day, ctx.api_key)
        conn.execute(
            "INSERT INTO users (day, username, email, password, role, display) VALUES "
            "(?,?,?,?,?,?)",
            (g.day, "admin", "admin@ledgerly.io", ctx.admin_password, "admin", "Ada Admin"),
        )
        conn.execute(
            "INSERT INTO users (day, username, email, password, role, display) VALUES "
            "(?,?,?,?,?,?)",
            (g.day, "hunter", "hunter@ledgerly.io", "hunter-pass", "user", "Hunter One"),
        )
        conn.execute(
            "INSERT INTO users (day, username, email, password, role, display) VALUES "
            "(?,?,?,?,?,?)",
            (g.day, "olivia", "olivia@ledgerly.io", "olivia-pass", "user", "Olivia Reed"),
        )
        hunter_id = conn.execute(
            "SELECT id FROM users WHERE day=? AND username='hunter'", (g.day,)
        ).fetchone()["id"]
        olivia_id = conn.execute(
            "SELECT id FROM users WHERE day=? AND username='olivia'", (g.day,)
        ).fetchone()["id"]

        clients = [
            ("Acme Widgets", "public", hunter_id),
            ("Northwind Traders", "public", hunter_id),
            ("Riverstone Partners", "public", hunter_id),
            ("Eclipse Labs", "private", hunter_id),
            ("Ferris & Cole", "private", hunter_id),
            ("Beacon Systems", "public", olivia_id),
        ]
        conn.executemany(
            "INSERT INTO clients (day, name, access, owner_id) VALUES (?,?,?,?)",
            [(g.day, n, a, o) for n, a, o in clients],
        )
        if "nosqli" in ctx.active_vulns:
            # The flag hides in a private client's internal note, reachable only
            # through the API filter operators (which leak the full row).
            nosqli_flag = ctx.flags[ctx.active_vulns.index("nosqli")]
            conn.execute(
                "UPDATE clients SET note=? WHERE day=? AND name='Eclipse Labs'",
                (nosqli_flag, g.day),
            )

        fixtures = [
            ("INV-1001", hunter_id, "Acme Widgets", 120_000, "paid"),
            ("INV-1002", hunter_id, "Northwind Traders", 4800, "open"),
            ("INV-1003", hunter_id, "Riverstone Partners", 95000, "open"),
            ("INV-1004", olivia_id, "Beacon Systems", 220_000, "paid"),
            ("INV-1005", olivia_id, "Beacon Systems", 150_00, "open"),
            ("INV-1006", olivia_id, "Ferris & Cole", 8000, "open"),
        ]
        for i, (number, owner, client, cents, status) in enumerate(fixtures):
            lines = [{"description": f"Services {i + 1}", "qty": 1, "unit_price": cents}]
            if "idor" in ctx.active_vulns and number == "INV-1006":
                # The idor flag rides on a foreign invoice's second line item,
                # only reachable by reading someone else's invoice.
                idor_flag = ctx.flags[ctx.active_vulns.index("idor")]
                lines.append({"description": idor_flag, "qty": 1, "unit_price": 0})
            conn.execute(
                "INSERT INTO invoices (day, number, owner_id, client, amount_cents, status, lines) "
                "VALUES (?,?,?,?,?,?,?)",
                (g.day, number, owner, client, cents, status, json.dumps(lines)),
            )
        if "lfi" in ctx.active_vulns:
            # The flag hides inside a workspace document, reachable only by
            # reading a file through the unsanitized documents path.
            lfi_flag = ctx.flags[ctx.active_vulns.index("lfi")]
            docs_dir = os.path.join(store.BASE_DIR, "data", "documents")
            os.makedirs(docs_dir, exist_ok=True)
            path = os.path.join(docs_dir, "audit-summary.txt")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(
                    "Ledgerly - Workspace audit summary\n"
                    "==================================\n"
                    "Prepared by the internal audit team.\n"
                    "\n"
                    "Findings this quarter: two invoice discrepancies and one\n"
                    "archived contract marked for review.\n"
                    "\n"
                    f"Archive reference token: {lfi_flag}\n"
                )


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

def _auth_routes(app: Flask) -> None:
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(_route("dashboard"))
        error = None
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = _authenticate(username, password)
            if user:
                if any(m in username.lower() for m in SQLI_MARKERS):
                    _mark("sqli", f"login bypass authenticated as {user['username']}")
                session.clear()
                session["uid"] = user["id"]
                nxt = request.args.get("next")
                if nxt and nxt.startswith("/") and not nxt.startswith("//") and "\\" not in nxt:
                    return redirect(nxt)
                landing = "analytics" if getattr(current_app, "is_meta", False) else "dashboard"
                return redirect(_route(landing))
            error = "Invalid username or password"
        return render_template("login.html", error=error)

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            email = (request.form.get("email") or "").strip()
            password = request.form.get("password") or ""
            if not (username and email and password):
                flash("All fields are required", "error")
                return redirect(url_for("register"))
            with store._connect() as conn:
                try:
                    cur = conn.execute(
                        "INSERT INTO users (day, username, email, password, role, display) "
                        "VALUES (?,?,?,?,?,?)",
                        (g.day, username, email, password, "user", username),
                    )
                except sqlite3.IntegrityError:
                    flash("That username is taken", "error")
                    return redirect(url_for("register"))
            session["uid"] = cur.lastrowid
            landing = "analytics" if getattr(current_app, "is_meta", False) else "dashboard"
            return redirect(_route(landing))
        return render_template("register.html")

    @app.route("/logout")
    def logout():
        session.clear()
        return redirect(url_for("login"))


def _authenticate(username: str, password: str) -> dict[str, Any] | None:
    with store._connect() as conn:
        if "sqli" in g.ctx.active_vulns:
            # Genuine injection: the query is built from raw input. A comment
            # terminator cancels the password clause so any password authenticates.
            # Day is inlined like the rest of the clause - a comment-terminated
            # username still cancels the password check.
            q = (
                "SELECT id, username, password, role, display FROM users "
                f"WHERE username = '{username}' AND password = '{password}' "
                f"AND day = '{g.day}'"
            )
            return _row_to_dict(
                conn.execute(q).fetchone()
            )
        return _row_to_dict(
            conn.execute(
                "SELECT id, username, password, role, display FROM users "
                "WHERE username=? AND password=? AND day=?",
                (username, password, g.day),
            ).fetchone()
        )


def _row_to_dict(row) -> dict[str, Any] | None:
    return dict(row) if row else None


# --------------------------------------------------------------------------
# dashboard / invoices / clients
# --------------------------------------------------------------------------

def _dashboard_routes(app: Flask) -> None:
    @app.route("/")
    def index():
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    def dashboard():
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            open_count = conn.execute(
                "SELECT COUNT(*) c FROM invoices WHERE owner_id=? AND status='open'",
                (g.user["id"],),
            ).fetchone()["c"]
            balance = conn.execute(
                "SELECT COALESCE(SUM(amount_cents),0) s FROM invoices WHERE owner_id=?",
                (g.user["id"],),
            ).fetchone()["s"]
            recent = conn.execute(
                "SELECT number, client, amount_cents, status FROM invoices "
                "WHERE owner_id=? ORDER BY id DESC LIMIT 4",
                (g.user["id"],),
            ).fetchall()
        return render_template(
            "dashboard.html",
            open_count=open_count,
            balance=balance,
            recent=[dict(r) for r in recent],
            ctx=g.ctx,
        )

    @app.route("/invoices")
    def invoices():
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM invoices WHERE owner_id=? ORDER BY id DESC",
                (g.user["id"],),
            ).fetchall()
        return render_template("invoices.html", invoices=[dict(r) for r in rows], ctx=g.ctx)

    @app.route("/invoices/<int:inv_id>")
    def invoice_detail(inv_id: int):
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            row = conn.execute("SELECT * FROM invoices WHERE id=?", (inv_id,)).fetchone()
        if row is None:
            abort(404)
        invoice = dict(row)
        if invoice["owner_id"] != g.user["id"]:
            if "idor" in g.ctx.active_vulns:
                _mark("idor", f"read invoice {invoice['number']} owned by user {invoice['owner_id']}")
            else:
                abort(404)
        return render_template(
            "invoice_detail.html",
            invoice=invoice,
            lines=json.loads(invoice["lines"]),
            logic_flag=_flag_for("logic") if invoice["amount_cents"] < 0 else None,
            csrf_flag=(
                _flag_for("csrf")
                if "csrf" in g.ctx.active_vulns
                and store.vuln_status(g.day, "csrf") != "active"
                else None
            ),
            ctx=g.ctx,
        )

    @app.route("/invoices/new", methods=["GET", "POST"])
    def invoice_new():
        _require_login()
        _lock_guard()
        if request.method == "GET":
            return render_template("invoice_new.html", ctx=g.ctx)
        try:
            lines = json.loads(request.form.get("lines") or "[]")
        except json.JSONDecodeError:
            flash("Invalid line items payload", "error")
            return redirect(url_for("invoice_new"))
        if not lines:
            flash("Add at least one line item", "error")
            return redirect(url_for("invoice_new"))

        reject = False
        total = 0
        for line in lines:
            qty = line.get("qty", 0)
            price = line.get("unit_price", 0)
            total += qty * price
            if qty < 0 or price < 0:
                if "logic" in g.ctx.active_vulns:
                    _mark("logic", f"negative line qty={qty} price={price} invoice_total={total}")
                else:
                    reject = True
        if reject:
            flash("Quantities and prices must be positive", "error")
            return redirect(url_for("invoice_new"))

        number = f"INV-{1000 + _next_invoice_seq()}"
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO invoices (day, number, owner_id, client, amount_cents, status, lines) "
                "VALUES (?,?,?,?,?,?,?)",
                (g.day, number, g.user["id"], "New client", total, "draft", json.dumps(lines)),
            )
        flash(f"Invoice {number} created", "ok")
        return redirect(url_for("invoices"))

    @app.route("/clients")
    def clients():
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM clients WHERE owner_id=? ORDER BY id", (g.user["id"],)
            ).fetchall()
        return render_template("clients.html", clients=[dict(r) for r in rows], ctx=g.ctx)

    @app.route("/clients/new", methods=["POST"])
    def client_new():
        _require_login()
        _lock_guard()
        name = (request.form.get("name") or "").strip()
        access = request.form.get("access") or "public"
        if not name:
            flash("Name is required", "error")
            return redirect(url_for("clients"))
        with store._connect() as conn:
            conn.execute(
                "INSERT INTO clients (day, name, access, owner_id) VALUES (?,?,?,?)",
                (g.day, name, access, g.user["id"]),
            )
        flash("Client added", "ok")
        return redirect(url_for("clients"))


def _next_invoice_seq() -> int:
    with store._connect() as conn:
        row = conn.execute("SELECT COUNT(*) c FROM invoices WHERE day=?", (g.day,)).fetchone()
    return row["c"]


# --------------------------------------------------------------------------
# settings: webhooks, notifications, api keys
# --------------------------------------------------------------------------

def _settings_routes(app: Flask) -> None:
    @app.route("/settings/webhooks")
    def webhooks():
        _require_login()
        _lock_guard()
        if not g.ctx.toggles.get("webhooks_enabled"):
            abort(404)
        return render_template("webhooks.html", ctx=g.ctx)

    @app.route("/settings/webhooks/test", methods=["POST"])
    def webhook_test():
        _require_login()
        url = (request.form.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url is required"}), 400

        if "ssrf" in g.ctx.active_vulns:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "LedgerlyHook/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(2048).decode("utf-8", "replace")
                host = _host_of(url)
                if _is_private(host):
                    _mark("ssrf", f"fetched internal host {host} -> {body[:120]!r}")
                return jsonify({"status": resp.status, "body": body})
            except urllib.error.HTTPError as exc:
                return jsonify(
                    {"status": exc.code, "body": exc.read(2048).decode("utf-8", "replace")}
                )
            except Exception as exc:
                return jsonify({"error": str(exc)}), 400

        if not url.startswith(("https://", "http://")) or _is_private(_host_of(url)):
            return jsonify({"error": "Only public webhook URLs are allowed"}), 400
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                body = resp.read(512).decode("utf-8", "replace")
            return jsonify({"status": resp.status, "body": body})
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

    @app.route("/settings/notifications")
    def notifications():
        _require_login()
        _lock_guard()
        if not g.ctx.toggles.get("notifications_enabled"):
            abort(404)
        return render_template("notifications.html", ctx=g.ctx)

    @app.route("/settings/notifications/preview", methods=["POST"])
    def notification_preview():
        _require_login()
        template = request.form.get("template") or ""
        if "ssti" in g.ctx.active_vulns:
            from jinja2 import Template
            from markupsafe import escape

            try:
                rendered = Template(template).render(
                    user=g.user, flag=_flag_for("ssti")
                )
            except Exception as exc:
                return jsonify({"error": f"Template could not be rendered: {exc}"}), 400
            literal = str(escape(template))
            if ("{{" in template or "{%" in template) and rendered != literal:
                _mark("ssti", f"template evaluated: {template[:80]!r} -> {rendered[:120]!r}")
            return jsonify({"rendered": rendered})
        return jsonify({"rendered": template})


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return urlparse(url).hostname or ""
    except Exception:
        return ""


def _is_private(host: str) -> bool:
    if host in ("localhost", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in ipaddress.ip_network(f"{net}/{pfx}") for net, pfx in _PRIVATE_NETS)


# --------------------------------------------------------------------------
# docs, internal, admin, team
# --------------------------------------------------------------------------

def _misc_routes(app: Flask) -> None:
    @app.route("/docs")
    def docs():
        _require_login()
        _lock_guard()
        return render_template("docs.html", api=g.api, ctx=g.ctx)

    @app.route("/internal/secret")
    def internal_secret():
        # Exists only when SSRF is in today's draw; otherwise the surface is
        # absent entirely. Loopback-only: a remote caller should never reach it;
        # reaching it via the webhook fetch is the SSRF proof.
        if "ssrf" not in g.ctx.active_vulns:
            abort(404)
        if not _is_private(request.remote_addr or ""):
            abort(403)
        return jsonify({"token": _flag_for("ssrf"), "note": "internal only"})

    @app.route("/admin")
    def admin():
        _require_login()
        _lock_guard()
        _require_admin()
        with store._connect() as conn:
            users = conn.execute(
                "SELECT username, email, role FROM users WHERE day=?", (g.day,)
            ).fetchall()
            inv_count = conn.execute(
                "SELECT COUNT(*) c FROM invoices WHERE day=?", (g.day,)
            ).fetchone()["c"]
        return render_template(
            "admin.html",
            users=[dict(r) for r in users],
            inv_count=inv_count,
            flag=_flag_for("sqli")
            if store.vuln_status(g.day, "sqli") != "active"
            else None,
            ctx=g.ctx,
        )

    @app.route("/team")
    def team():
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT username, email, role, display FROM users WHERE day=? ORDER BY id",
                (g.day,),
            ).fetchall()
        elev_flag = (
            _flag_for("mass_assignment")
            if g.user["role"] == "admin"
            and store.vuln_status(g.day, "mass_assignment") != "active"
            else None
        )
        return render_template(
            "team.html", members=[dict(r) for r in rows], elev_flag=elev_flag, ctx=g.ctx
        )


# --------------------------------------------------------------------------
# extended surfaces: 17 additional primitives + chain recovery
# --------------------------------------------------------------------------

def _docs_dir() -> str:
    base = os.path.join(store.BASE_DIR, "data", "documents")
    os.makedirs(base, exist_ok=True)
    return base


def _has_script_marker(text: str) -> bool:
    lowered = text.lower()
    markers = ("<script", "onerror=", "onload=", "onmouseover=", "javascript:",
               "<img", "<svg", "<iframe", "<a ")
    return any(m in lowered for m in markers)


def _looks_cross_site() -> bool:
    """True when a state change is not attributable to a same-origin caller."""
    origin = request.headers.get("Origin") or ""
    referer = request.headers.get("Referer") or ""
    host = request.host.split(":")[0]
    if origin:
        return urlparse(origin).netloc.split(":")[0] != host
    if referer:
        return urlparse(referer).netloc.split(":")[0] != host
    return True  # no source signal at all: the server never checks who asked


def _is_external(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return False
    return parsed.netloc.split(":")[0] != request.host.split(":")[0]


def _has_shell_meta(value: str) -> bool:
    return any(m in value for m in (";", "&&", "||", "`", "$(", "\n", ">" ))


def _looks_catastrophic(pattern: str) -> bool:
    try:
        return bool(re.search(r"\([^)]*(\+|\*)\)\s*[+*{]", pattern))
    except re.error:
        return False


def _merge_pp(target: dict[str, Any], source: dict[str, Any]) -> bool:
    """Recursive merge that walks __proto__ like a vulnerable deep-merge."""
    hit = False
    for key, value in source.items():
        if key == "__proto__":
            hit = True
        if isinstance(value, dict):
            nested = target.setdefault(key, {})
            if isinstance(nested, dict):
                hit = _merge_pp(nested, value) or hit
        else:
            target[key] = value
    return hit


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64d(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _mint_jwt(payload: dict[str, Any], secret: str) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    h = _b64u(json.dumps(header).encode())
    p = _b64u(json.dumps(payload).encode())
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64u(sig)}"


def _parse_jwt(token: str) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    try:
        h, p, s = token.split(".")
        return json.loads(_b64d(h)), json.loads(_b64d(p)), s
    except Exception:
        return None


def _jwt_signed_ok(token: str, secret: str) -> bool:
    parsed = _parse_jwt(token)
    if not parsed:
        return False
    header, _payload, _sig = parsed
    if header.get("alg") != "HS256":
        return False
    h, p, _ = token.split(".")
    expect = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return hmac.compare_digest(_b64d(_sig), expect)


def _bearer_token() -> str | None:
    header = request.headers.get("Authorization") or ""
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return None


def _key_authorized() -> tuple[bool, str | None, dict[str, Any] | None]:
    """Authenticate via a plain API key or a JWT. Returns (ok, how, payload)."""
    token = _bearer_token()
    if not token:
        return False, None, None
    if store.is_valid_api_key(g.day, token):
        if "token_mgmt" in g.ctx.active_vulns and token != store.current_api_key(g.day):
            _mark("token_mgmt", "rotated-away key still authenticates")
        return True, "key", None
    parsed = _parse_jwt(token)
    if parsed:
        header, payload, _sig = parsed
        if header.get("alg") in ("none", "None", "NONE", "nOnE", "nonex") and payload.get("sub"):
            if "jwt" in g.ctx.active_vulns:
                _mark("jwt", "alg:none token accepted")
            return True, "jwt_none", payload
        if _jwt_signed_ok(token, g.ctx.jwt_secret):
            return True, "jwt", payload
    return False, None, None


def _extended_routes(app: Flask) -> None:
    @app.route("/profile", methods=["GET", "POST"])
    def profile():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            display = (request.form.get("display") or "").strip()
            if display:
                with store._connect() as conn:
                    conn.execute(
                        "UPDATE users SET display=? WHERE id=? AND day=?",
                        (display, g.user["id"], g.day),
                    )
                g.user["display"] = display
                flash("Profile updated", "ok")
            return redirect(url_for("profile"))
        xss_active = "xss" in g.ctx.active_vulns
        if xss_active and _has_script_marker(g.user.get("display") or ""):
            _mark("xss", f"stored script rendered on profile: {(g.user.get('display') or '')[:60]!r}")
        xss_flag = (
            _flag_for("xss")
            if xss_active and store.vuln_status(g.day, "xss") != "active"
            else None
        )
        return render_template(
            "profile.html", xss_active=xss_active, xss_flag=xss_flag, ctx=g.ctx,
        )

    @app.route("/invoices/<int:inv_id>/status", methods=["POST"])
    def invoice_status(inv_id: int):
        _require_login()
        _lock_guard()
        status = (request.form.get("status") or "").strip()
        if status not in ("open", "paid", "draft"):
            return jsonify({"error": "bad status"}), 400
        with store._connect() as conn:
            conn.execute(
                "UPDATE invoices SET status=? WHERE id=? AND day=?",
                (status, inv_id, g.day),
            )
        if "csrf" in g.ctx.active_vulns and _looks_cross_site():
            origin = request.headers.get("Origin") or request.headers.get("Referer") or "no source"
            _mark("csrf", f"invoice {inv_id} status -> {status} ({origin})")
        flash("Invoice updated", "ok")
        return redirect(url_for("invoice_detail", inv_id=inv_id))

    @app.route("/billing/return")
    def billing_return():
        _require_login()
        _lock_guard()
        target = request.args.get("to") or url_for("dashboard")
        if "open_redirect" in g.ctx.active_vulns:
            if _is_external(target):
                _mark("open_redirect", f"unvalidated redirect to {target}")
        elif _is_external(target):
            return redirect(url_for("dashboard"))
        return redirect(target)

    @app.route("/account")
    def account():
        _require_login()
        _lock_guard()
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT username, email, role, display FROM users "
                "WHERE id=? AND day=?",
                (g.user["id"], g.day),
            ).fetchall()
        resp = make_response(render_template(
            "account.html", me=dict(rows[0]) if rows else g.user, ctx=g.ctx
        ))
        if "clickjacking" in g.ctx.active_vulns:
            if request.headers.get("Sec-Fetch-Dest") == "iframe" or request.args.get("embed") == "1":
                _mark("clickjacking", "account page served frameable in an iframe context")
        else:
            resp.headers["X-Frame-Options"] = "DENY"
        return resp

    @app.route("/settings/api-keys", methods=["GET"])
    def api_keys():
        _require_login()
        _lock_guard()
        if not g.ctx.toggles.get("api_keys_enabled"):
            abort(404)
        keys = store.api_key_list(g.day)
        jwt_token = _mint_jwt(
            {"sub": g.user["username"], "role": g.user["role"], "iat": int(time.time())},
            g.ctx.jwt_secret,
        )
        jwt_flag = (
            _flag_for("jwt")
            if "jwt" in g.ctx.active_vulns and store.vuln_status(g.day, "jwt") != "active"
            else None
        )
        token_flag = (
            _flag_for("token_mgmt")
            if "token_mgmt" in g.ctx.active_vulns
            and store.vuln_status(g.day, "token_mgmt") != "active"
            else None
        )
        return render_template(
            "api_keys.html", keys=keys, jwt_token=jwt_token,
            jwt_flag=jwt_flag, token_flag=token_flag, ctx=g.ctx,
        )

    @app.route("/settings/api-keys/rotate", methods=["POST"])
    def api_key_rotate():
        _require_login()
        new_key = "lk_live_" + secrets.token_hex(12)
        if "token_mgmt" in g.ctx.active_vulns:
            store.add_api_key(g.day, new_key)
            flash("API key rotated (the previous key is still accepted)", "warn")
        else:
            store.replace_all_api_keys(g.day, new_key)
            flash("API key rotated", "ok")
        return redirect(url_for("api_keys"))

    @app.route("/auth/partner")
    def auth_partner():
        code = request.args.get("code")
        state = request.args.get("state")
        client_id = request.args.get("client_id") or g.ctx.partner_client_id
        if "oauth" in g.ctx.active_vulns:
            if code and not state:
                _mark("oauth", "code exchange without state parameter")
            elif code and state:
                _mark("oauth", "state accepted but never verified against the stored value")
        else:
            if not code or state != "expected-state":
                flash("Partner sign-in requires a valid state", "error")
                return redirect(url_for("login"))
        with store._connect() as conn:
            row = conn.execute(
                "SELECT id FROM users WHERE day=? AND username='partner'", (g.day,)
            ).fetchone()
            if row:
                uid = row["id"]
            else:
                cur = conn.execute(
                    "INSERT INTO users (day, username, email, password, role, display) "
                    "VALUES (?,?,?,?,?,?)",
                    (g.day, "partner", f"partner@{client_id}.example", None, "user", "Partner Session"),
                )
                uid = cur.lastrowid
        session.clear()
        session["uid"] = uid
        return redirect(url_for("dashboard"))

    @app.route("/settings/backup", methods=["GET", "POST"])
    def backup():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            blob = request.form.get("blob") or ""
            if "deser" in g.ctx.active_vulns:
                try:
                    obj = pickle.loads(base64.b64decode(blob))
                except Exception as exc:
                    return jsonify({"error": f"restore failed: {exc}"}), 400
                if not isinstance(obj, (list, dict, str, int, float, bool, type(None))):
                    _mark("deser", f"unpickled {type(obj).__name__} object from untrusted blob")
                    return jsonify({
                        "ok": True,
                        "restored": repr(obj)[:140],
                        "archive_reference": _flag_for("deser"),
                    })
                return jsonify({"ok": True, "restored": repr(obj)[:140]})
            return jsonify({"ok": True, "restored": "backup restored"})
        return render_template("backup.html", ctx=g.ctx)

    @app.route("/documents")
    def documents_index():
        _require_login()
        _lock_guard()
        files = sorted(os.listdir(_docs_dir()))
        documents = [{"label": os.path.basename(f), "path": f} for f in files]
        return render_template("documents.html", documents=documents, ctx=g.ctx)

    @app.route("/documents/<path:name>")
    def doc_get(name: str):
        _require_login()
        _lock_guard()
        base = _docs_dir()
        if "lfi" in g.ctx.active_vulns:
            if ".." in name:
                _mark("lfi", f"path traversal read: {name}")
            target = os.path.join(base, name)
            try:
                with open(target, "r", errors="replace") as fh:
                    content = fh.read(8192)
            except OSError:
                abort(404)
            return make_response(content, 200, {"Content-Type": "text/plain; charset=utf-8"})
        if ".." in name or not os.path.isfile(os.path.join(base, name)):
            abort(404)
        with open(os.path.join(base, name), "r", errors="replace") as fh:
            content = fh.read(8192)
        return make_response(content, 200, {"Content-Type": "text/plain; charset=utf-8"})

    @app.route("/reports/export")
    def report_export():
        _require_login()
        _lock_guard()
        fmt = (request.args.get("format") or "csv").strip()
        if "cmdi" in g.ctx.active_vulns:
            if _has_shell_meta(fmt):
                _mark("cmdi", f"format value reached a shell command: {fmt[:40]!r}")
            try:
                out = subprocess.check_output(
                    f"echo exported:{fmt}", shell=True, text=True, timeout=5
                )
            except Exception:
                out = ""
            return make_response(out, 200, {"Content-Type": "text/plain; charset=utf-8"})
        if fmt not in ("csv", "json"):
            return jsonify({"error": "unsupported format"}), 400
        return jsonify({"ok": True, "format": fmt})

    @app.route("/settings/import", methods=["GET", "POST"])
    def import_xml():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            xml = request.get_data(as_text=True) or ""
            if "xxe" in g.ctx.active_vulns:
                from lxml import etree
                try:
                    parser = etree.XMLParser(resolve_entities=True, no_network=True)
                    root = etree.fromstring(xml.encode("utf-8"), parser)
                except Exception as exc:
                    return jsonify({"error": f"import failed: {exc}"}), 400
                if "<!DOCTYPE" in xml.upper() and "SYSTEM" in xml.upper():
                    _mark("xxe", "external entity in DOCTYPE expanded")
                return jsonify({"ok": True, "imported": etree.tostring(root)[:200].decode(errors="replace")})
            if "<!DOCTYPE" in xml.upper():
                return jsonify({"error": "DOCTYPE not allowed"}), 400
            return jsonify({"ok": True, "imported": "row parsed"})
        return render_template("import.html", ctx=g.ctx)

    @app.route("/coupons")
    def coupons():
        _require_login()
        _lock_guard()
        code = g.ctx.coupon_code
        c = store.coupon_get(g.day, code)
        race_flag = (
            _flag_for("race")
            if "race" in g.ctx.active_vulns and store.vuln_status(g.day, "race") != "active"
            else None
        )
        return render_template(
            "coupons.html",
            code=code,
            uses=(c["uses"] if c else 0),
            last_used=(c["last_used"] if c else None),
            race_flag=race_flag,
            ctx=g.ctx,
        )

    @app.route("/coupons/redeem", methods=["POST"])
    def coupon_redeem_route():
        _require_login()
        code = (request.form.get("code") or "").strip()
        if code != g.ctx.coupon_code:
            return jsonify({"error": "invalid code"}), 400
        if "race" in g.ctx.active_vulns:
            time.sleep(0.25)
            res = store.coupon_redeem(g.day, code)
            if res["raced"] or res["uses"] > 1:
                _mark("race", f"code {code} applied {res['uses']} times by a parallel burst")
            return jsonify({"ok": True, "uses": res["uses"]})
        return jsonify({"ok": True, "redeemed": True})

    @app.route("/search")
    def search():
        _require_login()
        _lock_guard()
        q = (request.args.get("q") or "").strip()
        if "redos" in g.ctx.active_vulns and q:
            try:
                pattern = re.compile(q)
                pattern.search("a" * 200 + "b")
                if _looks_catastrophic(q):
                    _mark("redos", f"user regex compiled and matched: {q[:40]!r}")
            except re.error:
                pass
        results = ["INV-1001", "INV-1002", "INV-1003", "Acme Widgets", "Northwind Traders"]
        if q:
            results = [r for r in results if q.lower() in r.lower()]
        return render_template("search.html", q=q, results=results, ctx=g.ctx)

    @app.route("/api/v1/health")
    def health():
        payload = {"status": "ok", "app": "ledgerly", "version": g.ctx.version}
        if "infoleak" in g.ctx.active_vulns:
            payload["secret_key"] = app.config["SECRET_KEY"]
            payload["internal_token"] = g.ctx.internal_token
            payload["admin_user"] = "admin"
            payload["db_path"] = store.DB_PATH
            _mark("infoleak", "health endpoint exposed runtime configuration")
            if store.vuln_status(g.day, "infoleak") != "active":
                payload["reference_token"] = _flag_for("infoleak")
        return jsonify(payload)

    @app.route("/graphql", methods=["GET", "POST"])
    def graphql():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            body = request.get_json(silent=True) or {}
            q = body.get("query") or request.form.get("query") or ""
        else:
            q = request.args.get("query") or ""
        if not q:
            return render_template("graphql.html", result=None, ctx=g.ctx)
        if "graphql" in g.ctx.active_vulns and "{__schema" in q:
            return jsonify({"data": {"__schema": {"types": [
                {"name": n} for n in ("Query", "Invoice", "Client", "User", "Mutation")
            ]}}})
        m = re.search(r"invoice\s*\(\s*id\s*:\s*(\d+)\s*\)", q)
        if m:
            inv_id = int(m.group(1))
            with store._connect() as conn:
                row = conn.execute(
                    "SELECT * FROM invoices WHERE id=? AND day=?", (inv_id, g.day)
                ).fetchone()
            if row is None:
                return jsonify({"errors": [{"message": "invoice not found"}]}), 404
            invoice = dict(row)
            if invoice["owner_id"] != g.user["id"]:
                if "graphql" in g.ctx.active_vulns:
                    _mark("graphql", f"read foreign invoice {invoice['number']} via graphql")
                else:
                    return jsonify({"errors": [{"message": "not authorized"}]}), 403
            return jsonify({"data": {"invoice": {
                "number": invoice["number"],
                "client": invoice["client"],
                "amount": invoice["amount_cents"],
            }}})
        return render_template("graphql.html", result={"errors": ["unsupported query"]}, ctx=g.ctx)

    @app.route("/settings/theme", methods=["GET", "POST"])
    def theme():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            payload = request.get_json(silent=True) or {}
            if "prototype_pollution" in g.ctx.active_vulns:
                merged: dict[str, Any] = {}
                polluted = _merge_pp(merged, payload)
                if polluted:
                    _mark("prototype_pollution", "reserved __proto__ key merged into object")
                name = merged.get("name") or payload.get("name") or "default"
                return jsonify({"ok": True, "theme": name})
            if "__proto__" in json.dumps(payload):
                return jsonify({"error": "reserved keys are not allowed"}), 400
            return jsonify({"ok": True, "theme": payload.get("name") or "default"})
        return render_template("theme.html", ctx=g.ctx)

    # -- chain compound surface -------------------------------------------------

    @app.route("/recovery")
    def recovery():
        _require_login()
        _lock_guard()
        return render_template("recovery.html", unlocked=False, error=None, ctx=g.ctx)

    @app.route("/recovery/verify", methods=["POST"])
    def recovery_verify():
        _require_login()
        submitted = [
            (request.form.get(f"factor_{i}") or "").strip()
            for i in range(1, 1 + len(g.ctx.chain_factors))
        ]
        submitted = [s for s in submitted if s]
        expected = g.ctx.chain_code_expected()
        ok = bool(submitted) and chainmod.chain_code(submitted) == expected
        if ok:
            store.mark_exploited(g.day, "chain", "compound surface unlocked via chain code")
            return render_template(
                "recovery.html", unlocked=True, error=None,
                chain_flag=g.ctx.chain_flag, ctx=g.ctx,
            )
        return render_template(
            "recovery.html", unlocked=False,
            error="The factors did not combine. Re-check the outputs.",
            ctx=g.ctx,
        )


# --------------------------------------------------------------------------
# JSON API
# --------------------------------------------------------------------------

def _api_routes(app: Flask) -> None:
    def api_dispatch(rest: str):
        prefix = g.api
        path = request.path
        if not path.startswith(prefix):
            return jsonify({"error": "not found"}), 404
        target = path[len(prefix):].strip("/")

        if target == "clients" and request.method == "GET":
            return api_clients()
        if target == "keys" and request.method == "GET":
            return api_keys_list()
        if target == "team/me" and request.method == "PUT":
            return api_team_me()
        if target.startswith("invoices/") and request.method == "GET":
            return api_invoice(target.split("/", 1)[1])
        return jsonify({"error": "not found"}), 404

    def api_clients() -> Any:
        _require_login()
        origin = request.headers.get("Origin") or ""
        raw = request.args.get("filter")
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM clients WHERE owner_id=? ORDER BY id", (g.user["id"],)
            ).fetchall()
        clients = [dict(r) for r in rows]
        result: list[dict[str, Any]]
        if not raw:
            result = [c for c in clients if c["access"] != "private"]
        else:
            try:
                filt = json.loads(raw)
            except json.JSONDecodeError:
                return jsonify({"error": "filter must be valid JSON"}), 400
            if "nosqli" in g.ctx.active_vulns and _has_operator(filt):
                result = [c for c in clients if _match_operator(c, filt)]
                leaked = [c for c in result if c["access"] == "private"]
                if leaked:
                    _mark("nosqli", f"filter {raw[:120]!r} exposed {len(leaked)} private clients")
            else:
                result = [c for c in clients if _match_operator(c, filt) and c["access"] != "private"]

        resp = jsonify({"clients": result})
        if "cors" in g.ctx.active_vulns and origin:
            if urlparse(origin).netloc.split(":")[0] != request.host.split(":")[0]:
                resp.headers["Access-Control-Allow-Origin"] = origin
                resp.headers["Access-Control-Allow-Credentials"] = "true"
                _mark("cors", f"reflected origin {origin} allowed with credentials")
        return resp

    def _has_operator(filt: Any) -> bool:
        return any(
            isinstance(v, dict) and any(op.startswith("$") for op in v)
            for v in filt.values()
        )

    def _match_operator(record: dict[str, Any], filt: dict[str, Any]) -> bool:
        for key, cond in filt.items():
            value = record.get(key)
            if isinstance(cond, dict):
                for op, expected in cond.items():
                    if op == "$ne" and value == expected:
                        return False
                    if op == "$eq" and value != expected:
                        return False
                    if op == "$gt" and not (value is not None and value > expected):
                        return False
                    if op == "$lt" and not (value is not None and value < expected):
                        return False
            else:
                if value != cond:
                    return False
        return True

    def api_keys_list() -> Any:
        _require_login()
        ok, how, _payload = _key_authorized()
        if not ok:
            return jsonify({"error": "invalid or missing credentials"}), 401
        return jsonify({"keys": store.api_key_list(g.day), "auth": how})

    def api_team_me() -> Any:
        _require_login()
        payload = request.get_json(silent=True) or {}
        allowed = {"display", "email"}
        if "mass_assignment" in g.ctx.active_vulns:
            allowed = {"display", "email", "role"}
            if "role" in payload:
                _mark("mass_assignment", f"role set to {payload['role']!r}")
        updates = {k: payload[k] for k in allowed if k in payload}
        if not updates:
            return jsonify({"error": "no writable fields"}), 400
        sets = ", ".join(f"{k}=?" for k in updates)
        args = list(updates.values()) + [g.user["id"], g.day]
        with store._connect() as conn:
            conn.execute(f"UPDATE users SET {sets} WHERE id=? AND day=?", args)
        g.user.update(updates)
        return jsonify({"ok": True, "updated": list(updates)})

    def api_invoice(inv_id: str) -> Any:
        _require_login()
        try:
            inv_id = int(inv_id)
        except ValueError:
            return jsonify({"error": "invalid id"}), 400
        with store._connect() as conn:
            row = conn.execute("SELECT * FROM invoices WHERE id=?", (inv_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        invoice = dict(row)
        if invoice["owner_id"] != g.user["id"]:
            if "idor" in g.ctx.active_vulns:
                _mark("idor", f"api read invoice {invoice['number']} owned by user {invoice['owner_id']}")
            else:
                return jsonify({"error": "not found"}), 404
        invoice["lines"] = json.loads(invoice["lines"])
        return jsonify({"invoice": invoice})

    for prefix in ("/api/v1", "/api/v2", "/v1"):
        app.add_url_rule(
            f"{prefix}/<path:rest>",
            endpoint=f"api_dispatch_{prefix.strip('/').replace('/', '_')}",
            view_func=api_dispatch,
            methods=["GET", "PUT", "POST"],
        )


# --------------------------------------------------------------------------
# reports / analytics / triage view / complete / flags
# --------------------------------------------------------------------------

def _report_routes(app: Flask) -> None:
    @app.route("/flags", methods=["GET", "POST"])
    def flags():
        _require_login()
        _lock_guard()
        if request.method == "POST":
            res = store.capture_flag(g.day, g.ctx.to_dict(), request.form.get("flag") or "")
            flash(res["error"] if not res["ok"] else f"Flag {res['slot']} captured", "ok" if res["ok"] else "error")
            return redirect(url_for("flags"))
        captured = store.captured_slots(g.day)
        active = g.ctx.active_vulns
        # The full lab catalog: one slot per registered class plus the
        # compound chain = 25 slots. Every class is live every day.
        chain_slot = len(active) + 1 if g.ctx.chain_recipe else None
        slots = []
        for cls in vulns.REGISTRY:
            if cls == "chain":
                continue
            slots.append({
                "slot": active.index(cls) + 1,
                "class": cls,
                "captured": (active.index(cls) + 1) in captured,
                "chain": False,
            })
        if g.ctx.chain_recipe:
            slots.append({
                "slot": chain_slot,
                "class": "chain",
                "captured": chain_slot in captured,
                "chain": True,
            })
        slots.sort(key=lambda s: s["slot"])
        return render_template("flags.html", slots=slots, ctx=g.ctx)

    @app.route("/flags/reset/<int:slot>", methods=["POST"])
    def flags_reset(slot: int):
        """Per-slot reset: un-bank a captured flag so it can be re-farmed.
        Releases the slot and unlocks the day if it was completed by it."""
        _require_login()
        if 1 <= slot <= _max_slots():
            store.release_capture(g.day, slot)
            flash(f"Slot {slot} released", "ok")
        return redirect(url_for("flags"))

    @app.route("/reports")
    def reports():
        _require_login()
        _lock_guard()
        return render_template("reports.html", reports=store.list_reports(day=g.day), ctx=g.ctx)

    @app.route("/reports/new", methods=["GET", "POST"])
    def report_new():
        _require_login()
        if request.method == "GET":
            _lock_guard()
            return render_template("report_new.html", ctx=g.ctx)
        fields = {
            "title": (request.form.get("title") or "").strip(),
            "class": (request.form.get("class") or "").strip(),
            "severity": (request.form.get("severity") or "").strip(),
            "endpoint": (request.form.get("endpoint") or "").strip(),
            "parameter": (request.form.get("parameter") or "").strip(),
            "payload": (request.form.get("payload") or "").strip(),
            "repro": (request.form.get("repro") or "").strip(),
            "impact": (request.form.get("impact") or "").strip(),
            "fix": (request.form.get("fix") or "").strip(),
            "notes": (request.form.get("notes") or "").strip(),
        }
        if not fields["title"]:
            return jsonify({"error": "A title is required"}), 400
        if not fields["endpoint"] and not fields["payload"]:
            return jsonify({"error": "Provide an endpoint or a payload"}), 400

        matched = vulns.match_report(fields, g.day, g.ctx.to_dict())
        score = vulns.score_report(fields, matched)
        rid = store.insert_report(g.day, fields, matched, score)
        if matched and store.vuln_status(g.day, matched) != "validated":
            store.set_vuln_status(g.day, matched, "reported", "report " + rid)
        store.export_reports(g.day)
        return jsonify({"ok": True, "id": rid, "matched": matched, "score": score})

    @app.route("/analytics")
    def analytics():
        _require_login()
        data = vulns.compute_analytics(g.ctx.to_dict())
        return render_template("analytics.html", data=data, ctx=g.ctx)

    @app.route("/triage")
    def triage_view():
        _require_login()
        return render_template("triage.html", reports=store.list_reports(day=g.day), ctx=g.ctx)

    @app.route("/complete")
    def complete():
        if not _completed():
            raise RedirectAbort(_route("dashboard"))
        data = vulns.compute_analytics(g.ctx.to_dict())
        return render_template("complete.html", data=data, ctx=g.ctx)

    @app.route("/api/flags/new", methods=["GET"])
    def flags_api():
        return jsonify({"captures": store.claim_captures(g.day)})


# --------------------------------------------------------------------------
# reset + error handlers
# --------------------------------------------------------------------------

def _admin_routes(app: Flask) -> None:
    @app.route("/admin/reset", methods=["POST"])
    def admin_reset():
        _require_admin()
        state = store.get_day_state(g.day)
        new_count = (state["reset_count"] + 1) if state else 1
        ctx = DayContext(g.day, new_count)
        store.reset_day(g.day, ctx.to_dict())
        app.config["DAY_CTX"] = ctx
        g.ctx = ctx
        return redirect(url_for("login"))


def _register_main_routes(app: Flask) -> None:
    _auth_routes(app)
    _dashboard_routes(app)
    _settings_routes(app)
    _misc_routes(app)
    _extended_routes(app)
    _api_routes(app)
    _admin_routes(app)


def _register_meta_routes(app: Flask) -> None:
    # The reporting desk: auth (so a login works here too) + reports/flags/
    # analytics/triage/complete. State is shared via the same sqlite file.
    _auth_routes(app)
    _report_routes(app)


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(RedirectAbort)
    def _redirect_abort(err: RedirectAbort):
        return redirect(err.location)

    @app.errorhandler(403)
    def forbidden(_e):
        return render_template("error.html", code=403, message="Forbidden"), 403

    @app.errorhandler(404)
    def not_found(_e):
        return render_template("error.html", code=404, message="Not found"), 404

    @app.errorhandler(500)
    def server_error(_e):
        return render_template("error.html", code=500, message="Server error"), 500
