"""Flask application: routes, feature surfaces, and the vulnerable sinks.

Every vuln is gated on today's active set. When a class is not active its
endpoint behaves safely; when it is active the primitive is real and the
handler calls store.mark_exploited only after the exploitation actually fired.
"""

from __future__ import annotations

import ipaddress
import json
import os
import random
import sqlite3
import urllib.error
import urllib.request
from datetime import date
from typing import Any

from flask import (
    Flask,
    abort,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from . import store, vulns
from .config import DayContext, today_iso

PORT = int(os.environ.get("LEDGERLY_PORT", "5001"))
HOST = os.environ.get("LEDGERLY_HOST", "127.0.0.1")

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


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("LEDGERLY_SECRET", "dev-secret-change-me")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    _prime_day(app)

    @app.template_filter("money")
    def money_filter(cents: int) -> str:
        return f"${cents / 100:,.2f}"

    @app.context_processor
    def inject_globals() -> dict[str, Any]:
        return {
            "found_active": _found_active_count,
            "registry": vulns.REGISTRY,
            "ctx": getattr(g, "ctx", None) or _fallback_ctx(),
        }

    _register_hooks(app)
    _register_routes(app)
    return app


def _found_active_count() -> int:
    return len(store.captured_slots(g.day))


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
    if len(store.captured_slots(g.day)) != len(active):
        return False
    store.complete_day(g.day)
    return True


def _lock_guard() -> None:
    """Send the player to the completion screen once the day is solved.
    The report area stays open so detailed writeups can still be submitted."""
    if _completed():
        public = {"complete", "analytics", "logout", "flags_api", "static",
                  "reports", "report_new"}
        if request.endpoint not in public:
            raise RedirectAbort(url_for("complete"))


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


# --------------------------------------------------------------------------
# auth
# --------------------------------------------------------------------------

def _auth_routes(app: Flask) -> None:
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.user:
            return redirect(url_for("dashboard"))
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
                return redirect(url_for("dashboard"))
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
            return redirect(url_for("dashboard"))
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
            q = (
                "SELECT id, username, password, role, display FROM users "
                f"WHERE username = '{username}' AND password = '{password}'"
            )
            return _row_to_dict(conn.execute(q).fetchone())
        return _row_to_dict(
            conn.execute(
                "SELECT id, username, password, role, display FROM users "
                "WHERE username=? AND password=?",
                (username, password),
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

    @app.route("/settings/api-keys")
    def api_keys():
        _require_login()
        _lock_guard()
        if not g.ctx.toggles.get("api_keys_enabled"):
            abort(404)
        return render_template("api_keys.html", ctx=g.ctx)


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
        if target == "team/me" and request.method == "PUT":
            return api_team_me()
        if target.startswith("invoices/") and request.method == "GET":
            return api_invoice(target.split("/", 1)[1])
        return jsonify({"error": "not found"}), 404

    def api_clients() -> Any:
        _require_login()
        raw = request.args.get("filter")
        with store._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM clients WHERE owner_id=? ORDER BY id", (g.user["id"],)
            ).fetchall()
        clients = [dict(r) for r in rows]
        if not raw:
            return jsonify({"clients": [c for c in clients if c["access"] != "private"]})
        try:
            filt = json.loads(raw)
        except json.JSONDecodeError:
            return jsonify({"error": "filter must be valid JSON"}), 400

        if "nosqli" in g.ctx.active_vulns and _has_operator(filt):
            result = [c for c in clients if _match_operator(c, filt)]
            leaked = [c for c in result if c["access"] == "private"]
            if leaked:
                _mark("nosqli", f"filter {raw[:120]!r} exposed {len(leaked)} private clients")
            return jsonify({"clients": result})

        filtered = [c for c in clients if _match_operator(c, filt)]
        return jsonify({"clients": [c for c in filtered if c["access"] != "private"]})

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
        slots = [
            {"slot": i + 1, "captured": (i + 1) in captured}
            for i in range(len(g.ctx.active_vulns))
        ]
        return render_template("flags.html", slots=slots, ctx=g.ctx)

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
            raise RedirectAbort(url_for("dashboard"))
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


def _register_routes(app: Flask) -> None:
    _auth_routes(app)
    _dashboard_routes(app)
    _settings_routes(app)
    _misc_routes(app)
    _api_routes(app)
    _report_routes(app)
    _admin_routes(app)

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
