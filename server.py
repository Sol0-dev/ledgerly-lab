#!/usr/bin/env python3
"""Ledgerly lab launcher and triage CLI.

Commands:
  python3 server.py run           start the lab (default port 5001)
  python3 server.py seed          print today's active classes + secrets
  python3 server.py triage        review pending reports, then accept/reject
  python3 server.py flags         list awarded flags
  python3 server.py reset         re-seed today with a fresh draw
"""

from __future__ import annotations

import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from ledgerly import store, vulns  # noqa: E402
from ledgerly.config import DayContext, today_iso  # noqa: E402


def _ctx() -> DayContext:
    store.init_db()
    state = store.get_day_state(today_iso())
    count = state["reset_count"] if state else 0
    return DayContext(today_iso(), count)


def _lan_url(port: int) -> str | None:
    """Best-effort LAN address so the lab can be routed through Burp."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        return f"http://{ip}:{port}"
    except Exception:
        return None


def cmd_run(args: argparse.Namespace) -> None:
    from ledgerly.web import create_app
    from werkzeug.serving import WSGIRequestHandler, run_simple

    store.init_db()
    app = create_app(meta=False)
    meta_app = create_app(meta=True)

    class _FingerprintHandler(WSGIRequestHandler):
        """Suppress werkzeug's own Server header so the app's fingerprint
        header is the only one a client sees."""

        def send_response(self, code, message=None):
            self.log_request(code)
            self.send_response_only(code, message)
            self.send_header("Date", self.date_time_string())

    meta_port = int(os.environ.get("LEDGERLY_META_PORT", "5002"))

    def serve(target_app, port: int, label: str) -> None:
        run_simple(
            args.host, port, target_app, threaded=True,
            request_handler=_FingerprintHandler, use_reloader=False,
        )

    print(f"Ledgerly product  listening on {args.host}:{args.port}")
    print(f"Ledgerly reporting (reports/flags/analytics) on {args.host}:{meta_port}")
    lan = _lan_url(args.port)
    if lan:
        print(f"Via proxy (Burp): browse to {lan}  - NOT localhost, so the "
              "proxy intercepts every request.")
        lan_meta = _lan_url(meta_port)
        if lan_meta:
            print(f"Reporting desk via proxy: {lan_meta}")

    import threading
    threads = [
        threading.Thread(target=serve, args=(meta_app, meta_port, "reporting"), daemon=True),
    ]
    for t in threads:
        t.start()
    serve(app, args.port, "product")


def cmd_seed(args: argparse.Namespace) -> None:
    store.init_db()
    ctx = _ctx()
    data = {"day": ctx.day, "active": ctx.active_vulns}
    if args.verbose:
        data.update(ctx.to_dict())
    print(json.dumps(data, indent=2, sort_keys=True))


def cmd_flags(args: argparse.Namespace) -> None:
    store.init_db()
    flags = store.list_flags()
    if not flags:
        print("No flags awarded yet.")
        return
    for f in flags:
        label = vulns.REGISTRY[f["class"]]["label"]
        print(f"{f['id']}  {f['day']}  {label:<32} report={f['report_id']}")


def cmd_reset(args: argparse.Namespace) -> None:
    store.init_db()
    ctx = _ctx()
    new_count = ctx.reset_count + 1
    ctx2 = DayContext(ctx.day, new_count)
    store.reset_day(ctx.day, ctx2.to_dict())
    print(f"Re-seeded {ctx.day} (draw {new_count}). Active: {', '.join(ctx2.active_vulns)}")


def cmd_triage(args: argparse.Namespace) -> None:
    store.init_db()
    day = today_iso()
    pending = store.list_reports(day=day, pending_only=True)
    if not pending:
        print("No pending reports for today.")
        return

    def show(report: dict) -> None:
        label = vulns.REGISTRY[report["matched_class"]]["label"] if report["matched_class"] else "unmatched"
        print(f"\n[{report['id']}] {report['title']}")
        print(f"  day={report['day']} class={report['class'] or '-'} severity={report['severity'] or '-'}")
        print(f"  matched={report['matched_class'] or '-'} ({label}) score={report['score']}")
        if report["endpoint"]:
            print(f"  endpoint={report['endpoint']} param={report['parameter'] or '-'}")
        if report["payload"]:
            print(f"  payload={report['payload'][:140]}")
        if report["repro"]:
            print("  repro:")
            for ln in report["repro"].splitlines():
                print(f"    {ln}")
        if report["impact"]:
            print(f"  impact={report['impact'][:140]}")
        if report["fix"]:
            print(f"  fix={report['fix'][:140]}")

    while pending:
        show(pending[0])
        rid = pending[0]["id"]
        answer = input("\naccept / reject / next / quit> ").strip().lower()
        if answer in ("q", "quit"):
            break
        if answer in ("n", "next"):
            pending.pop(0)
            continue
        if answer in ("a", "accept"):
            note = input("triage note (optional): ").strip() or None
            _accept(rid, note)
            pending.pop(0)
            continue
        if answer in ("r", "reject"):
            note = input("reason (optional): ").strip() or None
            _reject(rid, note)
            pending.pop(0)
            continue
        print("Commands: accept / reject / next / quit")


def _accept(rid: str, note: str | None) -> None:
    report = store.get_report(rid)
    if report is None:
        print("Unknown report.")
        return
    cls = report["matched_class"]
    if not cls:
        store.set_report_triage(rid, "rejected", note or "no matching exploited issue", None)
        print("Rejected: report does not match any exploited issue.")
        return
    day = report["day"]
    status = store.vuln_status(day, cls)
    if status not in ("exploited", "reported"):
        store.set_report_triage(rid, "rejected", note or "issue was not exploited", None)
        print("Rejected: the issue was never confirmed by an exploit.")
        return
    store.set_vuln_status(day, cls, "validated", f"accepted report {rid}")
    flag_id = store.award_flag(day, cls, rid)
    store.set_report_triage(rid, "accepted", note, flag_id)
    state = store.get_day_state(day)
    t_found = None
    rows = store.day_vuln_rows(day)
    for r in rows:
        if r["class"] == cls:
            t_found = r["exploited_at"]
    if state and t_found:
        t_found -= state["started_at"]
    store.upsert_history(day, cls, 1, t_found, report["score"])
    print(f"Accepted {rid}. Class {cls} validated. Flag {flag_id} awarded.")


def _reject(rid: str, note: str | None) -> None:
    report = store.get_report(rid)
    if report is None:
        print("Unknown report.")
        return
    store.set_report_triage(rid, "rejected", note, None)
    if report["matched_class"]:
        store.set_vuln_status(report["day"], report["matched_class"], "exploited")
    print(f"Rejected {rid}.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="server.py", description="Ledgerly lab")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="start the lab")
    p_run.add_argument("--host", default=os.environ.get("LEDGERLY_HOST", "0.0.0.0"))
    p_run.add_argument("--port", type=int, default=int(os.environ.get("LEDGERLY_PORT", "5001")))
    p_run.add_argument("--debug", action="store_true")
    p_run.set_defaults(func=cmd_run)

    p_seed = sub.add_parser("seed", help="show today's active classes")
    p_seed.add_argument("--verbose", action="store_true")
    p_seed.set_defaults(func=cmd_seed)

    sub.add_parser("triage", help="triage pending reports").set_defaults(func=cmd_triage)
    sub.add_parser("flags", help="list awarded flags").set_defaults(func=cmd_flags)
    sub.add_parser("reset", help="re-seed today").set_defaults(func=cmd_reset)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
