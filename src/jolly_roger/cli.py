import argparse
import getpass
import json
import os
import sys
from dataclasses import asdict, is_dataclass
from urllib.parse import urlsplit

from dotenv import load_dotenv

from .browser import BrowserTransport, gateway_origin
from .http import HttpTransport
from .router import Router, RouterError, Rule, positive


def parser():
    p = argparse.ArgumentParser(description="Local Rogers forwarding; JSON output, explicit writes")
    p.add_argument(
        "--gateway",
        default=os.getenv("JOLLY_ROGER_GATEWAY", "http://10.0.0.1"),
        help="Local IPv4 HTTP(S) origin",
    )
    p.add_argument(
        "--cdp-url", help="Attach existing authenticated Chromium via a trusted CDP endpoint"
    )
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("status", "list"):
        commands.add_parser(name)
    scan = commands.add_parser(
        "scan", help="Read-only, bounded edit-page discovery; never claims completeness"
    )
    scan.add_argument("--max-id", required=True, help="Explicit inclusive bound, 1–999")
    for name in ("remove", "enable", "disable", "global-enable", "global-disable"):
        command = commands.add_parser(name)
        if not name.startswith("global-"):
            command.add_argument("id")
        command.add_argument("--yes", action="store_true", help="Confirm this mutation")
    add = commands.add_parser("add", help="IPv4 only; same internal/external port range")
    add.add_argument("--name", required=True)
    add.add_argument("--protocol", choices=("TCP", "UDP", "TCP/UDP"), required=True)
    add.add_argument("--ip", required=True)
    add.add_argument("--start", required=True)
    add.add_argument("--end", help="Inclusive end; defaults to start")
    add.add_argument(
        "--scan-max-id", help="Optional bounded gated discovery; cannot supply missing rule state"
    )
    add.add_argument("--yes", action="store_true", help="Confirm this mutation")
    return p


def validate(args):
    args.gateway = gateway_origin(args.gateway)
    if args.command in ("remove", "enable", "disable"):
        args.id = positive(args.id, 999)
    if args.command == "scan":
        args.max_id = positive(args.max_id, 999)
    if args.command == "add":
        args.start = positive(args.start)
        args.end = positive(args.end if args.end is not None else args.start)
        Rule(1, args.name, args.protocol, args.ip, args.start, args.end, True).validate()
        if args.ip == urlsplit(args.gateway).hostname:
            raise RouterError("Target cannot be the gateway address")
        if args.scan_max_id is not None:
            args.scan_max_id = positive(args.scan_max_id, 999)
    if hasattr(args, "yes") and not args.yes:
        if not sys.stdin.isatty():
            raise RouterError("Mutation requires confirmation; pass --yes in noninteractive use")
        if input(f"Confirm {args.command} on {args.gateway}? Type yes: ") != "yes":
            raise RouterError("Mutation cancelled")


def dispatch(router, args):
    if args.command in ("list", "status"):
        return router.status()
    if args.command == "scan":
        return router.scan(args.max_id)
    if args.command.startswith("global-"):
        return router.set_global(args.command == "global-enable")
    if args.command == "remove":
        return router.remove(args.id)
    if args.command in ("enable", "disable"):
        return router.set_enabled(args.id, args.command == "enable")
    if args.scan_max_id is not None:
        # Discovery is diagnostic, never authorization to invent absent fields.
        inventory = router.scan(args.scan_max_id)
        if any(r["enabled"] is None for r in inventory["rules"]):
            raise RouterError(
                "Bounded scan found rules without enabled state; refusing add on gated firmware"
            )
    return router.add(args.name, args.protocol, args.ip, args.start, args.end)


def main(argv=None):
    load_dotenv(".env", override=False, interpolate=False)
    args = parser().parse_args(argv)
    try:
        validate(args)
        if not args.cdp_url:
            username = os.getenv("JOLLY_ROGER_USERNAME", "admin")
            password = os.getenv("JOLLY_ROGER_PASSWORD")
            if not password:
                if not sys.stdin.isatty():
                    raise RouterError(
                        "Set JOLLY_ROGER_PASSWORD in .env or use a terminal password prompt"
                    )
                password = getpass.getpass("Router password: ")
            transport = HttpTransport(args.gateway)
            try:
                transport.login(username, password)
                result = dispatch(Router(transport), args)
                print(json.dumps(asdict(result) if is_dataclass(result) else result, indent=2))
            finally:
                transport.close()
            return 0
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            try:
                browser = p.chromium.connect_over_cdp(args.cdp_url, timeout=15000)
            except Exception:
                raise RouterError(
                    "CDP connection failed; check the trusted browser endpoint"
                ) from None
            pages = [
                page
                for context in browser.contexts
                for page in context.pages
                if page.url.split("/", 3)[:3] == args.gateway.split("/", 3)[:3]
            ]
            if not pages:
                raise RouterError("No existing browser page on gateway origin; log in there first")
            result = dispatch(Router(BrowserTransport(pages[0], args.gateway)), args)
            print(json.dumps(asdict(result) if is_dataclass(result) else result, indent=2))
            # Disconnect without closing the user's browser.
        return 0
    except RouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("error: cancelled", file=sys.stderr)
        return 2
    except Exception:
        # Playwright errors may embed page HTML/URLs; never print arbitrary exception details.
        print(
            "error: operation failed; inspect state before retrying any write",
            file=sys.stderr,
        )
        return 2
