import argparse
import getpass
import json
import os
import sys
from contextlib import AbstractContextManager
from dataclasses import asdict, is_dataclass
from urllib.parse import urlsplit

import httpx
from dotenv import load_dotenv

from . import backends
from .backend import Backend, Router
from .connection import browser_session
from .gateway import discover_gateway, gateway_origin
from .models import Listing, Removal, RouterError, Rule, RuleSpec, ScanResult, positive


def parser():
    p = argparse.ArgumentParser(description="Local router forwarding; JSON output, explicit writes")
    p.add_argument(
        "--gateway",
        default=os.getenv("JOLLY_ROGER_GATEWAY"),
        help="Local IPv4 HTTP(S) origin; otherwise discover the IPv4 default gateway",
    )
    p.add_argument(
        "--cdp-url", help="Attach existing authenticated Chromium via a trusted CDP endpoint"
    )
    p.add_argument(
        "--backend",
        choices=("auto", *(backend.name for backend in backends.BACKENDS)),
        default="auto",
        help="Require a matching router family; auto uses public interface fingerprints",
    )
    commands = p.add_subparsers(dest="command", required=True)
    for name in ("detect", "status", "list"):
        commands.add_parser(name)
    scan = commands.add_parser(
        "scan", help="Read-only, bounded edit-page discovery; never claims completeness"
    )
    scan.add_argument(
        "--max-id", required=True, help="Explicit inclusive bound; limited by the selected backend"
    )
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
    args.gateway = gateway_origin(args.gateway) if args.gateway else None
    if args.command == "scan":
        args.max_id = positive(args.max_id)
    if args.command == "add":
        args.rule = RuleSpec.parse(args.name, args.protocol, args.ip, args.start, args.end)
        if args.scan_max_id is not None:
            args.scan_max_id = positive(args.scan_max_id)
    if args.backend != "auto":
        validate_backend(args, backends.named_backend(args.backend))
    args.gateway = args.gateway or discover_gateway()
    if args.command == "add" and args.ip == urlsplit(args.gateway).hostname:
        raise RouterError("Target cannot be the gateway address")
    if hasattr(args, "yes") and not args.yes:
        if not sys.stdin.isatty():
            raise RouterError("Mutation requires confirmation; pass --yes in noninteractive use")
        if input(f"Confirm {args.command} on {args.gateway}? Type yes: ") != "yes":
            raise RouterError("Mutation cancelled")


def validate_backend(args, backend: Backend) -> None:
    backend.capabilities.require(args.command)
    if hasattr(args, "id"):
        args.id = backend.parse_id(args.id)
    bound = args.max_id if args.command == "scan" else getattr(args, "scan_max_id", None)
    if bound is not None:
        backend.capabilities.scan_bound(bound)


def dispatch(router: Router, args) -> Listing | Rule | Removal | ScanResult:
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
        if any(r.enabled is None for r in inventory.rules):
            raise RouterError(
                "Bounded scan found rules without enabled state; refusing add on gated firmware"
            )
    return router.add(args.rule)


def credentials() -> tuple[str, str]:
    username = os.getenv("JOLLY_ROGER_USERNAME", "admin")
    password = os.getenv("JOLLY_ROGER_PASSWORD")
    if not password:
        if not sys.stdin.isatty():
            raise RouterError("Set JOLLY_ROGER_PASSWORD in .env or use a terminal password prompt")
        password = getpass.getpass("Router password: ")
    return username, password


def main(argv=None):
    load_dotenv(".env", override=False, interpolate=False)
    args = parser().parse_args(argv)
    try:
        validate(args)
        with httpx.Client(
            base_url=args.gateway, timeout=10, follow_redirects=False, trust_env=False
        ) as probe:
            backend = backends.detect_backend(probe, args.backend)
        validate_backend(args, backend)
        result: Listing | Rule | Removal | ScanResult | dict[str, str]
        if args.command == "detect":
            result = {"gateway": args.gateway, "backend": backend.name}
        else:
            session: AbstractContextManager[Router]
            if args.cdp_url:
                session = browser_session(backend, args.gateway, args.cdp_url)
            else:
                username, password = credentials()
                session = backend.open_http(args.gateway, username, password)
            with session as router:
                result = dispatch(router, args)
        print(json.dumps(asdict(result) if is_dataclass(result) else result, indent=2))
        return 0
    except RouterError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("error: cancelled", file=sys.stderr)
        return 2
    except Exception:
        # Browser/HTTP exceptions can contain credentials or page HTML.
        print("error: operation failed; inspect state before retrying any write", file=sys.stderr)
        return 2
