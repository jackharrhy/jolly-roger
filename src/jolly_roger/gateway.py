"""Local gateway addressing, independent of router family or authentication."""

import json
import subprocess
from ipaddress import IPv4Address
from urllib.parse import urlsplit

from .models import RouterError


def gateway_origin(value):
    parsed = urlsplit(value)
    try:
        address = IPv4Address(parsed.hostname or "")
        port = parsed.port
    except ValueError:
        raise RouterError("Gateway must be a local IPv4 HTTP(S) origin") from None
    if (
        parsed.scheme not in ("http", "https")
        or not (address.is_private or address.is_loopback)
        or address.is_unspecified
        or address.is_multicast
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise RouterError("Gateway must be a local IPv4 HTTP(S) origin without credentials/path")
    return f"{parsed.scheme}://{address}" + (f":{port}" if port else "")


def discover_gateway(routes=None):
    if routes is None:
        try:
            result = subprocess.run(
                ["ip", "-j", "-4", "route", "show", "default"],
                capture_output=True,
                text=True,
                check=True,
                timeout=5,
            )
            routes = json.loads(result.stdout)
        except (OSError, ValueError, subprocess.SubprocessError):
            raise RouterError("Cannot discover default gateway; specify --gateway") from None
    candidates = [r for r in routes if r.get("gateway") and r.get("type", "unicast") == "unicast"]
    if not candidates:
        raise RouterError("No IPv4 default gateway; specify --gateway")
    metric = min(r.get("metric", 0) for r in candidates)
    gateways = {r["gateway"] for r in candidates if r.get("metric", 0) == metric}
    if len(gateways) != 1:
        raise RouterError("Default route is ambiguous; specify --gateway")
    return gateway_origin("http://" + gateways.pop())
