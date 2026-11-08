"""Read-only gateway discovery; addresses are not router fingerprints."""

import json
import subprocess

import httpx
from bs4 import BeautifulSoup

from .browser import gateway_origin
from .router import RouterError


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


def detect_backend(client):
    def read(path):
        try:
            response = client.get(path, follow_redirects=False)
            if response.is_redirect:
                if path == "/" and response.headers.get("location") == "/index.jst":
                    return ""
                raise RouterError("Gateway detection refused a redirect")
            if response.status_code in (401, 403, 404):
                return ""
            response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise RouterError("Gateway fingerprint response too large")
            return response.text
        except httpx.HTTPError:
            raise RouterError("Gateway detection request failed; specify --gateway") from None

    html = read("/")
    soup = BeautifulSoup(html, "html.parser")
    if any(f.get("action", "").lstrip("/") == "check.jst" for f in soup.find_all("form")):
        return "rdk"
    scripts = {s.get("src", "").split("?", 1)[0] for s in soup.find_all("script")}
    if "/gui/js/gui-core.js" in scripts:
        core = read("/gui/js/gui-core.js")
        if "tr181bell" in core and "GUI_DATAMODELS" in core:
            return "bell"
    index = BeautifulSoup(read("/index.jst"), "html.parser")
    if any(f.get("action", "").lstrip("/") == "check.jst" for f in index.find_all("form")):
        return "rdk"
    raise RouterError("Unknown router interface; no login or mutation attempted")
