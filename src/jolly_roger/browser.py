"""Authenticated same-origin fetch; tokens and cookies stay inside Chromium."""

import re
from ipaddress import IPv4Address
from urllib.parse import urlsplit

from .router import RouterError

# This is our fixed code, not JavaScript extracted from the gateway.
FETCH = r"""async ({origin, path, fields}) => {
    if (location.origin !== origin) return {error: 'origin'};
    const read = async (path, options = {}) => {
        const response = await fetch(origin + '/' + path, {
            credentials: 'same-origin', cache: 'no-store', redirect: 'error',
            signal: AbortSignal.timeout(60000), ...options
        });
        if (!response.ok) throw new Error('http');
        return await response.text();
    };
    try {
        if (fields !== null) {
            const html = await read('port_forwarding.jst');
            const doc = new DOMParser().parseFromString(html, 'text/html');
            const scripts = [...doc.scripts].map(s => s.textContent).join('\n');
            const tokens = [...scripts.matchAll(/\bvar\s+token\s*=\s*(["'])([^"'\\\r\n]+)\1\s*;/g)];
            if (tokens.length !== 1) return {error: 'token'};
            const body = new URLSearchParams({...fields, csrfp_token: tokens[0][2]});
            const text = await read('actionHandler/ajax_port_forwarding.jst', {
                method: 'POST', body,
                headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                          'X-Requested-With': 'XMLHttpRequest'}
            });
            // Return only the handler's documented response vocabulary, never arbitrary HTML.
            if (text.trim() === '"Success!"' || text.trim() === '""') return {text};
            return {error: 'rejected'};
        }
        const html = await read(path);
        const doc = new DOMParser().parseFromString(html, 'text/html');
        doc.querySelectorAll('input[type=password], input[name=csrfp_token]').forEach(e => e.remove());
        doc.querySelectorAll('script').forEach(s => {
            s.textContent = s.textContent.replace(/\bvar\s+token\s*=\s*(["'])([^"'\\\r\n]*)\1\s*;/g,
                                                'var token = "REDACTED";');
        });
        return {text: doc.documentElement.outerHTML};
    } catch (_) { return {error: 'request'}; }
}"""


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


class BrowserTransport:
    """Accept a synchronous Playwright Page already on the gateway origin."""

    def __init__(self, page, gateway="http://10.0.0.1"):
        self.page = page
        self.origin = gateway_origin(gateway)

    def _request(self, path, fields=None):
        try:
            result = self.page.evaluate(FETCH, dict(origin=self.origin, path=path, fields=fields))
        except Exception:
            raise RouterError(
                "Browser request failed; authentication or connection lost; "
                "write outcome may be unknown"
            ) from None
        if "error" in result:
            messages = {
                "origin": "Browser page is not on the configured gateway origin",
                "token": "Authenticated CSRF token unavailable; no write sent",
                "rejected": "Router response not successful; inspect state before retrying",
                "request": "Gateway request failed; write outcome may be unknown; inspect before retrying",
            }
            raise RouterError(messages.get(result["error"], "Browser request failed"))
        return result["text"]

    def get(self, path):
        if path not in ("port_forwarding.jst", "port_forwarding_add.jst") and not re.fullmatch(
            r"port_forwarding_edit\.jst\?id=[1-9][0-9]{0,2}", path
        ):
            raise RouterError("Read path not allowed (the action handler must NEVER receive GET)")
        return self._request(path)

    def post(self, fields):
        return self._request("actionHandler/ajax_port_forwarding.jst", fields)
