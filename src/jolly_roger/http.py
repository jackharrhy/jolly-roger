import re

import httpx
from bs4 import BeautifulSoup

from .browser import gateway_origin
from .router import RouterError, parse_listing


class HttpTransport:
    def __init__(self, gateway):
        self.client = httpx.Client(
            base_url=gateway_origin(gateway),
            timeout=60,
            follow_redirects=False,
            trust_env=False,
        )

    def close(self):
        self.client.close()

    def _request(self, method, path, data=None, login=False):
        try:
            response = self.client.request(method, path, data=data)
            # Login commonly redirects to at_a_glance.jst; verify the session separately.
            if login and response.status_code in (301, 302, 303):
                return ""
            response.raise_for_status()
            return response.text
        except httpx.HTTPError:
            raise RouterError(
                "Gateway request failed; check connectivity/login. Writes are not retried."
            ) from None

    def login(self, username, password):
        self._request("GET", "/index.jst")
        self._request(
            "POST", "/check.jst", {"username": username, "password": password}, login=True
        )
        try:
            parse_listing(self.get("port_forwarding.jst"))
        except RouterError:
            raise RouterError(
                "Login could not be verified; check credentials and firmware"
            ) from None

    def get(self, path):
        if path not in ("port_forwarding.jst", "port_forwarding_add.jst") and not re.fullmatch(
            r"port_forwarding_edit\.jst\?id=[1-9][0-9]{0,2}", path
        ):
            raise RouterError("Read path not allowed")
        return self._request("GET", "/" + path)

    def post(self, fields):
        soup = BeautifulSoup(self.get("port_forwarding.jst"), "html.parser")
        scripts = "\n".join(s.get_text() for s in soup.find_all("script"))
        tokens = re.findall(r"\bvar\s+token\s*=\s*(['\"])([^'\"\\\r\n]+)\1\s*;", scripts)
        if len(tokens) != 1:
            raise RouterError("Authenticated CSRF token unavailable; no write sent")
        return self._request(
            "POST",
            "/actionHandler/ajax_port_forwarding.jst",
            {**fields, "csrfp_token": tokens[0][1]},
        )
