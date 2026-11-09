"""A cached, read-only public-interface probe; it never authenticates or follows redirects."""

from functools import cache

import httpx

from .models import RouterError


class Probe:
    def __init__(self, client: httpx.Client):
        self.client = client

    @cache
    def _response(self, path: str) -> httpx.Response:
        try:
            response = self.client.get(path, follow_redirects=False)
            if not response.is_redirect and response.status_code not in (401, 403, 404):
                response.raise_for_status()
            if len(response.content) > 2_000_000:
                raise RouterError("Gateway fingerprint response too large")
            return response
        except httpx.HTTPError:
            raise RouterError("Gateway detection request failed; specify --gateway") from None

    def read(self, path: str) -> str:
        response = self._response(path)
        return response.text if response.is_success else ""

    def redirect(self, path: str) -> str | None:
        response = self._response(path)
        return response.headers.get("location") if response.is_redirect else None
