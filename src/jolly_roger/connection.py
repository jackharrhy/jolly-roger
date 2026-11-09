"""Own the Playwright attachment, never the user's browser or login session."""

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Protocol, TypeVar

from .backend import Backend, Router
from .models import RouterError


@contextmanager
def browser_session(backend: Backend, gateway: str, endpoint: str) -> Iterator[Router]:
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        try:
            browser = p.chromium.connect_over_cdp(endpoint, timeout=15000)
        except Exception:
            raise RouterError("CDP connection failed; check the trusted browser endpoint") from None
        pages = [
            page
            for context in browser.contexts
            for page in context.pages
            if page.url.split("/", 3)[:3] == gateway.split("/", 3)[:3]
        ]
        if not pages:
            raise RouterError("No existing browser page on gateway origin; log in there first")
        yield backend.attach_browser(pages[0], gateway)
        # Stopping our Playwright client disconnects; never call browser.close().


class LoginSession(Protocol):
    def login(self, username: str, password: str) -> None: ...
    def close(self) -> None: ...


Session = TypeVar("Session", bound=LoginSession)


@contextmanager
def owned_http_session(
    create: Callable[[], Session],
    build_router: Callable[[Session], Router],
    username: str,
    password: str,
) -> Iterator[Router]:
    transport = create()
    try:
        transport.login(username, password)
        yield build_router(transport)
    finally:
        try:
            transport.close()
        except Exception:
            # Cleanup is observable without masking a verified write or its original error.
            logging.getLogger(__name__).warning(
                "Gateway session cleanup failed; session closure unverified"
            )
