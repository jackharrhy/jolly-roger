"""Own the Playwright attachment, never the user's browser or login session."""

from collections.abc import Iterator
from contextlib import contextmanager

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
