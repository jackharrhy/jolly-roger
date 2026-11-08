from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from ...backend import Backend, Router
from ...discovery import Probe
from .browser import BrowserTransport
from .http import HttpTransport
from .router import RdkRouter, parse_id

if TYPE_CHECKING:
    from playwright.sync_api import Page


def matches(probe: Probe) -> bool:
    def login(html: str) -> bool:
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action")
            if isinstance(action, str) and action.lstrip("/") == "check.jst":
                return True
        return False

    if login(probe.read("/")):
        return True
    if probe.redirect("/") not in (None, "/index.jst"):
        return False
    return login(probe.read("/index.jst"))


@contextmanager
def open_http(gateway: str, username: str, password: str) -> Iterator[Router]:
    transport = HttpTransport(gateway)
    try:
        transport.login(username, password)
        yield RdkRouter(transport)
    finally:
        transport.close()


def attach_browser(page: Page, gateway: str) -> Router:
    return RdkRouter(BrowserTransport(page, gateway))


BACKEND = Backend("rdk", RdkRouter.capabilities, parse_id, matches, open_http, attach_browser)
