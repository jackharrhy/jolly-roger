from __future__ import annotations

from contextlib import AbstractContextManager
from typing import TYPE_CHECKING

from bs4 import BeautifulSoup

from ...backend import Backend, Router
from ...connection import owned_http_session
from ...discovery import Probe
from .browser import BellBrowserTransport
from .http import BellHttpTransport
from .protocol import parse_id
from .router import BellRouter, validate_add

if TYPE_CHECKING:
    from playwright.sync_api import Page


def matches(probe: Probe) -> bool:
    soup = BeautifulSoup(probe.read("/"), "html.parser")
    scripts = set()
    for script in soup.find_all("script"):
        source = script.get("src")
        if isinstance(source, str):
            scripts.add(source.split("?", 1)[0])
    if "/gui/js/gui-core.js" not in scripts:
        return False
    core = probe.read("/gui/js/gui-core.js")
    return "tr181bell" in core and "GUI_DATAMODELS" in core


def open_http(gateway: str, username: str, password: str) -> AbstractContextManager[Router]:
    return owned_http_session(lambda: BellHttpTransport(gateway), BellRouter, username, password)


def attach_browser(page: Page, gateway: str) -> Router:
    return BellRouter(BellBrowserTransport(page, gateway))


BACKEND = Backend(
    "bell", BellRouter.capabilities, parse_id, matches, open_http, attach_browser, validate_add
)
