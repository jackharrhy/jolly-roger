"""Extension and ownership contracts, independent of either built-in vendor."""

import json
from contextlib import contextmanager
from dataclasses import replace

import httpx
import pytest

from jolly_roger import backends, cli
from jolly_roger.backend import Backend, Capabilities, Router
from jolly_roger.models import Listing, Removal, RouterError, Rule, RuleSpec


class FutureRouter(Router):
    def status(self):
        return Listing(None, [], True)

    def add(self, rule: RuleSpec):
        return Rule("opaque:1", rule.name, rule.protocol, rule.ip, rule.start, rule.end, True)

    def set_enabled(self, id, enabled):
        return replace(self.add(RuleSpec.parse("future", "TCP", "10.0.0.2", 1234)), enabled=enabled)

    def remove(self, id):
        return Removal(id)


@pytest.mark.parametrize("explicit", [False, True])
def test_registered_third_backend_needs_no_cli_branch_or_numeric_id_assumption(
    monkeypatch, capsys, explicit
):
    events = []

    def parse_id(value):
        if value != "opaque:1":
            raise RouterError("Unknown opaque identifier")
        return value

    @contextmanager
    def open_http(gateway, username, password):
        events.append("open")
        try:
            yield FutureRouter()
        finally:
            events.append("close")

    backend = Backend(
        "future",
        Capabilities(),
        parse_id,
        lambda probe: probe.read("/") == "future-interface",
        open_http,
        lambda page, gateway: FutureRouter(),
    )
    monkeypatch.setattr(backends, "BACKENDS", (*backends.BACKENDS, backend))
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
    monkeypatch.setattr(cli, "credentials", lambda: ("fixture-user", "fixture-password"))
    real_client = httpx.Client
    monkeypatch.setattr(
        httpx,
        "Client",
        lambda **kw: real_client(
            **kw,
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, text="future-interface")
            ),
        ),
    )
    args = ["--gateway", "http://127.0.0.1"]
    if explicit:
        args += ["--backend", "future"]
    assert cli.main([*args, "remove", "opaque:1", "--yes"]) == 0
    assert json.loads(capsys.readouterr().out) == {"removed": "opaque:1", "verified": True}
    assert events == ["open", "close"]


def test_unsupported_operation_is_rejected_before_credentials_or_browser(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)

    def forbidden():
        pytest.fail("Unsupported operation must never request credentials")

    monkeypatch.setattr(cli, "credentials", forbidden)
    assert (
        cli.main(["--gateway", "http://127.0.0.1", "--backend", "bell", "global-enable", "--yes"])
        == 2
    )
    assert "global" in capsys.readouterr().err


@pytest.mark.parametrize("name", ["rdk", "bell"])
@pytest.mark.parametrize("login_fails", [False, True])
def test_backend_owns_http_session_cleanup_even_when_login_fails(monkeypatch, name, login_fails):
    import importlib

    provider = importlib.import_module("jolly_roger.backends." + name)
    events = []

    class Transport:
        def __init__(self, gateway):
            events.append("constructed")

        def login(self, username, password):
            events.append("login")
            if login_fails:
                raise RouterError("synthetic login failure")

        def close(self):
            events.append("close")

    monkeypatch.setattr(
        provider, "HttpTransport" if name == "rdk" else "BellHttpTransport", Transport
    )
    if login_fails:
        with pytest.raises(RouterError):
            with provider.BACKEND.open_http("http://127.0.0.1", "fixture", "fixture"):
                pytest.fail("Failed login must not yield a router")
    else:
        with provider.BACKEND.open_http("http://127.0.0.1", "fixture", "fixture") as router:
            assert isinstance(router, Router)
    assert events == ["constructed", "login", "close"]
