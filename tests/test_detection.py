import json

import httpx
import pytest

from jolly_roger.discovery import detect_backend, discover_gateway
from jolly_roger.router import RouterError


def test_default_route_uses_lowest_metric_and_rejects_ambiguity():
    routes = [
        {"gateway": "192.168.2.1", "metric": 100},
        {"gateway": "10.0.0.1", "metric": 500},
    ]
    assert discover_gateway(routes) == "http://192.168.2.1"
    with pytest.raises(RouterError, match="ambiguous"):
        discover_gateway([{"gateway": "192.168.2.1"}, {"gateway": "10.0.0.1"}])
    with pytest.raises(RouterError):
        discover_gateway([])


def test_detects_bell_from_firmware_not_ip_range():
    seen = []

    def serve(request):
        seen.append(request.url.path)
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/gui/js/gui-core.js"></script>')
        if request.url.path == "/gui/js/gui-core.js":
            return httpx.Response(200, text='GUI_DATAMODELS:"gtw:tr181:tr181bell"')
        return httpx.Response(404)

    with httpx.Client(base_url="http://10.0.0.1", transport=httpx.MockTransport(serve)) as client:
        assert detect_backend(client) == "bell"
    assert seen == ["/", "/gui/js/gui-core.js"]


def test_cli_detect_does_not_authenticate_or_require_credentials(monkeypatch, capsys):
    from jolly_roger import cli

    calls = []
    real_client = httpx.Client

    def serve(request):
        calls.append(request.method)
        if request.url.path == "/":
            return httpx.Response(200, text='<script src="/gui/js/gui-core.js"></script>')
        return httpx.Response(200, text='GUI_DATAMODELS:"gtw:tr181:tr181bell"')

    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
    monkeypatch.setattr(
        httpx, "Client", lambda **kw: real_client(**kw, transport=httpx.MockTransport(serve))
    )
    assert cli.main(["--gateway", "http://192.168.2.1", "detect"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["backend"] == "bell"
    assert set(calls) == {"GET"}
    assert cli.main(["--gateway", "http://192.168.2.1", "--backend", "rdk", "detect"]) == 2
    assert "match" in capsys.readouterr().err


def test_unknown_or_redirected_gateway_never_authenticates():
    for response in [
        httpx.Response(200, text="Not a router"),
        httpx.Response(302, headers={"Location": "http://example.com"}),
    ]:
        calls = []

        def serve(request):
            calls.append(request.method)
            return response

        with httpx.Client(
            base_url="http://192.168.2.1", transport=httpx.MockTransport(serve)
        ) as client:
            with pytest.raises(RouterError, match="Unknown|redirect"):
                detect_backend(client)
        assert set(calls) == {"GET"}


def test_detects_rdk_login_form():
    def serve(request):
        return httpx.Response(200, text='<form action="check.jst"><input name="username"></form>')

    with httpx.Client(
        base_url="http://192.168.2.1", transport=httpx.MockTransport(serve)
    ) as client:
        assert detect_backend(client) == "rdk"
