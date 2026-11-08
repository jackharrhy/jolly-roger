import hashlib
import json

import httpx
import pytest

from jolly_roger.backends.bell.http import BellHttpTransport
from jolly_roger.models import RouterError

OK = 16777238


def reply(action, parameters):
    return {
        "reply": {
            "error": {"code": 16777216},
            "actions": [
                {
                    "id": 0,
                    "error": {"code": OK},
                    "callbacks": [{"result": {"code": OK}, "parameters": parameters}],
                }
            ],
        }
    }


def test_digest_login_and_read_use_real_firmware_envelope_without_password_on_wire():
    requests = []
    password = "synthetic-test-password"

    def h(x):
        return hashlib.sha512(x.encode()).hexdigest()

    def serve(request):
        if request.method == "GET":
            return httpx.Response(200, text='GUI_ACTIVATE_SHA512ENCODE_OPT:1,GUI_PASSWORD_SALT:""')
        from urllib.parse import parse_qs

        body = json.loads(parse_qs(request.content.decode())["req"][0])["request"]
        requests.append(body)
        assert password not in request.content.decode()
        nonce = "" if body["id"] == 0 else "synthetic-nonce"
        ha1 = h("admin:" + nonce + ":" + h(password))
        assert body["auth-key"] == h(f"{ha1}:{body['id']}:{body['cnonce']}:JSON:/cgi/json-req")
        action = body["actions"][0]
        if action["method"] == "logIn":
            assert body["priority"] is True
            assert body["session-id"] == "0"
            return httpx.Response(200, json=reply(action, {"id": 8, "nonce": "synthetic-nonce"}))
        assert body["session-id"] == 8
        return httpx.Response(
            200, json=reply(action, {"value": {"PortMappings": {"PortMapping": []}}})
        )

    transport = BellHttpTransport("http://192.168.2.1", transport=httpx.MockTransport(serve))
    transport.login("admin", password)
    assert transport.request("getValue", "Device/NAT/PortMappings") == {
        "PortMappings": {"PortMapping": []}
    }
    assert [r["id"] for r in requests] == [0, 1]
    transport.close()
    assert requests[-1]["actions"][0]["method"] == "logOut"
    assert transport.session == 0


def test_errors_and_redirects_never_leak_response_or_retry():
    calls = []

    def serve(request):
        calls.append(request)
        if request.method == "GET":
            return httpx.Response(200, text='GUI_ACTIVATE_SHA512ENCODE_OPT:1,GUI_PASSWORD_SALT:""')
        return httpx.Response(
            200, json={"reply": {"error": {"code": 16777223, "description": "SECRET"}}}
        )

    transport = BellHttpTransport("http://192.168.2.1", transport=httpx.MockTransport(serve))
    with pytest.raises(RouterError) as exc:
        transport.login("admin", "synthetic")
    assert "SECRET" not in str(exc.value)
    assert sum(r.method == "POST" for r in calls) == 1
    with pytest.raises(RouterError):
        transport.request("setValue", "Device/ManagementServer/Enable", True)
    transport.close()
