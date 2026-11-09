"""Provider policy and session cleanup must not leak into CLI flow."""

import importlib

import pytest

from jolly_roger import cli
from jolly_roger.models import RouterError, RuleSpec


def test_rdk_name_restrictions_are_enforced_before_authentication(monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_dotenv", lambda *a, **kw: None)
    monkeypatch.setattr(cli, "credentials", lambda: pytest.fail("must fail before credentials"))
    assert (
        cli.main(
            [
                "--gateway",
                "http://127.0.0.1",
                "--backend",
                "rdk",
                "add",
                "--name",
                "bad&name",
                "--protocol",
                "TCP",
                "--ip",
                "10.0.0.2",
                "--start",
                "1234",
                "--yes",
            ]
        )
        == 2
    )
    assert "name" in capsys.readouterr().err.lower()


@pytest.mark.parametrize("name", ["rdk", "bell"])
@pytest.mark.parametrize("operation_fails", [False, True])
def test_cleanup_failure_does_not_mask_the_operation(monkeypatch, caplog, name, operation_fails):
    provider = importlib.import_module("jolly_roger.backends." + name)

    class Transport:
        def __init__(self, gateway):
            pass

        def login(self, username, password):
            pass

        def close(self):
            raise RuntimeError("PRIVATE cleanup detail")

    monkeypatch.setattr(
        provider, "HttpTransport" if name == "rdk" else "BellHttpTransport", Transport
    )
    if operation_fails:
        with pytest.raises(RouterError, match="original operation"):
            with provider.BACKEND.open_http("http://127.0.0.1", "fixture", "fixture"):
                raise RouterError("original operation")
    else:
        with provider.BACKEND.open_http("http://127.0.0.1", "fixture", "fixture") as router:
            assert router is not None
    assert "PRIVATE" not in caplog.text
    assert "cleanup" in caplog.text.lower()


def test_bell_and_rdk_own_different_service_name_schemas():
    from jolly_roger.backends.bell import BACKEND as bell
    from jolly_roger.backends.rdk import BACKEND as rdk

    rule = RuleSpec.parse("café " + "a" * 59, "TCP", "10.0.0.2", 1234)
    bell.validate_add(rule)
    with pytest.raises(RouterError, match="RDK"):
        rdk.validate_add(rule)
    with pytest.raises(RouterError, match="64"):
        bell.validate_add(RuleSpec.parse("a" * 65, "TCP", "10.0.0.2", 1234))
