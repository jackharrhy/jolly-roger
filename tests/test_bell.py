"""Synthetic XMO state, based on the Giga Hub 7.3.28 public UI model."""

from copy import deepcopy

import pytest

from jolly_roger.bell import BellRouter
from jolly_roger.router import RouterError


def mapping(uid=1200, **fields):
    return {
        "uid": uid,
        "Description": "web",
        "Enable": True,
        "Protocol": "TCP",
        "InternalClient": "192.168.2.30",
        "InternalPort": 8443,
        "ExternalPort": 443,
        "ExternalPortEndRange": 0,
        "Alias": "",
        "Service": "",
        **fields,
    }


class Gateway:
    def __init__(self, new_enabled=False):
        self.new_enabled = new_enabled
        self.rows = [mapping(), mapping(1, Alias="BELL_API_DMZ", Service="DMZ", ExternalPort=0)]
        self.calls = []
        self.corrupt = False

    def request(self, method, path, value=None):
        self.calls.append((method, path, value))
        if method == "getValue":
            return {"PortMappings": {"PortMapping": deepcopy(self.rows)}}
        if method == "addChild":
            self.rows.append(mapping(1201, Description="", Enable=self.new_enabled, ExternalPort=0))
            return {"uid": 1201}
        uid = int(path.split("[@uid='")[1].split("']")[0])
        row = next(r for r in self.rows if r["uid"] == uid)
        if method == "deleteChild":
            self.rows.remove(row)
        elif method == "setValue":
            row[path.rsplit("/", 1)[1]] = value
        if self.corrupt:
            self.rows[0]["InternalPort"] = 22
        return {}


def test_inventory_preserves_translated_ports_and_reports_no_global_switch():
    state = BellRouter(Gateway()).status()
    assert state.enabled is None
    assert state.complete
    assert len(state.rules) == 1
    assert state.rules[0].start == 443
    assert state.rules[0].internal_start == 8443


@pytest.mark.parametrize("new_enabled", [False, True])
@pytest.mark.parametrize("port", [25565, "25565"])
def test_add_enable_disable_and_remove_verify_unrelated_raw_entries(new_enabled, port):
    gateway = Gateway(new_enabled)
    router = BellRouter(gateway)
    original = deepcopy(gateway.rows)
    added = router.add("minecraft", "TCP", "192.168.2.30", port, port)
    assert added.id == 1201
    assert gateway.rows[:2] == original
    writes = [c for c in gateway.calls if c[0] == "setValue"]
    assert writes[-1][1].endswith("/Enable") and writes[-1][2] is True
    assert router.set_enabled(1201, False).enabled is False
    assert router.set_enabled(1201, True).enabled is True
    router.remove(1201)
    assert gateway.rows == original


def test_conflicts_unknown_fields_and_global_toggle_fail_without_writes():
    gateway = Gateway()
    router = BellRouter(gateway)
    with pytest.raises(RouterError, match="overlap|conflict"):
        router.add("collision", "TCP", "192.168.2.30", 443, 443)
    with pytest.raises(RouterError, match="global"):
        router.set_global(True)
    gateway.rows[0]["Enable"] = "false"
    with pytest.raises(RouterError):
        router.remove(1200)
    assert all(c[0] == "getValue" for c in gateway.calls)


def test_partial_write_is_not_retried_or_reported_successful():
    gateway = Gateway()
    gateway.corrupt = True
    with pytest.raises(RouterError, match="verification|changed"):
        BellRouter(gateway).add("minecraft", "TCP", "192.168.2.30", 25565, 25565)
    assert sum(c[0] == "addChild" for c in gateway.calls) == 1
    assert not any(c[1].endswith("/Enable") and c[2] is True for c in gateway.calls)
