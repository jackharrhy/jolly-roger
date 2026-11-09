"""Synthetic XMO state, based on the Giga Hub 7.3.28 public UI model."""

from copy import deepcopy

import pytest

from jolly_roger.backends.bell.router import BellRouter
from jolly_roger.models import RouterError, RuleSpec
from tests.fakes.bell import Gateway


def test_inventory_preserves_translated_ports_and_reports_no_global_switch():
    state = BellRouter(Gateway()).status()
    assert state.enabled is None
    assert state.complete
    assert len(state.rules) == 1
    assert state.rules[0].start == 443
    assert state.rules[0].internal_start == 8443


@pytest.mark.parametrize("new_enabled", [False, True])
def test_add_enable_disable_and_remove_verify_unrelated_raw_entries(new_enabled):
    gateway = Gateway(new_enabled)
    router = BellRouter(gateway)
    original = deepcopy(gateway.rows)
    added = router.add(RuleSpec.parse("minecraft", "TCP", "192.168.2.30", 25565))
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
        router.add(RuleSpec.parse("collision", "TCP", "192.168.2.30", 443, 443))
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
        BellRouter(gateway).add(RuleSpec.parse("minecraft", "TCP", "192.168.2.30", 25565, 25565))
    assert sum(c[0] == "addChild" for c in gateway.calls) == 1
    assert not any(c[1].endswith("/Enable") and c[2] is True for c in gateway.calls)


def test_verification_does_not_ignore_unrelated_lease_timestamp_changes():
    gateway = Gateway()
    router = BellRouter(gateway)
    expected = router._raw()
    gateway.rows[0]["LeaseStart"] = "2026-01-03T00:00:00Z"
    with pytest.raises(RouterError, match="verification"):
        router._verify(expected, updated={1201})
