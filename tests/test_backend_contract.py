"""Both real drivers must honor the same domain-level operation contract."""

from dataclasses import is_dataclass

import pytest

from jolly_roger.backends.bell.router import BellRouter
from jolly_roger.backends.rdk.router import RdkRouter
from tests.fakes.bell import Gateway
from tests.fakes.rdk import ROW, SyntheticTransport, listing


@pytest.mark.parametrize("backend", ["rdk", "bell"])
def test_remove_returns_a_verified_removal_not_vendor_specific_data(backend):
    if backend == "rdk":
        router = RdkRouter(SyntheticTransport([listing(), listing("")]))
        id = 7
    else:
        router = BellRouter(Gateway())
        id = 1200
    result = router.remove(id)
    assert is_dataclass(result), "Removal is a shared typed result, not a provider dictionary"
    assert result.removed == id
    assert result.verified is True


@pytest.mark.parametrize("backend", ["rdk", "bell"])
def test_add_accepts_one_shared_request_model(backend):
    from jolly_roger.models import Rule, RuleSpec

    if backend == "rdk":
        added = (
            ROW.replace("synthetic", "contract").replace("54321", "25565").replace("54322", "25565")
        )
        router = RdkRouter(SyntheticTransport([listing(""), listing(added)]))
    else:
        router = BellRouter(Gateway())
    result = router.add(RuleSpec.parse("contract", "TCP", "10.0.0.42", 25565))
    assert isinstance(result, Rule)
    assert (result.name, result.start, result.end) == ("contract", 25565, 25565)


def test_toggle_returns_the_same_rule_shape_for_both_drivers():
    rdk = RdkRouter(SyntheticTransport([listing(), listing(ROW.replace(" checked", ""))]))
    bell = BellRouter(Gateway())
    left = rdk.set_enabled(7, False)
    right = bell.set_enabled(1200, False)
    assert type(left) is type(right)
    assert left.enabled is right.enabled is False
