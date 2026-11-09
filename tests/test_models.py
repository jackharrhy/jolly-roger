"""Wire sentinels must be decoded before entering shared models."""

import pytest

from jolly_roger.backends.rdk.router import parse_listing
from jolly_roger.models import RouterError, Rule
from tests.fakes.rdk import ROW, listing


def test_rdk_decodes_its_ipv4_only_wire_sentinel():
    html = listing(ROW.replace('headers="server-ipv6"></td>', 'headers="server-ipv6">x</td>'))
    assert parse_listing(html).rules[0].ipv6 == ""


def test_common_rule_does_not_accept_a_vendor_specific_ipv6_sentinel():
    with pytest.raises(RouterError, match="IPv6"):
        Rule("opaque:1", "neutral", "TCP", "10.0.0.2", 1234, 1234, True, ipv6="x").validate()
