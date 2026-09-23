"""All HTML and router responses in this module are synthetic, never live captures."""

import pytest

GLOBAL = '<script>$("#pf_switch").radioswitch({state: true ? "on" : "off"});</script>'
ROW = """<tr><td headers="service-name">synthetic</td><td headers="service-type">TCP</td>
<td headers="start-port">54321</td><td headers="end-port">54322</td>
<td headers="server-ip">10.0.0.42</td><td headers="server-ipv6"></td>
<td headers="active"><input type="checkbox" name="PortActive" id="PortActive_7" checked></td>
<td><a href="port_forwarding_edit.jst?id=7">Edit</a></td></tr>"""


def listing(row=ROW):
    return (
        GLOBAL
        + '<table summary="This table list available port forwarding entries">'
        + row
        + "</table>"
    )


def test_listing_and_validation():
    from jolly_roger.router import RouterError, Rule, parse_listing, positive

    result = parse_listing(listing())
    assert result.complete
    assert result.rules == [Rule(7, "synthetic", "TCP", "10.0.0.42", 54321, 54322, True, "")]
    for value in ["0", "-1", "+7", "07", "7x", " 7", True, 1.0]:
        with pytest.raises(RouterError):
            positive(value, 999)
    for changes in [
        {"start": 0},
        {"end": 65536},
        {"end": 20},
        {"ip": "::1"},
        {"protocol": "tcp"},
        {"name": "bad<name"},
        {"name": ""},
    ]:
        args = dict(
            id=7,
            name="test",
            protocol="TCP",
            ip="10.0.0.42",
            start=54321,
            end=54322,
            enabled=True,
            ipv6="",
        )
        args.update(changes)
        with pytest.raises(RouterError):
            Rule(**args).validate()
    with pytest.raises(RouterError):
        parse_listing(listing(ROW.replace('id="PortActive_7"', 'id="PortActive_07"')))
    with pytest.raises(RouterError):
        parse_listing(listing(ROW.replace('name="PortActive"', 'name="missing"')))


class SyntheticTransport:
    def __init__(self, pages, response='"Success!"'):
        self.pages = iter(pages)
        self.response = response
        self.writes = []
        self.reads = []

    def get(self, path):
        self.reads.append(path)
        return next(self.pages)

    def post(self, fields):
        self.writes.append(fields)
        return self.response


def test_verified_mutations():
    from jolly_roger.router import Router, RouterError

    for enabled in (True, False):
        before = listing(ROW.replace(" checked", "") if enabled else ROW)
        after = listing(ROW if enabled else ROW.replace(" checked", ""))
        transport = SyntheticTransport([before, after])
        result = Router(transport).set_enabled("7", enabled)
        assert result.enabled is enabled
        assert transport.writes == [dict(active="true", isChecked=str(enabled).lower(), id="7")]
    transport = SyntheticTransport([listing(), listing("")], '""')
    assert Router(transport).remove("7") == {"removed": 7, "verified": True}
    assert transport.writes == [{"del": "7"}]
    transport = SyntheticTransport([listing(), listing()], '"Success!"')
    with pytest.raises(RouterError, match="verification"):
        Router(transport).remove("7")
    for html in [GLOBAL, listing().replace("state: true", "state: false")]:
        transport = SyntheticTransport([html])
        with pytest.raises(RouterError):
            Router(transport).remove("7")
        assert not transport.writes


def test_global_change_is_separate_and_verified():
    from jolly_roger.router import Router, RouterError

    transport = SyntheticTransport([GLOBAL.replace("true", "false"), GLOBAL], '""')
    assert Router(transport).set_global(True).enabled
    assert transport.writes == [dict(set="true", UFWDStatus="Enabled")]
    transport = SyntheticTransport([GLOBAL, GLOBAL], '""')
    with pytest.raises(RouterError, match="verification"):
        Router(transport).set_global(False)


def test_add_conflicts_and_readback():
    from jolly_roger.router import Router, RouterError

    transport = SyntheticTransport([listing(""), listing()])
    rule = Router(transport).add("synthetic", "TCP", "10.0.0.42", "54321", "54322")
    assert rule.id == 7
    assert transport.writes == [
        dict(
            add="true",
            name="synthetic",
            type="TCP",
            ip="10.0.0.42",
            ipv6addr="x",
            startport="54321",
            endport="54322",
        )
    ]
    for name, protocol, start in [
        ("synthetic", "UDP", "12345"),
        ("different", "TCP", "54322"),
        ("different", "TCP/UDP", "54322"),
    ]:
        transport = SyntheticTransport([listing()])
        with pytest.raises(RouterError, match="conflict"):
            Router(transport).add(name, protocol, "10.0.0.43", start, start)
        assert not transport.writes
    transport = SyntheticTransport([GLOBAL])
    with pytest.raises(RouterError, match="gated"):
        Router(transport).add("test", "TCP", "10.0.0.43", "54323", "54323")
    assert not transport.writes
    transport = SyntheticTransport([listing(""), listing("")])
    with pytest.raises(RouterError, match="verification"):
        Router(transport).add("test", "TCP", "10.0.0.43", "54323", "54323")


def test_bounded_scan_keeps_gaps_and_reports_partial_fields():
    from jolly_roger.router import Router, RouterError

    hidden = """<script>
    var ID = "3";
    var jsV6ServerIP = "x";
    if(service_names.indexOf("synthetic") < 0){
      var service_name='synthetic'; var startport='54321'; var endport='54322';
    } else {var service_name=''; var startport=''; var endport='';}
    </script>"""
    redirect = '<script>location.href="port_forwarding.jst";</script>'
    transport = SyntheticTransport([GLOBAL, redirect, redirect, hidden])
    result = Router(transport).scan("3")
    assert result["complete"] is False
    assert result["unresolved_ids"] == [1, 2]
    assert result["rules"][0] == dict(
        id=3,
        name="synthetic",
        start=54321,
        end=54322,
        ip=None,
        protocol=None,
        enabled=None,
        ipv6="x",
    )
    assert transport.reads == ["port_forwarding.jst"] + [
        f"port_forwarding_edit.jst?id={n}" for n in (1, 2, 3)
    ]
    assert not transport.writes
    for bad in ["0", "1000", "03", "-1"]:
        with pytest.raises(RouterError):
            Router(SyntheticTransport([])).scan(bad)


def test_hidden_global_state_is_parsed_without_form():
    from jolly_roger.router import RouterError, parse_listing

    state = parse_listing("""<script>$("#pf_switch").radioswitch({
        id: "forwarding-switch", state: false ? "on" : "off" });</script>
        <span id="portmess">Use the app</span>""")
    assert state.enabled is False
    assert state.complete is False
    assert state.rules == []
    with pytest.raises(RouterError, match="global"):
        parse_listing("<html>Login</html>")
