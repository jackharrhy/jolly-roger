"""Parse RDK server-rendered values; never execute gateway JavaScript."""

import re

from bs4 import BeautifulSoup

from ...backend import Capabilities, Router
from ...models import (
    Listing,
    PartialRule,
    Removal,
    RouterError,
    Rule,
    RuleId,
    RuleSpec,
    ScanResult,
    positive,
)


def parse_id(value):
    return positive(value, 999)


def parse_listing(html):
    soup = BeautifulSoup(html, "html.parser")
    scripts = "\n".join(s.get_text() for s in soup.find_all("script"))
    states = re.findall(r'state\s*:\s*(true|false)\s*\?\s*"on"\s*:\s*"off"', scripts)
    if len(states) != 1:
        raise RouterError(
            "Missing or ambiguous global forwarding state; authentication/firmware unknown"
        )
    table = soup.find("table", summary="This table list available port forwarding entries")
    rules: list[Rule] = []
    if table is not None:
        for row in table.find_all("tr"):
            if row.find_parent("tfoot") or row.find("th"):
                continue
            cells = {}
            for td in row.find_all("td"):
                headers = td.get("headers")
                key = headers if isinstance(headers, str) else " ".join(headers or [])
                cells[key] = td.get_text(strip=True)
            checkbox = row.find("input", attrs={"name": "PortActive", "type": "checkbox"})
            identifier = checkbox.get("id") if checkbox else None
            if (
                checkbox is None
                or not isinstance(identifier, str)
                or not identifier.startswith("PortActive_")
            ):
                raise RouterError("Missing rule state")
            try:
                rule = Rule(
                    parse_id(identifier.removeprefix("PortActive_")),
                    cells["service-name"],
                    cells["service-type"],
                    cells["server-ip"],
                    positive(cells["start-port"]),
                    positive(cells["end-port"]),
                    checkbox.has_attr("checked"),
                    "" if cells["server-ipv6"] == "x" else cells["server-ipv6"],
                )
            except KeyError:
                raise RouterError("Missing rule fields") from None
            if rule.start > rule.end or rule.protocol not in ("TCP", "UDP", "TCP/UDP"):
                raise RouterError("Unrecognized rule fields")
            if any(other.id == rule.id for other in rules):
                raise RouterError("Duplicate rule ID")
            rules.append(rule)
    return Listing(
        states[0] == "true",
        rules,
        table is not None,
        "visible local forwarding rules; excludes HS/UPnP/system entries",
    )


def parse_edit(html, id) -> PartialRule | None:
    """The gated source exposes name/ports/IPv6, NOT IPv4/protocol/enabled."""
    from html import unescape

    soup = BeautifulSoup(html, "html.parser")
    scripts = "\n".join(s.get_text() for s in soup.find_all("script"))

    # Only literal strings are accepted. No eval, expression parsing, or inferred defaults.
    def literal(variable):
        matches = re.findall(
            r"\bvar\s+" + re.escape(variable) + r"\s*=\s*(['\"])([^'\"\\\n\r]*)\1\s*;", scripts
        )
        return unescape(matches[0][1]) if matches else None

    if literal("ID") != str(id):
        return None
    name, start, end = (literal(v) for v in ("service_name", "startport", "endport"))
    if not name or not start or not end:
        return None
    start, end = positive(start), positive(end)
    if start > end:
        raise RouterError("Invalid edit-page port range")
    ip, protocol = None, None
    ipv6 = literal("jsV6ServerIP")
    if ipv6 == "x":
        ipv6 = ""
    fields = [soup.find("input", id=f"server_ip_address_{n}") for n in range(1, 5)]
    values = [field.get("value") if field is not None else None for field in fields]
    octets = [value for value in values if isinstance(value, str)]
    if len(octets) == 4:
        ip = ".".join(octets)
    select = soup.find("select", id="service_type")
    if select:
        selected = select.find_all("option", selected=True)
        if len(selected) == 1 and selected[0].get_text(strip=True) in ("TCP", "UDP", "TCP/UDP"):
            protocol = selected[0].get_text(strip=True)
    return PartialRule(id, name, start, end, ip, protocol, None, ipv6)


class RdkRouter(Router):
    capabilities = Capabilities(scan_limit=999, global_toggle=True)

    """Transport supplies get(relative_path) and post(fields); no credentials here."""

    def __init__(self, transport):
        self.transport = transport

    def status(self) -> Listing:
        return parse_listing(self.transport.get("port_forwarding.jst"))

    def scan(self, max_id: int | str) -> ScanResult:
        """Read every edit page in an explicit bound; gaps never terminate discovery."""
        maximum = positive(max_id, 999)
        state = self.status()
        known = {r.id: r for r in state.rules}
        rules: list[Rule | PartialRule] = []
        unresolved = []
        for id in range(1, maximum + 1):
            html = self.transport.get(f"port_forwarding_edit.jst?id={id}")
            partial = parse_edit(html, id)
            if id in known:
                rules.append(known[id])
            elif partial is not None:
                rules.append(partial)
            else:
                unresolved.append(id)
        return ScanResult(
            enabled=state.enabled,
            rules=rules,
            complete=False,
            max_id=maximum,
            unresolved_ids=unresolved,
            scope="Bounded discovery only; unresolved IDs may be absent, hidden, or unreadable. "
            "IDs beyond max_id were not queried; null fields are unknown.",
        )

    def _writable(self):
        state = self.status()
        if not state.enabled:
            raise RouterError("Global forwarding disabled; use explicit global-enable first")
        if not state.complete:
            raise RouterError("App-gated listing: rule state/inventory unavailable; refusing write")
        return state

    def _post(self, fields):
        import json
        from html import unescape

        response = self.transport.post(fields)
        try:
            result = json.loads(unescape(response))
        except (ValueError, TypeError):
            raise RouterError(
                "Unrecognized write response; outcome unknown, inspect before retrying"
            ) from None
        if result not in ("", "Success!"):
            raise RouterError("Router rejected operation; inspect state before retrying")

    def set_global(self, enabled: bool) -> Listing:
        if type(enabled) is not bool:
            raise RouterError("Expected boolean global state")
        before = self.status()
        if before.enabled == enabled:
            return before
        self._post({"set": "true", "UFWDStatus": "Enabled" if enabled else "Disabled"})
        after = self.status()
        if after.enabled != enabled:
            raise RouterError("Global write verification failed; do not retry blindly")
        return after

    def _target(self, state, id):
        rule = next((r for r in state.rules if r.id == id), None)
        if rule is None:
            raise RouterError("Rule ID not present in visible inventory")
        rule.validate()
        return rule

    def _verify(self, before, expected):
        after = self.status()
        if not after.complete or after.enabled != before.enabled or after.rules != expected:
            raise RouterError(
                "Write verification failed; outcome uncertain, inspect before retrying"
            )
        return after

    def set_enabled(self, id: RuleId, enabled: bool) -> Rule:
        from dataclasses import replace

        id = parse_id(id)
        if type(enabled) is not bool:
            raise RouterError("Expected boolean rule state")
        before = self._writable()
        rule = self._target(before, id)
        if rule.enabled == enabled:
            return rule
        updated = replace(rule, enabled=enabled)
        self._post({"active": "true", "isChecked": str(enabled).lower(), "id": str(id)})
        self._verify(before, [updated if r.id == id else r for r in before.rules])
        return updated

    def remove(self, id: RuleId) -> Removal:
        id = parse_id(id)
        before = self._writable()
        self._target(before, id)
        self._post({"del": str(id)})
        self._verify(before, [r for r in before.rules if r.id != id])
        return Removal(id)

    def add(self, rule: RuleSpec) -> Rule:
        rule.validate()
        name, protocol, ip = rule.name, rule.protocol, rule.ip
        before = self._writable()
        for existing in before.rules:
            same_protocol = protocol == existing.protocol or "TCP/UDP" in (
                protocol,
                existing.protocol,
            )
            overlap = rule.start <= existing.end and existing.start <= rule.end
            if existing.name == name or (same_protocol and overlap):
                raise RouterError("Name or port/protocol conflict with existing rule")
        self._post(
            {
                "add": "true",
                "name": name,
                "type": protocol,
                "ip": ip,
                "ipv6addr": "x",
                "startport": str(rule.start),
                "endport": str(rule.end),
            }
        )
        after = self.status()
        old_ids = {r.id for r in before.rules}
        added = [r for r in after.rules if r.id not in old_ids]
        if (
            not after.complete
            or after.enabled != before.enabled
            or len(added) != 1
            or [r for r in after.rules if r.id in old_ids] != before.rules
        ):
            raise RouterError("Add verification failed; inspect before retrying")
        actual = added[0]
        if (actual.name, actual.protocol, actual.ip, actual.start, actual.end, actual.enabled) != (
            name,
            protocol,
            ip,
            rule.start,
            rule.end,
            True,
        ) or actual.ipv6 not in ("", "x"):
            raise RouterError("Add verification failed; inspect before retrying")
        return actual
