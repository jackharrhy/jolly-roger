"""Bell/Sagemcom forwarding, derived from Giga Hub's public web UI 7.3.28.

XMO supplies request(method, xpath, value=None). No automatic write retries or
cleanup: a failed multi-step add may leave an incomplete, disabled entry.
"""

from dataclasses import replace

from .router import Listing, RouterError, Rule, positive

PATH = "Device/NAT/PortMappings"


def row_id(row):
    value = row.get("uid", row.get("@uid"))
    if "uid" in row and "@uid" in row and row["uid"] != row["@uid"]:
        raise RouterError("Conflicting Bell mapping identifiers")
    return positive(value, 4294967295)


def node(id):
    return f"{PATH}/PortMapping[@uid='{positive(id, 4294967295)}']"


def parse_row(row):
    try:
        start = positive(row["ExternalPort"])
        end = row["ExternalPortEndRange"]
        end = start if type(end) in (int, str) and end in (0, "0") else positive(end)
        protocol = "TCP/UDP" if row["Protocol"] == "BOTH" else row["Protocol"]
        rule = Rule(
            row_id(row),
            row["Description"],
            protocol,
            row["InternalClient"],
            start,
            end,
            row["Enable"],
            internal_start=positive(row["InternalPort"]),
        )
        rule.validate()
        return rule
    except (KeyError, TypeError):
        raise RouterError("Missing or malformed Bell mapping fields") from None


def enabled_row(row, enabled):
    result = {**row, "Enable": enabled}
    if "Status" in row:
        result["Status"] = "ENABLED" if enabled else "DISABLED"
    return result


class BellRouter:
    def __init__(self, transport):
        self.transport = transport

    def _raw(self):
        value = self.transport.request("getValue", PATH)
        # XMO wraps content names; the browser API removes the outer wrapper.
        if isinstance(value, dict) and set(value) == {"PortMappings"}:
            value = value["PortMappings"]
        if isinstance(value, dict) and "PortMapping" in value:
            value = value["PortMapping"]
        if not isinstance(value, list) or not all(isinstance(r, dict) for r in value):
            raise RouterError("Bell forwarding collection unavailable; no write sent")
        rows = {row_id(r): r for r in value}
        if len(rows) != len(value):
            raise RouterError("Duplicate Bell mapping identifiers")
        return rows

    def _listing(self, rows):
        rules, complete = [], True
        for row in rows.values():
            if row.get("Alias") == "BELL_API_DMZ" and row.get("Service") == "DMZ":
                continue
            try:
                rules.append(parse_row(row))
            except (RouterError, ValueError, TypeError):
                complete = False
        return Listing(
            None,
            rules,
            complete,
            "Bell NAT mappings; protected DMZ entry omitted; no global forwarding switch",
        )

    def status(self):
        return self._listing(self._raw())

    def _writable(self):
        rows = self._raw()
        if not self._listing(rows).complete:
            raise RouterError("Incomplete Bell forwarding inventory; refusing write")
        return rows

    def _target(self, rows, id):
        id = positive(id, 4294967295)
        if id not in rows:
            raise RouterError("Rule ID not present in inventory")
        row = rows[id]
        if row.get("Service") == "DMZ" or "upnp" in str(row.get("Creator", "")).lower():
            raise RouterError("Refusing mutation of a DMZ or UPnP-managed mapping")
        return parse_row(row)

    def _verify(self, expected, updated=()):
        after = self._raw()
        comparison = {k: dict(v) for k, v in after.items()}
        for id in updated:
            if id in comparison and id in expected:
                if isinstance(comparison[id].get("LeaseStart"), str) and isinstance(
                    expected[id].get("LeaseStart"), str
                ):
                    # The modem regenerates this read-only timestamp on configuration changes.
                    comparison[id]["LeaseStart"] = expected[id]["LeaseStart"]
        if comparison != expected:
            raise RouterError(
                "Bell write verification failed; state changed, inspect before retrying"
            )
        return after

    def set_global(self, enabled):
        raise RouterError("Bell does not expose this global forwarding switch")

    def scan(self, max_id):
        raise RouterError("Bell has a collection inventory; use list, not RDK edit-page scan")

    def set_enabled(self, id, enabled):
        if type(enabled) is not bool:
            raise RouterError("Expected boolean rule state")
        rows = self._writable()
        rule = self._target(rows, id)
        if rule.enabled == enabled:
            return rule
        self.transport.request("setValue", node(rule.id) + "/Enable", enabled)
        expected = {k: dict(v) for k, v in rows.items()}
        expected[rule.id] = enabled_row(expected[rule.id], enabled)
        self._verify(expected, updated={rule.id})
        return replace(rule, enabled=enabled)

    def remove(self, id):
        rows = self._writable()
        rule = self._target(rows, id)
        self.transport.request("deleteChild", node(rule.id))
        self._verify({k: v for k, v in rows.items() if k != rule.id})
        return rule

    def add(self, name, protocol, ip, start, end):
        start, end = positive(start), positive(end)
        requested = Rule(
            1,
            name,
            protocol,
            ip,
            positive(start),
            positive(end),
            True,
            internal_start=positive(start),
        )
        requested.validate()
        before = self._writable()

        def protocols(p):
            return {"TCP", "UDP"} if p == "TCP/UDP" else {p}

        for other in self._listing(before).rules:
            if (
                protocols(protocol) & protocols(other.protocol)
                and start <= other.end
                and end >= other.start
            ):
                raise RouterError("Port range overlaps an existing mapping")
        # Match the UI: allocate one child, then populate its fields. Never retry.
        created = self.transport.request("addChild", PATH, {})
        if not isinstance(created, dict):
            raise RouterError("Bell add outcome unknown; inspect before retrying")
        id = positive(created.get("uid"), 4294967295)
        rows = self._raw()
        if (
            id in before
            or set(rows) != set(before) | {id}
            or any(rows[k] != v for k, v in before.items())
        ):
            raise RouterError("Bell add verification failed; unrelated inventory changed")
        if type(rows[id].get("Enable")) is not bool:
            raise RouterError("New Bell entry has unknown enabled state; inspect before continuing")
        if rows[id]["Enable"]:
            self.transport.request("setValue", node(id) + "/Enable", False)
            rows[id] = enabled_row(rows[id], False)
            self._verify(rows, updated={id})
        values = {
            "Description": name,
            "Protocol": "BOTH" if protocol == "TCP/UDP" else protocol,
            "InternalClient": ip,
            "InternalPort": start,
            "ExternalPort": start,
            "ExternalPortEndRange": 0 if start == end else end,
        }
        expected = {k: dict(v) for k, v in rows.items()}
        for field, value in values.items():
            self.transport.request("setValue", node(id) + "/" + field, value)
            expected[id][field] = value
        self._verify(expected, updated={id})
        self.transport.request("setValue", node(id) + "/Enable", True)
        expected[id] = enabled_row(expected[id], True)
        verified = self._verify(expected, updated={id})
        return parse_row(verified[id])
