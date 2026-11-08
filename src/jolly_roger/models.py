"""Router-neutral requests and verified results. Wire formats belong to backends."""

import re
from dataclasses import dataclass
from ipaddress import IPv4Address

RuleId = int | str


class RouterError(ValueError):
    pass


def positive(value: int | str, maximum: int = 65535) -> int:
    if type(value) not in (str, int) or not re.fullmatch(r"[1-9][0-9]*", str(value)):
        raise RouterError("Expected canonical positive decimal integer")
    number = int(value)
    if number > maximum:
        raise RouterError(f"Integer exceeds {maximum}")
    return number


@dataclass(frozen=True)
class RuleSpec:
    name: str
    protocol: str
    ip: str
    start: int
    end: int

    @classmethod
    def parse(cls, name, protocol, ip, start, end=None) -> "RuleSpec":
        start = positive(start)
        spec = cls(name, protocol, ip, start, positive(end if end is not None else start))
        spec.validate()
        return spec

    def validate(self) -> None:
        if type(self.start) is not int or type(self.end) is not int:
            raise RouterError("Port fields must be canonical integers")
        positive(self.start)
        positive(self.end)
        if self.start > self.end:
            raise RouterError("Start port exceeds end port")
        if self.protocol not in ("TCP", "UDP", "TCP/UDP"):
            raise RouterError("Unsupported protocol")
        try:
            address = IPv4Address(self.ip)
        except ValueError:
            raise RouterError("Expected IPv4 address") from None
        if (
            address.is_unspecified
            or address.is_multicast
            or address.is_loopback
            or int(address) == 0xFFFFFFFF
        ):
            raise RouterError("Expected unicast IPv4 target")
        if not isinstance(self.name, str) or not self.name or self.name.strip() != self.name:
            raise RouterError("Name must be nonempty without outer whitespace")
        if not self.name.isprintable():
            raise RouterError("Name must contain printable characters")


@dataclass(frozen=True)
class Rule:
    id: RuleId
    name: str
    protocol: str
    ip: str
    start: int
    end: int
    enabled: bool
    ipv6: str = ""
    internal_start: int | None = None

    def validate(self) -> None:
        # Identifier syntax is a backend concern, not a global numeric assumption.
        if type(self.id) not in (int, str) or self.id == "":
            raise RouterError("Missing rule identifier")
        RuleSpec(self.name, self.protocol, self.ip, self.start, self.end).validate()
        if self.internal_start is not None:
            positive(self.internal_start)
            if self.internal_start + self.end - self.start > 65535:
                raise RouterError("Internal port range exceeds 65535")
        if type(self.enabled) is not bool:
            raise RouterError("Missing rule enabled state")
        if self.ipv6:
            raise RouterError("IPv6 rules are not supported for mutation")


@dataclass(frozen=True)
class Listing:
    enabled: bool | None
    rules: list[Rule]
    complete: bool
    scope: str = "local forwarding rules"


@dataclass(frozen=True)
class Removal:
    removed: RuleId
    verified: bool = True


@dataclass(frozen=True)
class PartialRule:
    id: RuleId
    name: str
    start: int
    end: int
    ip: str | None = None
    protocol: str | None = None
    enabled: bool | None = None
    ipv6: str | None = None


@dataclass(frozen=True)
class ScanResult:
    enabled: bool | None
    rules: list[Rule | PartialRule]
    complete: bool
    max_id: int
    unresolved_ids: list[int]
    scope: str
