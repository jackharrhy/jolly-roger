"""The forwarding contract. Backend wire protocols are deliberately not unified."""

from abc import ABC, abstractmethod
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar

from .models import Listing, Removal, RouterError, Rule, RuleId, RuleSpec, ScanResult

if TYPE_CHECKING:
    from playwright.sync_api import Page

    from .discovery import Probe


@dataclass(frozen=True)
class Capabilities:
    scan_limit: int | None = None
    global_toggle: bool = False

    def scan_bound(self, value: int | str) -> int:
        from .models import positive

        if self.scan_limit is None:
            raise RouterError("Bounded scan is not supported by this backend; use list")
        return positive(value, self.scan_limit)

    def require(self, command: str) -> None:
        if command == "scan" and self.scan_limit is None:
            raise RouterError("Bounded scan is not supported by this backend; use list")
        if command.startswith("global-") and not self.global_toggle:
            raise RouterError("This backend does not expose a global forwarding switch")


class Router(ABC):
    capabilities: ClassVar[Capabilities] = Capabilities()

    @abstractmethod
    def status(self) -> Listing: ...

    @abstractmethod
    def add(self, rule: RuleSpec) -> Rule: ...

    @abstractmethod
    def set_enabled(self, id: RuleId, enabled: bool) -> Rule: ...

    @abstractmethod
    def remove(self, id: RuleId) -> Removal: ...

    def scan(self, max_id: int) -> ScanResult:
        raise RouterError("Bounded scan is not supported by this backend; use list")

    def set_global(self, enabled: bool) -> Listing:
        raise RouterError("This backend does not expose a global forwarding switch")


@dataclass(frozen=True)
class Backend:
    name: str
    capabilities: Capabilities
    parse_id: Callable[[RuleId], RuleId]
    matches: Callable[["Probe"], bool]
    open_http: Callable[[str, str, str], AbstractContextManager[Router]]
    attach_browser: Callable[["Page", str], Router]
