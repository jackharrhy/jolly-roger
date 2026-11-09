"""Built-in backends. Adding a family changes this registry, not the CLI."""

import httpx

from ..backend import Backend
from ..discovery import Probe
from ..models import RouterError
from .bell import BACKEND as BELL
from .rdk import BACKEND as RDK

BACKENDS = (BELL, RDK)


def named_backend(name: str) -> Backend:
    for backend in BACKENDS:
        if backend.name == name:
            return backend
    raise RouterError("Unknown backend")


def detect_backend(client: httpx.Client, requested: str = "auto") -> Backend:
    candidates = BACKENDS if requested == "auto" else (named_backend(requested),)
    probe = Probe(client)
    for backend in candidates:
        if backend.matches(probe):
            return backend
    if requested != "auto":
        raise RouterError("Detected router does not match requested --backend; no login sent")
    raise RouterError("Unknown router interface; no login or mutation attempted")
