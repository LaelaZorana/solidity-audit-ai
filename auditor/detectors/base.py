"""Detector base class and registry."""
from __future__ import annotations

from collections.abc import Iterable

from auditor.models import Finding
from auditor.source import SoliditySource


class Detector:
    """Base class for all static detectors.

    Subclasses set the class attributes and implement :meth:`run`, yielding
    :class:`Finding` objects. The engine handles file attribution and the
    LLM-assisted enrichment, so detectors only need to produce the static facts.
    """

    id: str = ""              # stable identifier, e.g. "reentrancy"
    title: str = ""           # default short title
    swc_id: str = ""          # SWC registry id, e.g. "SWC-107"
    severity = None           # auditor.models.Severity
    references: list[str] = []

    def run(self, src: SoliditySource) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError


_REGISTRY: list[type[Detector]] = []


def register(cls: type[Detector]) -> type[Detector]:
    """Class decorator to register a detector."""
    if not cls.id:
        raise ValueError(f"Detector {cls.__name__} must define an id")
    _REGISTRY.append(cls)
    return cls


def all_detectors() -> list[Detector]:
    """Instantiate every registered detector (sorted by id for stable output)."""
    return [cls() for cls in sorted(_REGISTRY, key=lambda c: c.id)]


def detector_catalog() -> list[type[Detector]]:
    return list(sorted(_REGISTRY, key=lambda c: c.id))
