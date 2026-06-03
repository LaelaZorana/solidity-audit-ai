"""Core data models for findings and severities."""
from __future__ import annotations

import enum
from dataclasses import asdict, dataclass, field


class Severity(enum.IntEnum):
    """Audit severity levels, ordered so they sort high-to-low naturally."""

    CRITICAL = 5
    HIGH = 4
    MEDIUM = 3
    LOW = 2
    INFORMATIONAL = 1

    @property
    def label(self) -> str:
        return {
            Severity.CRITICAL: "Critical",
            Severity.HIGH: "High",
            Severity.MEDIUM: "Medium",
            Severity.LOW: "Low",
            Severity.INFORMATIONAL: "Informational",
        }[self]

    @property
    def color(self) -> str:
        """Hex color used for HTML severity badges."""
        return {
            Severity.CRITICAL: "#b30000",
            Severity.HIGH: "#d9534f",
            Severity.MEDIUM: "#f0ad4e",
            Severity.LOW: "#5bc0de",
            Severity.INFORMATIONAL: "#777777",
        }[self]

    @classmethod
    def from_str(cls, value: str) -> Severity:
        return {s.label.lower(): s for s in cls}[value.strip().lower()]


@dataclass
class Finding:
    """A single security finding produced by a detector."""

    detector: str            # stable detector id, e.g. "reentrancy"
    title: str               # short human title
    severity: Severity
    swc_id: str              # e.g. "SWC-107"
    line: int                # 1-based line number of the primary location
    code: str                # the offending source line (trimmed)
    description: str         # what the issue is
    remediation: str         # how to fix it
    confidence: str = "Medium"          # High | Medium | Low
    file: str | None = None          # source file path (set by the engine)
    explanation: str = ""               # LLM-assisted plain-English narrative
    fix_suggestion: str = ""            # LLM-assisted concrete code fix
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        return d

    @property
    def location(self) -> str:
        where = self.file or "<source>"
        return f"{where}:{self.line}"
