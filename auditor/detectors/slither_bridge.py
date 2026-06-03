"""Optional Slither integration.

This is a *graceful* bridge: if Slither (and a Solidity compiler) is installed,
``run_slither`` shells out to it and converts its JSON findings into our
:class:`Finding` model. If it is not installed, the function returns an empty
list and never raises, so the pure-Python detectors remain the source of truth.

Slither is never required for the tool to work and is not a test dependency.
"""
from __future__ import annotations

import json
import shutil
import subprocess

from auditor.models import Finding, Severity

# Map Slither impact strings to our severities.
_IMPACT_TO_SEVERITY = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFORMATIONAL,
    "Optimization": Severity.INFORMATIONAL,
}


def slither_available() -> bool:
    return shutil.which("slither") is not None


def run_slither(path: str, timeout: int = 120) -> list[Finding]:
    """Run Slither on ``path`` if available; otherwise return []."""
    if not slither_available():
        return []
    try:
        proc = subprocess.run(
            ["slither", path, "--json", "-"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, OSError):
        return []
    # Slither exits non-zero when it finds issues; parse stdout regardless.
    raw = proc.stdout.strip()
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not data.get("success", True) and not data.get("results"):
        return []
    return list(_convert(data))


def _convert(data: dict) -> list[Finding]:
    findings: list[Finding] = []
    for det in data.get("results", {}).get("detectors", []):
        sev = _IMPACT_TO_SEVERITY.get(det.get("impact", "Low"), Severity.LOW)
        elements = det.get("elements", [])
        line, file_, code = 0, None, ""
        for el in elements:
            sm = el.get("source_mapping") or {}
            lines = sm.get("lines") or []
            if lines:
                line = lines[0]
                file_ = sm.get("filename_short")
                break
        findings.append(
            Finding(
                detector=f"slither:{det.get('check', 'unknown')}",
                title=det.get("check", "Slither finding").replace("-", " ").title(),
                severity=sev,
                swc_id=_slither_swc(det.get("check", "")),
                line=line or 0,
                code=code,
                description=(det.get("description") or "").strip(),
                remediation="See Slither documentation for this check.",
                confidence=det.get("confidence", "Medium"),
                file=file_,
            )
        )
    return findings


def _slither_swc(check: str) -> str:
    return {
        "reentrancy-eth": "SWC-107",
        "reentrancy-no-eth": "SWC-107",
        "tx-origin": "SWC-115",
        "unchecked-lowlevel": "SWC-104",
        "unchecked-send": "SWC-104",
        "suicidal": "SWC-106",
        "controlled-delegatecall": "SWC-112",
        "weak-prng": "SWC-120",
        "solc-version": "SWC-103",
    }.get(check, "")
