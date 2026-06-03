"""Audit engine: orchestrates detectors + LLM enrichment over source/files."""
from __future__ import annotations

import os
from collections.abc import Iterable
from dataclasses import dataclass, field

from auditor.detectors import all_detectors
from auditor.llm import get_provider
from auditor.llm.base import LLMProvider
from auditor.models import Finding, Severity
from auditor.source import SoliditySource


@dataclass
class AuditResult:
    """The full result of auditing one or more files."""

    findings: list[Finding] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    provider: str = "offline-stub"
    errors: list[str] = field(default_factory=list)

    # -- summaries --------------------------------------------------------
    def counts_by_severity(self) -> dict[str, int]:
        counts = {s.label: 0 for s in sorted(Severity, reverse=True)}
        for f in self.findings:
            counts[f.severity.label] += 1
        return counts

    def sorted_findings(self) -> list[Finding]:
        """Findings sorted by severity (desc), then file, then line."""
        return sorted(
            self.findings,
            key=lambda f: (-int(f.severity), f.file or "", f.line, f.detector),
        )

    @property
    def total(self) -> int:
        return len(self.findings)

    def summary_line(self) -> str:
        c = self.counts_by_severity()
        return (
            f"{self.total} findings across {len(self.files)} file(s): "
            f"{c['Critical']} Critical, {c['High']} High, {c['Medium']} Medium, "
            f"{c['Low']} Low, {c['Informational']} Informational."
        )


def _excerpt(src: SoliditySource, line: int, radius: int = 3) -> str:
    lo = max(1, line - radius)
    hi = min(len(src.raw_lines), line + radius)
    out = []
    for n in range(lo, hi + 1):
        marker = ">>" if n == line else "  "
        out.append(f"{marker} {n:4d}| {src.raw_lines[n - 1]}")
    return "\n".join(out)


def _enrich(findings: list[Finding], src: SoliditySource, provider: LLMProvider) -> None:
    for f in findings:
        explanation, fix = provider.explain(f, _excerpt(src, f.line))
        f.explanation = explanation
        f.fix_suggestion = fix


def audit_source(
    source: str,
    *,
    path: str | None = None,
    provider: LLMProvider | None = None,
    enrich: bool = True,
    use_slither: bool = False,
) -> AuditResult:
    """Audit a single Solidity source string.

    Parameters
    ----------
    source: the .sol contents.
    path: logical file name (used in report locations).
    provider: an LLM provider; defaults to the auto-selected one (offline stub
        unless an API key is configured).
    enrich: when True, attach LLM explanation + fix to each finding.
    use_slither: when True, also run Slither if it is installed (degrades to a
        no-op otherwise).
    """
    provider = provider or get_provider()
    src = SoliditySource(source, path=path)
    findings: list[Finding] = []
    for det in all_detectors():
        try:
            for f in det.run(src):
                f.file = path
                findings.append(f)
        except Exception as exc:  # one bad detector must not sink the audit
            findings_err = f"detector {det.id} failed: {exc!r}"
            # Record but keep going.
            findings.append(
                Finding(
                    detector=det.id,
                    title=f"Detector error: {det.id}",
                    severity=Severity.INFORMATIONAL,
                    swc_id=det.swc_id or "",
                    line=0,
                    code="",
                    description=findings_err,
                    remediation="This is an internal detector error; please report it.",
                    confidence="Low",
                    file=path,
                )
            )

    result = AuditResult(findings=findings, files=[path or "<source>"], provider=provider.name)

    if use_slither and path:
        from auditor.detectors.slither_bridge import run_slither

        result.findings.extend(run_slither(path))

    if enrich:
        _enrich(result.findings, src, provider)
    return result


def _iter_sol_files(path: str) -> Iterable[str]:
    if os.path.isfile(path):
        yield path
        return
    for root, _dirs, files in os.walk(path):
        # Skip common noise dirs.
        if any(part in root for part in ("node_modules", ".git", "artifacts", "out", "cache")):
            continue
        for name in sorted(files):
            if name.endswith(".sol"):
                yield os.path.join(root, name)


def audit_path(
    path: str,
    *,
    provider: LLMProvider | None = None,
    enrich: bool = True,
    use_slither: bool = False,
) -> AuditResult:
    """Audit a .sol file or a directory tree of .sol files."""
    provider = provider or get_provider()
    combined = AuditResult(provider=provider.name)
    for fp in _iter_sol_files(path):
        try:
            with open(fp, encoding="utf-8", errors="replace") as fh:
                source = fh.read()
        except OSError as exc:
            combined.errors.append(f"could not read {fp}: {exc}")
            continue
        sub = audit_source(
            source,
            path=fp,
            provider=provider,
            enrich=enrich,
            use_slither=use_slither,
        )
        combined.findings.extend(sub.findings)
        combined.files.extend(sub.files)
        combined.errors.extend(sub.errors)
    if not combined.files:
        combined.errors.append(f"no .sol files found at {path}")
    return combined
