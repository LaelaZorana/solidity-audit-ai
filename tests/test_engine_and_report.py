"""Tests for the engine orchestration and report generation."""
from __future__ import annotations

import json
import os

from auditor.engine import audit_path, audit_source
from auditor.llm import OfflineStubProvider, get_provider
from auditor.report import to_html, to_markdown
from tests.conftest import SAFE, VULN


def test_audit_directory_aggregates_files():
    result = audit_path(VULN)
    assert len(result.files) == 8
    assert result.total > 0
    counts = result.counts_by_severity()
    assert counts["Critical"] >= 2
    assert counts["High"] >= 3


def test_summary_line_consistent_with_counts():
    result = audit_path(VULN)
    counts = result.counts_by_severity()
    assert sum(counts.values()) == result.total


def test_findings_sorted_by_severity_desc():
    result = audit_path(VULN)
    sevs = [int(f.severity) for f in result.sorted_findings()]
    assert sevs == sorted(sevs, reverse=True)


def test_offline_provider_is_default_without_keys(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("AUDIT_LLM_PROVIDER", raising=False)
    provider = get_provider()
    assert isinstance(provider, OfflineStubProvider)
    assert provider.name == "offline-stub"


def test_enrichment_populates_explanation_and_fix():
    result = audit_path(os.path.join(VULN, "Reentrancy.sol"))
    reentrancy = [f for f in result.findings if f.detector == "reentrancy"]
    assert reentrancy
    f = reentrancy[0]
    assert f.explanation.strip()
    assert f.fix_suggestion.strip()
    # Deterministic stub fix for reentrancy mentions the CEI pattern / guard.
    assert "nonReentrant" in f.fix_suggestion or "balances" in f.fix_suggestion


def test_offline_provider_is_deterministic():
    p = OfflineStubProvider()
    result = audit_path(os.path.join(VULN, "TxOriginAuth.sol"))
    f = next(x for x in result.findings if x.detector == "tx-origin-auth")
    a1 = p.explain(f, "excerpt")
    a2 = p.explain(f, "excerpt")
    assert a1 == a2


def test_no_enrich_leaves_fields_empty():
    result = audit_path(os.path.join(VULN, "Reentrancy.sol"), enrich=False)
    assert all(f.explanation == "" and f.fix_suggestion == "" for f in result.findings)


def test_markdown_report_contains_sections():
    result = audit_path(os.path.join(VULN, "Reentrancy.sol"))
    md = to_markdown(result)
    assert "# Smart Contract Audit Report" in md
    assert "## Summary" in md
    assert "## Findings" in md
    assert "SWC-107" in md
    assert "```solidity" in md


def test_html_report_is_self_contained_and_has_badges():
    result = audit_path(os.path.join(VULN, "Reentrancy.sol"))
    html = to_html(result)
    assert html.startswith("<!doctype html>")
    assert "</html>" in html.strip()[-20:]
    # No external asset references.
    assert "http://" not in html.split("References")[0].lower() or "src=" not in html
    assert 'class="badge"' in html
    assert "Critical" in html


def test_html_escapes_content():
    src = 'pragma solidity 0.8.24;\ncontract C { function f() external { /* <script> */ } }'
    result = audit_source(src, path="C.sol")
    html = to_html(result)
    assert "<script>" not in html  # would only appear if unescaped


def test_empty_directory_reports_cleanly(tmp_path):
    result = audit_path(str(tmp_path))
    assert result.total == 0
    assert any("no .sol" in e for e in result.errors)
    md = to_markdown(result)
    assert "No findings" in md


def test_safe_directory_report_says_no_findings():
    result = audit_path(SAFE)
    md = to_markdown(result)
    assert "No findings" in md
    html = to_html(result)
    assert "No findings" in html


def test_json_serializable_findings():
    result = audit_path(os.path.join(VULN, "Reentrancy.sol"))
    payload = [f.to_dict() for f in result.findings]
    s = json.dumps(payload)  # must not raise
    assert "SWC-107" in s
    assert '"severity": "Critical"' in s


def test_detector_exception_is_isolated(monkeypatch):
    """A failing detector must not crash the whole audit."""
    import auditor.engine as engine

    class Boom:
        id = "boom"
        swc_id = "SWC-000"

        def run(self, src):
            raise RuntimeError("kaboom")

    real = engine.all_detectors

    def fake_all():
        return real() + [Boom()]

    monkeypatch.setattr(engine, "all_detectors", fake_all)
    result = audit_source("pragma solidity 0.8.24; contract C {}", path="C.sol")
    # The audit completes, and the error surfaces as an informational finding.
    assert any("Detector error" in f.title for f in result.findings)
