"""Smoke tests for the command-line interface."""
from __future__ import annotations

import json
import os

from auditor.cli import main
from tests.conftest import SAFE, VULN


def test_cli_terminal_runs(capsys):
    rc = main([os.path.join(VULN, "Reentrancy.sol"), "--no-enrich"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "audit summary" in out
    assert "Critical" in out


def test_cli_json_output(capsys):
    rc = main([os.path.join(VULN, "Reentrancy.sol"), "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 0
    data = json.loads(out)
    assert data["total"] >= 1
    assert any(f["swc_id"] == "SWC-107" for f in data["findings"])


def test_cli_writes_html_and_md(tmp_path, capsys):
    html = tmp_path / "report.html"
    md = tmp_path / "report.md"
    rc = main(
        [
            VULN,
            "--html",
            str(html),
            "--md",
            str(md),
            "--format",
            "json",
        ]
    )
    assert rc == 0
    assert html.exists() and html.read_text().startswith("<!doctype html>")
    assert md.exists() and "## Findings" in md.read_text()


def test_cli_fail_on_high_gate(capsys):
    # Vulnerable dir has Critical/High findings -> should exit non-zero.
    rc = main([VULN, "--no-enrich", "--fail-on", "high", "--format", "json"])
    capsys.readouterr()
    assert rc == 1


def test_cli_fail_on_gate_passes_for_clean(capsys):
    rc = main([SAFE, "--no-enrich", "--fail-on", "critical", "--format", "json"])
    capsys.readouterr()
    assert rc == 0
