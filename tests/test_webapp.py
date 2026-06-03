"""Web UI tests. Skipped gracefully if FastAPI/httpx are not installed so the
core suite still runs in a minimal environment."""
from __future__ import annotations

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")  # required by starlette's TestClient

from fastapi.testclient import TestClient  # noqa: E402

from auditor.webapp import app  # noqa: E402

client = TestClient(app)

VULN_SRC = (
    "// SPDX-License-Identifier: MIT\n"
    "pragma solidity ^0.8.0;\n"
    "contract C {\n"
    "    function kill(address payable d) external { selfdestruct(d); }\n"
    "}\n"
)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["detectors"] >= 8


def test_index_serves_form():
    r = client.get("/")
    assert r.status_code == 200
    assert "<form" in r.text
    assert "Audit contract" in r.text


def test_api_audit_returns_findings():
    r = client.post("/api/audit", json={"source": VULN_SRC, "filename": "C.sol"})
    assert r.status_code == 200
    data = r.json()
    assert data["total"] >= 1
    dets = {f["detector"] for f in data["findings"]}
    assert "unprotected-selfdestruct" in dets


def test_api_audit_rejects_empty():
    r = client.post("/api/audit", json={"source": "   "})
    assert r.status_code == 400


def test_form_audit_returns_html_report():
    r = client.post("/audit", data={"source": VULN_SRC, "filename": "C.sol"})
    assert r.status_code == 200
    assert r.text.startswith("<!doctype html>")
    assert 'class="badge"' in r.text
