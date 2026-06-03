"""Optional FastAPI web UI: paste a contract, get a security audit.

Run locally:
    uvicorn auditor.webapp:app --reload --port 8000
    # then open http://localhost:8000

Endpoints:
    GET  /            -> polished paste-a-contract workbench (Tailwind UI)
    POST /audit       -> form submit (no-JS fallback), returns the HTML report
    POST /api/audit   -> JSON in ({"source": "...", "filename": "X.sol"}), JSON out
    GET  /health      -> {"status": "ok", ...}

The web layer reuses the exact same engine + report code as the CLI, so the
output is identical. It runs fully offline: the LLM layer defaults to the
deterministic stub and Tailwind is vendored locally (no network required).
"""
from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from auditor import __version__
from auditor.detectors import detector_catalog
from auditor.engine import audit_source
from auditor.models import Severity
from auditor.report import to_html

_HERE = Path(__file__).resolve().parent
_SAMPLES_DIR = _HERE.parent / "samples"

app = FastAPI(title="solidity-audit-ai", version=__version__)
app.mount("/static", StaticFiles(directory=str(_HERE / "static")), name="static")
templates = Jinja2Templates(directory=str(_HERE / "templates"))


# --------------------------------------------------------------------------- #
# Context helpers
# --------------------------------------------------------------------------- #
def _detector_count() -> int:
    return len(detector_catalog())


def _detectors_context() -> list[dict]:
    """Catalog for the 'Detector coverage' grid (sorted Critical -> Informational)."""
    cat = detector_catalog()
    rows = []
    for cls in cat:
        sev = cls.severity or Severity.INFORMATIONAL
        rows.append(
            {
                "id": cls.id,
                "title": cls.title,
                "swc_id": cls.swc_id,
                "sev_label": sev.label,
                "sev_key": sev.label.lower(),
                "sev_rank": int(sev),
            }
        )
    rows.sort(key=lambda r: (-r["sev_rank"], r["id"]))
    return rows


# A built-in fallback contract (used if the sample files are unavailable).
_FALLBACK_SAMPLE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok);
        balances[msg.sender] -= amount; // reentrancy: state change after call
    }
}
"""

# One-click samples surfaced as buttons. Sourced from the real fixtures so the
# UI stays in sync with the test suite. (key, file, label, headline severity).
_SAMPLE_SPECS = [
    ("reentrancy", "vulnerable/Reentrancy.sol", "Reentrant bank", Severity.CRITICAL),
    ("selfdestruct", "vulnerable/Selfdestruct.sol", "Open selfdestruct", Severity.CRITICAL),
    ("access", "vulnerable/AccessControl.sol", "No access control", Severity.HIGH),
    ("lottery", "vulnerable/Lottery.sol", "Weak randomness", Severity.MEDIUM),
    ("safe", "safe/SafeBank.sol", "Hardened (clean)", Severity.INFORMATIONAL),
]


def _read_sample(rel: str) -> str | None:
    try:
        return (_SAMPLES_DIR / rel).read_text(encoding="utf-8")
    except OSError:
        return None


def _load_samples() -> tuple[list[dict], dict[str, dict]]:
    """Return (button_metadata, {key: {filename, source}}) for the template."""
    buttons: list[dict] = []
    data: dict[str, dict] = {}
    for key, rel, label, sev in _SAMPLE_SPECS:
        source = _read_sample(rel)
        if source is None:
            continue
        filename = rel.split("/")[-1]
        buttons.append(
            {
                "key": key,
                "label": label,
                "sev_label": sev.label,
                "sev_key": sev.label.lower(),
            }
        )
        data[key] = {"filename": filename, "source": source}
    return buttons, data


def _default_source(samples: dict[str, dict]) -> str:
    """Pre-fill the textarea with the reentrancy sample (instant 'aha')."""
    if "reentrancy" in samples:
        return samples["reentrancy"]["source"]
    return _FALLBACK_SAMPLE


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    buttons, data = _load_samples()
    sample = _default_source(data)
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "version": __version__,
            "detector_count": _detector_count(),
            "detectors": _detectors_context(),
            "samples": buttons,
            "samples_json": json.dumps(data),
            "sample": sample,
        },
    )


@app.post("/audit", response_class=HTMLResponse)
def audit_form(source: str = Form(...), filename: str = Form("Contract.sol")) -> str:
    """No-JS fallback: returns the self-contained HTML report for a form POST."""
    result = audit_source(source, path=filename)
    return to_html(result, title=f"Audit · {filename}")


@app.post("/api/audit")
async def audit_api(request: Request) -> JSONResponse:
    body = await request.json()
    source = body.get("source", "")
    filename = body.get("filename", "Contract.sol")
    if not source.strip():
        return JSONResponse({"error": "missing 'source'"}, status_code=400)
    result = audit_source(source, path=filename)
    return JSONResponse(
        {
            "summary": result.counts_by_severity(),
            "total": result.total,
            "provider": result.provider,
            "headline": result.summary_line(),
            "findings": [f.to_dict() for f in result.sorted_findings()],
        }
    )


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__, "detectors": _detector_count()}
