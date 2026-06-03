"""Shared test fixtures and helpers."""
from __future__ import annotations

import os
import sys

import pytest

# Ensure the package is importable when running `pytest` from the repo root
# without installing the package.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from auditor.engine import audit_path  # noqa: E402

SAMPLES = os.path.join(ROOT, "samples")
VULN = os.path.join(SAMPLES, "vulnerable")
SAFE = os.path.join(SAMPLES, "safe")


def detectors_for(result) -> set[str]:
    return {f.detector for f in result.findings}


@pytest.fixture
def audit():
    """Audit a single fixture file by name relative to a base dir."""

    def _audit(base: str, name: str):
        return audit_path(os.path.join(base, name))

    return _audit


@pytest.fixture
def vuln_dir() -> str:
    return VULN


@pytest.fixture
def safe_dir() -> str:
    return SAFE
