"""Each detector must fire on its vulnerable fixture and not false-positive
on the safe counterpart(s)."""
from __future__ import annotations

import os

import pytest

from auditor.engine import audit_path, audit_source
from auditor.models import Severity
from tests.conftest import SAFE, VULN, detectors_for

# (fixture file, detector id that MUST appear, expected severity)
VULN_CASES = [
    ("Reentrancy.sol", "reentrancy", Severity.CRITICAL),
    ("TxOriginAuth.sol", "tx-origin-auth", Severity.HIGH),
    ("AccessControl.sol", "missing-access-control", Severity.HIGH),
    ("UncheckedCall.sol", "unchecked-call", Severity.MEDIUM),
    ("Selfdestruct.sol", "unprotected-selfdestruct", Severity.CRITICAL),
    ("Delegatecall.sol", "delegatecall-untrusted", Severity.HIGH),
    ("Lottery.sol", "weak-randomness", Severity.MEDIUM),
    ("IntegerOverflow.sol", "integer-overflow", Severity.MEDIUM),
]


@pytest.mark.parametrize("filename,detector_id,severity", VULN_CASES)
def test_detector_fires_on_vulnerable(filename, detector_id, severity):
    result = audit_path(os.path.join(VULN, filename))
    dets = detectors_for(result)
    assert detector_id in dets, (
        f"{detector_id} did not fire on {filename}; got {sorted(dets)}"
    )
    # The matching finding carries the expected severity and an SWC id.
    matching = [f for f in result.findings if f.detector == detector_id]
    assert any(f.severity == severity for f in matching), (
        f"{detector_id} fired but not at severity {severity.label}"
    )
    assert all(f.swc_id.startswith("SWC-") for f in matching)


# Detectors that must NOT fire on the corresponding safe fixture.
SAFE_CASES = [
    ("SafeBank.sol", "reentrancy"),
    ("SafeWallet.sol", "tx-origin-auth"),
    ("SafeWallet.sol", "missing-access-control"),
    ("SafeWallet.sol", "unchecked-call"),
    ("SafeLottery.sol", "weak-randomness"),
    ("SafeToken.sol", "integer-overflow"),
]


@pytest.mark.parametrize("filename,detector_id", SAFE_CASES)
def test_detector_silent_on_safe(filename, detector_id):
    result = audit_path(os.path.join(SAFE, filename))
    dets = detectors_for(result)
    assert detector_id not in dets, (
        f"{detector_id} false-positived on safe fixture {filename}"
    )


def test_safe_fixtures_have_zero_findings():
    """The whole safe directory should be clean (no findings at all)."""
    result = audit_path(SAFE)
    assert result.total == 0, (
        "safe fixtures produced findings: "
        + ", ".join(f"{f.detector}@{f.location}" for f in result.findings)
    )


def test_floating_pragma_detector():
    src = "pragma solidity ^0.8.0;\ncontract C {}\n"
    result = audit_source(src, path="C.sol")
    assert "floating-pragma" in detectors_for(result)
    # A pinned pragma must not trigger it.
    src2 = "pragma solidity 0.8.24;\ncontract C {}\n"
    result2 = audit_source(src2, path="C.sol")
    assert "floating-pragma" not in detectors_for(result2)


def test_unprotected_selfdestruct_guarded_is_silent():
    src = """
    pragma solidity 0.8.24;
    contract C {
        address owner;
        modifier onlyOwner() { require(msg.sender == owner); _; }
        function kill() external onlyOwner { selfdestruct(payable(owner)); }
    }
    """
    result = audit_source(src, path="C.sol")
    assert "unprotected-selfdestruct" not in detectors_for(result)


def test_delegatecall_user_controlled_is_high_confidence():
    src = """
    pragma solidity 0.8.24;
    contract C {
        function f(address target, bytes calldata data) external {
            (bool ok,) = target.delegatecall(data);
            require(ok);
        }
    }
    """
    result = audit_source(src, path="C.sol")
    dc = [f for f in result.findings if f.detector == "delegatecall-untrusted"]
    assert dc and dc[0].confidence == "High"


def test_at_least_eight_detectors_registered():
    from auditor.detectors import detector_catalog

    assert len(detector_catalog()) >= 8
