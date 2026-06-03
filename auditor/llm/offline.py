"""Deterministic, offline LLM-stub provider.

Produces finding-specific plain-English explanations and concrete code-fix
suggestions WITHOUT any network access. The text is templated per detector and
parameterized with the finding's own data, so it reads like a tailored review
note and is fully reproducible (important for tests and air-gapped use).
"""
from __future__ import annotations

import textwrap

from auditor.models import Finding

# Per-detector code-fix templates. {sig}/{line}/etc. are filled from the finding.
_FIX_TEMPLATES: dict[str, str] = {
    "reentrancy": (
        "// Checks-Effects-Interactions: update state BEFORE the external call.\n"
        "function withdraw(uint256 amount) external nonReentrant {\n"
        "    require(balances[msg.sender] >= amount, \"insufficient\");\n"
        "    balances[msg.sender] -= amount;            // effect first\n"
        "    (bool ok, ) = msg.sender.call{value: amount}(\"\");  // interaction last\n"
        "    require(ok, \"transfer failed\");\n"
        "}"
    ),
    "tx-origin-auth": (
        "// Use msg.sender, never tx.origin, for authorization.\n"
        "require(msg.sender == owner, \"not authorized\");"
    ),
    "unchecked-call": (
        "(bool ok, bytes memory data) = target.call{value: amount}(payload);\n"
        "require(ok, \"low-level call failed\");\n"
        "// ... or use OpenZeppelin: Address.functionCallWithValue(target, payload, amount);"
    ),
    "missing-access-control": (
        "// Add an access-control modifier (OpenZeppelin Ownable / AccessControl).\n"
        "function {fn}(...) external onlyOwner {\n"
        "    // sensitive logic\n"
        "}"
    ),
    "unprotected-selfdestruct": (
        "function close() external onlyOwner {\n"
        "    selfdestruct(payable(owner));\n"
        "}"
    ),
    "delegatecall-untrusted": (
        "// Only delegatecall a trusted, fixed implementation address.\n"
        "address private immutable implementation;  // set once in constructor\n"
        "(bool ok, ) = implementation.delegatecall(data);\n"
        "require(ok, \"delegatecall failed\");"
    ),
    "weak-randomness": (
        "// Request verifiable randomness (Chainlink VRF) instead of block data.\n"
        "uint256 requestId = COORDINATOR.requestRandomWords(keyHash, subId, 3, gasLimit, 1);\n"
        "// fulfillRandomWords(requestId, randomWords) returns the secure value."
    ),
    "integer-overflow": (
        "// Prefer Solidity >=0.8 (checked arithmetic) or SafeMath on older versions.\n"
        "pragma solidity 0.8.24;\n"
        "balances[msg.sender] += amount;  // reverts on overflow automatically"
    ),
    "floating-pragma": "pragma solidity 0.8.24;  // pin the exact audited compiler",
    "dangerous-unary": "total += amount;  // use the compound operator, not `= +`",
}


def _impact_sentence(finding: Finding) -> str:
    sev = finding.severity.label
    by_sev = {
        "Critical": "If exploited, this can lead to a complete loss of funds or contract takeover.",
        "High": "Exploitation can cause significant fund loss or privilege escalation.",
        "Medium": "This can lead to incorrect behavior or partial loss under the right conditions.",
        "Low": "The impact is limited but it weakens the contract's robustness.",
        "Informational": "No direct exploit, but it is a best-practice / hygiene issue.",
    }
    return by_sev.get(sev, "")


class OfflineStubProvider:
    """Deterministic provider used when no API key is configured."""

    name = "offline-stub"

    def explain(self, finding: Finding, contract_excerpt: str) -> tuple[str, str]:
        explanation = self._explanation(finding)
        fix = self._fix(finding)
        return explanation, fix

    # -- explanation ------------------------------------------------------
    def _explanation(self, finding: Finding) -> str:
        parts = [
            f"[{finding.severity.label}] {finding.title} ({finding.swc_id}) "
            f"at line {finding.line}.",
            finding.description,
            _impact_sentence(finding),
            f"Recommended fix: {finding.remediation}",
        ]
        text = " ".join(p for p in parts if p)
        # Normalize whitespace deterministically.
        return " ".join(text.split())

    # -- code fix ---------------------------------------------------------
    def _fix(self, finding: Finding) -> str:
        template = _FIX_TEMPLATES.get(finding.detector)
        if template is None:
            return finding.remediation
        # Fill a couple of optional placeholders if present.
        fn_name = ""
        # crude: pull the function name out of the description if we mentioned it
        import re

        m = re.search(r"`([A-Za-z_$][\w$]*)`", finding.description)
        if m:
            fn_name = m.group(1)
        try:
            return textwrap.dedent(template).replace("{fn}", fn_name or "sensitiveAction")
        except Exception:
            return template
