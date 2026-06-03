"""Optional Anthropic-compatible provider.

Only imported when ``ANTHROPIC_API_KEY`` is set (or explicitly requested). Falls
back to the offline stub on any error, preserving the offline core path.
"""
from __future__ import annotations

import json
import os

from auditor.llm.offline import OfflineStubProvider
from auditor.models import Finding

_SYSTEM = (
    "You are a senior smart-contract security auditor. Given a single static "
    "finding and a code excerpt, reply with STRICT JSON: keys 'explanation' "
    "(2-4 plain-English sentences) and 'fix' (a concrete Solidity remediation "
    "snippet). No markdown fences, JSON only."
)


class AnthropicProvider:
    name = "anthropic"

    def __init__(self) -> None:
        import anthropic  # type: ignore

        self._client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])
        self._model = os.environ.get("AUDIT_LLM_MODEL", "claude-3-5-haiku-latest")
        self._fallback = OfflineStubProvider()

    def explain(self, finding: Finding, contract_excerpt: str) -> tuple[str, str]:
        user = (
            f"Finding: {finding.title} ({finding.swc_id}), severity "
            f"{finding.severity.label}, line {finding.line}.\n"
            f"Static description: {finding.description}\n\n"
            f"Code excerpt:\n{contract_excerpt}\n"
            "Return JSON only."
        )
        try:
            msg = self._client.messages.create(
                model=self._model,
                max_tokens=600,
                system=_SYSTEM,
                messages=[{"role": "user", "content": user}],
            )
            text = "".join(
                block.text for block in msg.content if getattr(block, "type", "") == "text"
            )
            data = json.loads(text)
            return data.get("explanation", finding.description), data.get(
                "fix", finding.remediation
            )
        except Exception:
            return self._fallback.explain(finding, contract_excerpt)
