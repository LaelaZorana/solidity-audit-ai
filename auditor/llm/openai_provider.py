"""Optional OpenAI-compatible provider.

Only imported when ``OPENAI_API_KEY`` is set (or the provider is explicitly
requested). If the ``openai`` package is missing or the call fails, the caller
(:func:`auditor.llm.base.get_provider`) falls back to the offline stub, so this
module can never break the offline core path.
"""
from __future__ import annotations

import json
import os

from auditor.llm.offline import OfflineStubProvider
from auditor.models import Finding

_SYSTEM = (
    "You are a senior smart-contract security auditor. Given a single static "
    "finding and a code excerpt, return STRICT JSON with keys 'explanation' "
    "(2-4 sentences, plain English, no fluff) and 'fix' (a concrete Solidity "
    "code snippet that remediates the issue). Do not include markdown fences."
)


class OpenAIProvider:
    name = "openai"

    def __init__(self) -> None:
        # Imported lazily so the dependency is truly optional.
        from openai import OpenAI  # type: ignore

        self._client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        self._model = os.environ.get("AUDIT_LLM_MODEL", "gpt-4o-mini")
        self._fallback = OfflineStubProvider()

    def explain(self, finding: Finding, contract_excerpt: str) -> tuple[str, str]:
        user = (
            f"Finding: {finding.title} ({finding.swc_id}), severity "
            f"{finding.severity.label}, line {finding.line}.\n"
            f"Static description: {finding.description}\n\n"
            f"Code excerpt:\n{contract_excerpt}\n"
        )
        try:
            resp = self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": _SYSTEM},
                    {"role": "user", "content": user},
                ],
                temperature=0,
                response_format={"type": "json_object"},
            )
            data = json.loads(resp.choices[0].message.content)
            return data.get("explanation", finding.description), data.get(
                "fix", finding.remediation
            )
        except Exception:
            return self._fallback.explain(finding, contract_excerpt)
