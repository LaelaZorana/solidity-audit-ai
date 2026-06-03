"""LLM provider interface and selection logic.

The auditor enriches each static finding with (1) a plain-English explanation and
(2) a concrete remediation/code-fix suggestion. That enrichment goes through this
provider interface.

Design goal (house style): the tool runs FULLY OFFLINE by default. When no API
key is configured we use a deterministic :class:`OfflineStubProvider` that
produces sensible, finding-specific text with zero network calls. A real provider
(e.g. OpenAI/Anthropic-compatible) can be plugged in by setting the appropriate
environment variable; it is strictly optional and never used by the test suite.
"""
from __future__ import annotations

import os
from typing import Protocol

from auditor.models import Finding


class LLMProvider(Protocol):
    """Protocol every provider implements."""

    name: str

    def explain(self, finding: Finding, contract_excerpt: str) -> tuple[str, str]:
        """Return (explanation, fix_suggestion) for a finding.

        ``contract_excerpt`` is a few lines of source around the finding to give
        the model local context. Implementations must be side-effect free with
        respect to ``finding``.
        """
        ...


def get_provider(name: str | None = None) -> LLMProvider:
    """Select a provider.

    Resolution order:
      1. explicit ``name`` argument ("offline" | "openai" | "anthropic")
      2. ``AUDIT_LLM_PROVIDER`` env var
      3. auto: use a real provider only if its API key is present, else offline
    """
    from auditor.llm.offline import OfflineStubProvider

    choice = (name or os.environ.get("AUDIT_LLM_PROVIDER") or "auto").lower()

    if choice in ("offline", "stub", "none"):
        return OfflineStubProvider()

    if choice == "auto":
        if os.environ.get("OPENAI_API_KEY"):
            choice = "openai"
        elif os.environ.get("ANTHROPIC_API_KEY"):
            choice = "anthropic"
        else:
            return OfflineStubProvider()

    try:
        if choice == "openai":
            from auditor.llm.openai_provider import OpenAIProvider

            return OpenAIProvider()
        if choice == "anthropic":
            from auditor.llm.anthropic_provider import AnthropicProvider

            return AnthropicProvider()
    except Exception:
        # Any import/config error → fall back to the deterministic stub so the
        # core path never breaks. (House rule: must run offline.)
        return OfflineStubProvider()

    return OfflineStubProvider()
