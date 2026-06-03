"""solidity-audit-ai: an offline-first static + LLM-assisted Solidity security auditor."""

from auditor.engine import audit_path, audit_source
from auditor.models import Finding, Severity

__all__ = ["Finding", "Severity", "audit_source", "audit_path"]
__version__ = "1.0.0"
