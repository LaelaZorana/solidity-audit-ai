"""Built-in static detectors.

Each detector operates on a comment/string-stripped :class:`SoliditySource`
view so that keywords inside comments or string literals never trigger a
finding. Detectors are intentionally high-signal heuristics: they aim to fire
reliably on the vulnerable patterns while avoiding the obvious safe forms.
"""
from __future__ import annotations

import re
from collections.abc import Iterable

from auditor.detectors.base import Detector, register
from auditor.models import Finding, Severity
from auditor.source import Function, SoliditySource

# Patterns describing an external value-bearing / low-level call.
_EXTERNAL_CALL_RE = re.compile(
    r"""(?P<recv>[A-Za-z_$][\w$.\[\]()]*?)\s*\.\s*
        (?:
            (?:call|delegatecall|staticcall)\s*(?:\{[^}]*\})?\s*\(   # low-level
          | (?:transfer|send)\s*\(                                   # value xfer
          | call\.value\s*\(                                         # legacy .call.value
        )
    """,
    re.VERBOSE,
)

# A state-mutating assignment heuristic: `something = ...`, `+=`, mappings, etc.
_STATE_WRITE_RE = re.compile(
    r"""(?<![=!<>])           # not part of ==, !=, <=, >=
        (?P<lhs>[A-Za-z_$][\w$]*(?:\s*\[[^\]]*\]|\s*\.\s*[A-Za-z_$][\w$]*)*)
        \s*(?:=(?!=)|\+=|-=|\*=|/=)   # assignment op (single = but not ==)
    """,
    re.VERBOSE,
)

# Names that strongly imply an access-control gate.
_ACCESS_MODIFIER_HINTS = re.compile(
    r"only|auth|admin|owner|restricted|governance|guard|role|whenNotPaused|nonReentrant",
    re.IGNORECASE,
)

# Sensitive operations inside a function body that demand access control.
_SENSITIVE_BODY_RE = re.compile(
    r"""\bselfdestruct\s*\(
      | \bsuicide\s*\(
      | \.\s*delegatecall\s*(?:\{[^}]*\})?\s*\(
      | \b(owner|admin|_owner|governance)\s*=(?!=)
      | \.\s*transfer\s*\(
      | \.\s*send\s*\(
      | \.\s*call\s*(?:\{[^}]*\})?\s*\(
      | \bmint\s*\(
      | \b_mint\s*\(
    """,
    re.VERBOSE,
)


def _line_in_body(fn: Function, match_start: int) -> int:
    return fn.body_line(match_start)


@register
class ReentrancyDetector(Detector):
    id = "reentrancy"
    title = "Reentrancy: state change after external call"
    swc_id = "SWC-107"
    severity = Severity.CRITICAL
    references = [
        "https://swcregistry.io/docs/SWC-107",
        "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
    ]

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for fn in src.functions:
            if fn.kind not in ("function", "fallback", "receive"):
                continue
            body = fn.body
            # Skip clearly reentrancy-guarded functions.
            guarded = any(
                re.search(r"nonReentrant|noReentrancy|lock\b", m, re.IGNORECASE)
                for m in fn.modifiers
            )
            for call in _EXTERNAL_CALL_RE.finditer(body):
                # Ignore staticcall (cannot change state) and `this.`/library-ish.
                snippet = call.group(0)
                recv = call.group("recv")
                if "staticcall" in snippet:
                    continue
                if recv in ("abi", "address", "type", "this"):
                    continue
                after = body[call.end():]
                write = _STATE_WRITE_RE.search(after)
                if not write:
                    continue
                # Filter out obvious local/temporary assignments to declared vars
                lhs = write.group("lhs").strip()
                if lhs in ("bool", "uint", "uint256", "success", "ok", "data", "returndata"):
                    continue
                # Require the write to look like persistent state: a mapping index,
                # a member access, or a bare identifier that is not freshly declared.
                decl_re = re.compile(
                    r"\b(?:uint\d*|int\d*|bool|address|bytes\d*|string)\s+" + re.escape(lhs.split("[")[0]) + r"\b"
                )
                if decl_re.search(body[:call.end()]):
                    continue
                line = _line_in_body(fn, call.start())
                conf = "Medium" if guarded else "High"
                desc = (
                    f"In `{fn.name}` an external call (`{snippet.strip()}...`) is "
                    f"followed by a state update (`{lhs} = ...`). An attacker "
                    f"contract can re-enter `{fn.name}` during the external call "
                    f"before state is updated, draining funds (classic DAO bug). "
                    f"This violates checks-effects-interactions."
                )
                if guarded:
                    desc += (
                        " A reentrancy guard appears present; verify it actually "
                        "protects this path."
                    )
                yield Finding(
                    detector=self.id,
                    title=self.title,
                    severity=self.severity,
                    swc_id=self.swc_id,
                    line=line,
                    code=src.raw_line(line),
                    description=desc,
                    remediation=(
                        "Apply the checks-effects-interactions pattern: update all "
                        "state (e.g. zero the balance) BEFORE making the external "
                        "call, and/or add a `nonReentrant` guard (OpenZeppelin "
                        "ReentrancyGuard). Prefer pull-payments over push."
                    ),
                    confidence=conf,
                    references=self.references,
                )
                break  # one finding per function is enough


@register
class TxOriginAuthDetector(Detector):
    id = "tx-origin-auth"
    title = "Authentication via tx.origin"
    swc_id = "SWC-115"
    severity = Severity.HIGH
    references = ["https://swcregistry.io/docs/SWC-115"]

    _RE = re.compile(r"require\s*\(\s*tx\s*\.\s*origin\s*==|tx\s*\.\s*origin\s*==|==\s*tx\s*\.\s*origin")

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for m in self._RE.finditer(src.clean):
            line = src.line_of(m.start())
            yield Finding(
                detector=self.id,
                title=self.title,
                severity=self.severity,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    "`tx.origin` is used for authorization. `tx.origin` is the "
                    "original external account of the whole transaction, so a "
                    "malicious contract the victim calls can forward the call and "
                    "impersonate the victim. Authorization checks must use "
                    "`msg.sender`."
                ),
                remediation="Replace `tx.origin` with `msg.sender` in the authorization check.",
                confidence="High",
                references=self.references,
            )


@register
class UncheckedCallDetector(Detector):
    id = "unchecked-call"
    title = "Unchecked low-level call return value"
    swc_id = "SWC-104"
    severity = Severity.MEDIUM
    references = ["https://swcregistry.io/docs/SWC-104"]

    # A low-level call/send used as a bare statement (return value discarded).
    _CALL_RE = re.compile(
        r"(?P<recv>[A-Za-z_$][\w$.\[\]()]*?)\s*\.\s*"
        r"(?P<method>call|delegatecall|send)\s*(?:\{[^}]*\})?\s*\([^;]*\)\s*;"
    )

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        clean = src.clean
        for m in self._CALL_RE.finditer(clean):
            method = m.group("method")
            # Find the start of the statement (after previous ; { or }).
            stmt_start = max(
                clean.rfind(";", 0, m.start()),
                clean.rfind("{", 0, m.start()),
                clean.rfind("}", 0, m.start()),
            ) + 1
            stmt = clean[stmt_start:m.end()]
            # If the result is assigned / required / used in a condition, it's checked.
            if re.search(r"(=(?!=)|require\s*\(|assert\s*\(|if\s*\(|return\b|\bbool\b)", stmt):
                continue
            line = src.line_of(m.start())
            yield Finding(
                detector=self.id,
                title=self.title,
                severity=self.severity,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    f"The return value of a low-level `.{method}(...)` is ignored. "
                    "Low-level calls do not revert on failure; they return `false`. "
                    "Ignoring it means a failed transfer/call is silently treated as "
                    "success, which can corrupt accounting."
                ),
                remediation=(
                    "Capture and check the boolean result, e.g. "
                    "`(bool ok, ) = addr.call{value: v}(\"\"); require(ok, \"call failed\");` "
                    "or use OpenZeppelin's `Address.sendValue` / `functionCall`."
                ),
                confidence="High",
                references=self.references,
            )


@register
class MissingAccessControlDetector(Detector):
    id = "missing-access-control"
    title = "Missing access control on sensitive function"
    swc_id = "SWC-105"
    severity = Severity.HIGH
    references = [
        "https://swcregistry.io/docs/SWC-105",
        "https://swcregistry.io/docs/SWC-106",
    ]

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for fn in src.functions:
            if fn.kind not in ("function", "fallback"):
                continue
            if fn.is_view_or_pure:
                continue
            vis = fn.visibility
            # Only externally reachable functions matter.
            if vis in ("internal", "private"):
                continue
            body = fn.body
            sensitive = _SENSITIVE_BODY_RE.search(body)
            if not sensitive:
                continue
            # Is there any access-control gate? Check modifiers + an in-body
            # require(msg.sender == ...) / onlyOwner-style guard.
            has_modifier_guard = any(_ACCESS_MODIFIER_HINTS.search(m) for m in fn.modifiers)
            has_inbody_guard = bool(
                re.search(
                    r"require\s*\(\s*msg\s*\.\s*sender\s*==|"
                    r"if\s*\(\s*msg\s*\.\s*sender\s*!=|"
                    r"_checkOwner\s*\(|_checkRole\s*\(",
                    body,
                )
            )
            if has_modifier_guard or has_inbody_guard:
                continue
            # Self-service pattern: the only sensitive op is a value transfer that
            # operates on the CALLER's own funds (recipient or balance keyed by
            # msg.sender). That is implicitly authorized per-caller, not an
            # access-control bug (e.g. a withdraw()). Privileged ops on arbitrary
            # addresses / state (selfdestruct, owner=, delegatecall, mint) are not
            # exempt.
            op_text = sensitive.group(0)
            is_value_transfer = bool(re.search(r"\.\s*(transfer|send|call)\b", op_text))
            keyed_by_sender = re.search(r"\[\s*msg\s*\.\s*sender\s*\]", body)
            pays_sender = re.search(r"msg\s*\.\s*sender\s*\.\s*(transfer|send|call)", body)
            if is_value_transfer and (keyed_by_sender or pays_sender):
                continue
            line = fn.header_line
            op = sensitive.group(0).strip().rstrip("(").strip()
            yield Finding(
                detector=self.id,
                title=self.title,
                severity=self.severity,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    f"`{fn.name}` is `{vis or 'public'}` and performs a sensitive "
                    f"operation (`{op}`) but has no access-control guard "
                    "(no `onlyOwner`/role modifier and no `require(msg.sender == ...)`). "
                    "Any account can call it."
                ),
                remediation=(
                    "Gate the function with an access-control modifier "
                    "(e.g. OpenZeppelin `onlyOwner` or `onlyRole(...)`) or an explicit "
                    "`require(msg.sender == owner, \"not authorized\");` check."
                ),
                confidence="Medium",
                references=self.references,
            )


@register
class UnprotectedSelfdestructDetector(Detector):
    id = "unprotected-selfdestruct"
    title = "Unprotected selfdestruct"
    swc_id = "SWC-106"
    severity = Severity.CRITICAL
    references = ["https://swcregistry.io/docs/SWC-106"]

    _RE = re.compile(r"\b(selfdestruct|suicide)\s*\(")

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for fn in src.functions:
            m = self._RE.search(fn.body)
            if not m:
                continue
            has_guard = any(_ACCESS_MODIFIER_HINTS.search(mod) for mod in fn.modifiers) or bool(
                re.search(r"require\s*\(\s*msg\s*\.\s*sender\s*==|_checkOwner\s*\(|_checkRole\s*\(", fn.body)
            )
            if has_guard:
                continue
            line = fn.body_line(m.start())
            yield Finding(
                detector=self.id,
                title=self.title,
                severity=self.severity,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    f"`{fn.name}` calls `selfdestruct` without an access-control "
                    "guard. Anyone can destroy the contract and sweep its balance "
                    "to an arbitrary address (cf. the Parity multisig freeze)."
                ),
                remediation=(
                    "Restrict `selfdestruct` to a trusted role (`onlyOwner`) or "
                    "remove it. Note `selfdestruct` is deprecated (EIP-6049); prefer "
                    "an upgradeable pause/withdraw pattern."
                ),
                confidence="High",
                references=self.references,
            )


@register
class DelegatecallDetector(Detector):
    id = "delegatecall-untrusted"
    title = "delegatecall to untrusted / user-controlled target"
    swc_id = "SWC-112"
    severity = Severity.HIGH
    references = ["https://swcregistry.io/docs/SWC-112"]

    _RE = re.compile(r"(?P<target>[A-Za-z_$][\w$.\[\]]*)\s*\.\s*delegatecall\s*(?:\{[^}]*\})?\s*\(")

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for fn in src.functions:
            for m in self._RE.finditer(fn.body):
                target = m.group("target")
                # Is the target derived from a parameter / arbitrary input?
                param_names = re.findall(r"[A-Za-z_$][\w$]*", fn.params)
                target_root = target.split(".")[0].split("[")[0]
                user_controlled = (
                    target_root in param_names
                    or "msg.data" in fn.body[m.start():m.start() + 60]
                )
                line = fn.body_line(m.start())
                conf = "High" if user_controlled else "Low"
                desc = (
                    f"`{fn.name}` uses `delegatecall` on `{target}`. `delegatecall` "
                    "executes external code in THIS contract's storage context; if "
                    "the target is untrusted it can overwrite any state variable "
                    "(including the owner) or selfdestruct the proxy."
                )
                if user_controlled:
                    desc += (
                        " The target appears to come from a function argument, so it "
                        "is attacker-controllable — this is high risk."
                    )
                yield Finding(
                    detector=self.id,
                    title=self.title,
                    severity=self.severity,
                    swc_id=self.swc_id,
                    line=line,
                    code=src.raw_line(line),
                    description=desc,
                    remediation=(
                        "Only `delegatecall` into trusted, immutable, audited "
                        "implementation addresses (e.g. a fixed library or a "
                        "governance-controlled proxy implementation). Never "
                        "`delegatecall` an address taken from untrusted input."
                    ),
                    confidence=conf,
                    references=self.references,
                )


@register
class WeakRandomnessDetector(Detector):
    id = "weak-randomness"
    title = "Weak randomness from block properties"
    swc_id = "SWC-120"
    severity = Severity.MEDIUM
    references = ["https://swcregistry.io/docs/SWC-120"]

    # block.timestamp / now / blockhash / block.difficulty / block.prevrandao
    _SOURCE_RE = re.compile(
        r"\bblock\s*\.\s*(timestamp|difficulty|prevrandao|number|coinbase|gaslimit)\b"
        r"|\bnow\b"
        r"|\bblockhash\s*\("
    )
    # Contexts that indicate the value feeds randomness/selection logic.
    _CONTEXT_RE = re.compile(
        r"keccak256|sha3|sha256|%|random|rand\b|winner|lottery|seed|roll|dice|draw",
        re.IGNORECASE,
    )

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for fn in src.functions:
            body = fn.body
            for m in self._SOURCE_RE.finditer(body):
                # Look at the enclosing statement (between the surrounding `;`)
                # for a randomness/selection context.
                stmt_start = body.rfind(";", 0, m.start()) + 1
                stmt_end = body.find(";", m.end())
                if stmt_end == -1:
                    stmt_end = len(body)
                ctx = body[stmt_start:stmt_end]
                if not self._CONTEXT_RE.search(ctx):
                    continue
                line = fn.body_line(m.start())
                yield Finding(
                    detector=self.id,
                    title=self.title,
                    severity=self.severity,
                    swc_id=self.swc_id,
                    line=line,
                    code=src.raw_line(line),
                    description=(
                        f"`{fn.name}` derives randomness from a miner/validator-"
                        f"influenced block property (`{m.group(0).strip()}`). Block "
                        "producers can manipulate or withhold blocks to bias the "
                        "outcome, so this is not secure randomness."
                    ),
                    remediation=(
                        "Use a verifiable randomness source such as Chainlink VRF, "
                        "or a commit-reveal scheme. Never use `block.timestamp`, "
                        "`blockhash`, or `block.prevrandao` alone for prizes/selection."
                    ),
                    confidence="Medium",
                    references=self.references,
                )
                break  # one per function


@register
class IntegerOverflowDetector(Detector):
    id = "integer-overflow"
    title = "Integer over/underflow risk (pre-0.8 or unchecked)"
    swc_id = "SWC-101"
    severity = Severity.MEDIUM
    references = ["https://swcregistry.io/docs/SWC-101"]

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        versions = src.pragma_versions()
        pre_080 = False
        for _, expr in versions:
            # crude: any explicit 0.4/0.5/0.6/0.7 or a ^0.x below 0.8
            if re.search(r"0\.[4-7]\b", expr):
                pre_080 = True
        # 1) Whole-contract risk when compiled pre-0.8 and SafeMath absent.
        uses_safemath = bool(re.search(r"\busing\s+SafeMath\b|SafeMath\s*\.", src.clean))
        if pre_080 and not uses_safemath:
            # Find first arithmetic-bearing function to anchor a finding.
            for fn in src.functions:
                if fn.is_view_or_pure:
                    continue
                am = re.search(r"[+\-*]=|\+\+|--|\bsub\b|\badd\b|\bmul\b", fn.body)
                if am:
                    line = fn.body_line(am.start())
                    yield Finding(
                        detector=self.id,
                        title=self.title,
                        severity=self.severity,
                        swc_id=self.swc_id,
                        line=line,
                        code=src.raw_line(line),
                        description=(
                            "Contract targets a Solidity version < 0.8 (no built-in "
                            "overflow checks) and does not use SafeMath. Arithmetic "
                            "such as balance updates can silently wrap around, "
                            "enabling balance/underflow exploits."
                        ),
                        remediation=(
                            "Upgrade the pragma to ^0.8.0 (checked arithmetic by "
                            "default) or use OpenZeppelin SafeMath for all arithmetic "
                            "on untrusted values."
                        ),
                        confidence="Medium",
                        references=self.references,
                    )
                    break
        # 2) Explicit `unchecked { }` blocks (any version) — flag for review.
        for m in re.finditer(r"\bunchecked\s*\{", src.clean):
            line = src.line_of(m.start())
            yield Finding(
                detector=self.id,
                title="Arithmetic inside unchecked block",
                severity=Severity.LOW,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    "An `unchecked { ... }` block disables overflow/underflow "
                    "protection. If any operand is influenced by untrusted input, "
                    "this can wrap around silently."
                ),
                remediation=(
                    "Confirm every operation in the `unchecked` block cannot "
                    "overflow/underflow for all reachable inputs; otherwise move it "
                    "out of the unchecked block."
                ),
                confidence="Low",
                references=self.references,
            )


@register
class FloatingPragmaDetector(Detector):
    id = "floating-pragma"
    title = "Floating / unlocked compiler pragma"
    swc_id = "SWC-103"
    severity = Severity.INFORMATIONAL
    references = ["https://swcregistry.io/docs/SWC-103"]

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for line, expr in src.pragma_versions():
            if expr.startswith("^") or expr.startswith("~") or ">" in expr or "<" in expr or "*" in expr:
                yield Finding(
                    detector=self.id,
                    title=self.title,
                    severity=self.severity,
                    swc_id=self.swc_id,
                    line=line,
                    code=src.raw_line(line),
                    description=(
                        f"The pragma `solidity {expr}` is floating, so the contract "
                        "may be compiled with a different (e.g. newer, buggier, or "
                        "older) compiler than it was tested/audited with."
                    ),
                    remediation=(
                        "Lock the compiler to an exact, audited version, e.g. "
                        "`pragma solidity 0.8.24;`."
                    ),
                    confidence="High",
                    references=self.references,
                )


@register
class DangerousUnaryDetector(Detector):
    """Catches the classic `x =+ y` typo (parsed as `x = (+y)`)."""

    id = "dangerous-unary"
    title = "Suspicious unary expression (possible `=+` typo)"
    swc_id = "SWC-129"
    severity = Severity.LOW
    references = ["https://swcregistry.io/docs/SWC-129"]

    _RE = re.compile(r"[A-Za-z_$][\w$\]]*\s*=\s*[+\-]\s*[A-Za-z0-9_$]")

    def run(self, src: SoliditySource) -> Iterable[Finding]:
        for m in self._RE.finditer(src.clean):
            text = m.group(0)
            # Exclude legitimate `= -1`, `= +something` only when it looks like a
            # compound-assignment typo (no space-insensitive `==`).
            if "==" in text:
                continue
            line = src.line_of(m.start())
            yield Finding(
                detector=self.id,
                title=self.title,
                severity=self.severity,
                swc_id=self.swc_id,
                line=line,
                code=src.raw_line(line),
                description=(
                    "An assignment of the form `x = +y` / `x = -y` was found. This is "
                    "often a typo for the compound operator `x += y` / `x -= y`; as "
                    "written it overwrites `x` instead of accumulating."
                ),
                remediation="Verify intent; if accumulation was meant use `+=` / `-=`.",
                confidence="Low",
                references=self.references,
            )
