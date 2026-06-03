"""Lightweight Solidity source model.

We deliberately avoid a full Solidity grammar/AST dependency so the tool runs
fully offline with zero external toolchain. Instead we build a robust
*comment- and string-stripped* view of the source that preserves line numbers,
plus simple brace-matched function extraction. This is accurate enough for
high-signal heuristic detectors while staying dependency-free.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass


def strip_comments_and_strings(source: str) -> str:
    """Return source with comments and string/hex literal *contents* removed.

    Newlines are preserved so that line numbers in the returned string match the
    original 1:1. Comment bodies and string contents are replaced with spaces so
    that token positions are also preserved. This prevents detectors from firing
    on keywords that appear inside comments or string literals.
    """
    out: list[str] = []
    i = 0
    n = len(source)
    state = "code"  # code | line_comment | block_comment | string | char
    quote = ""
    while i < n:
        c = source[i]
        nxt = source[i + 1] if i + 1 < n else ""
        if state == "code":
            if c == "/" and nxt == "/":
                state = "line_comment"
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                state = "block_comment"
                out.append("  ")
                i += 2
                continue
            if c in ('"', "'"):
                state = "string"
                quote = c
                out.append(c)  # keep the opening quote so "" still parses
                i += 1
                continue
            out.append(c)
            i += 1
            continue
        if state == "line_comment":
            if c == "\n":
                state = "code"
                out.append("\n")
            else:
                out.append(" ")
            i += 1
            continue
        if state == "block_comment":
            if c == "*" and nxt == "/":
                state = "code"
                out.append("  ")
                i += 2
            else:
                out.append("\n" if c == "\n" else " ")
                i += 1
            continue
        if state == "string":
            if c == "\\" and nxt:
                out.append("  ")
                i += 2
                continue
            if c == quote:
                state = "code"
                out.append(c)  # keep the closing quote
                i += 1
                continue
            out.append("\n" if c == "\n" else " ")
            i += 1
            continue
    return "".join(out)


# Matches a function/modifier/receive/fallback/constructor header.
_FUNC_HEADER_RE = re.compile(
    r"""(?P<kind>function|modifier|constructor|receive|fallback)\b
        \s*(?P<name>[A-Za-z_$][\w$]*)?      # name (optional for ctor/receive/fallback)
        \s*\((?P<params>[^)]*)\)            # parameter list (no nested parens expected)
        (?P<attrs>[^{;]*)                   # visibility/modifiers/returns
        (?P<term>[{;])                      # body open brace or `;` (interface/abstract)
    """,
    re.VERBOSE | re.DOTALL,
)

_VISIBILITY_RE = re.compile(r"\b(public|external|internal|private)\b")
_STATE_MUT_RE = re.compile(r"\b(view|pure|payable)\b")


@dataclass
class Function:
    kind: str                 # function | modifier | constructor | receive | fallback
    name: str
    params: str
    attrs: str                # raw attribute text between ) and {
    start: int                # char offset of header start (in clean source)
    body_start: int          # char offset just after the opening {
    body_end: int            # char offset of the matching closing } (exclusive)
    header_line: int          # 1-based line of the header
    clean_source: str        # reference to the comment-stripped source

    @property
    def visibility(self) -> str | None:
        m = _VISIBILITY_RE.search(self.attrs)
        return m.group(1) if m else None

    @property
    def modifiers(self) -> list[str]:
        """Identifiers in the attrs that are not visibility/mutability/returns.

        These are heuristically the applied function modifiers (e.g. onlyOwner).
        """
        text = _VISIBILITY_RE.sub(" ", self.attrs)
        text = _STATE_MUT_RE.sub(" ", text)
        # Drop a returns(...) clause entirely.
        text = re.sub(r"returns\s*\([^)]*\)", " ", text)
        text = re.sub(r"\boverride\b(\s*\([^)]*\))?", " ", text)
        text = re.sub(r"\bvirtual\b", " ", text)
        names = re.findall(r"[A-Za-z_$][\w$]*", text)
        return names

    @property
    def is_payable(self) -> bool:
        return bool(re.search(r"\bpayable\b", self.attrs))

    @property
    def is_view_or_pure(self) -> bool:
        return bool(re.search(r"\b(view|pure)\b", self.attrs))

    @property
    def body(self) -> str:
        return self.clean_source[self.body_start:self.body_end]

    def body_line(self, offset_in_body: int) -> int:
        """Map an offset within the body to a 1-based source line."""
        abs_off = self.body_start + offset_in_body
        return self.clean_source.count("\n", 0, abs_off) + 1


class SoliditySource:
    """A parsed-enough view of one Solidity source unit."""

    def __init__(self, source: str, path: str | None = None):
        self.raw = source
        self.path = path
        self.clean = strip_comments_and_strings(source)
        self.raw_lines = source.splitlines()
        self.functions: list[Function] = list(self._extract_functions())

    # -- line helpers -----------------------------------------------------
    def line_of(self, char_offset: int) -> int:
        return self.clean.count("\n", 0, char_offset) + 1

    def raw_line(self, line_no: int) -> str:
        if 1 <= line_no <= len(self.raw_lines):
            return self.raw_lines[line_no - 1].strip()
        return ""

    # -- function extraction ---------------------------------------------
    def _matching_brace(self, open_idx: int) -> int:
        """Given index of '{', return index just after the matching '}'."""
        depth = 0
        i = open_idx
        n = len(self.clean)
        while i < n:
            ch = self.clean[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1
        return n

    def _extract_functions(self) -> Iterator[Function]:
        for m in _FUNC_HEADER_RE.finditer(self.clean):
            term = m.group("term")
            if term == ";":
                # Interface / abstract declaration, no body to analyze.
                continue
            open_idx = m.end() - 1  # index of '{'
            body_end = self._matching_brace(open_idx)
            name = m.group("name") or m.group("kind")
            yield Function(
                kind=m.group("kind"),
                name=name,
                params=m.group("params") or "",
                attrs=m.group("attrs") or "",
                start=m.start(),
                body_start=open_idx + 1,
                body_end=body_end - 1,  # exclude closing brace
                header_line=self.line_of(m.start()),
                clean_source=self.clean,
            )

    # -- pragma helpers ---------------------------------------------------
    def pragma_versions(self) -> list[tuple[int, str]]:
        """Return list of (line_no, version_expr) for each solidity pragma."""
        results = []
        for m in re.finditer(r"pragma\s+solidity\s+([^;]+);", self.clean):
            results.append((self.line_of(m.start()), m.group(1).strip()))
        return results
