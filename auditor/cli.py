"""Command-line interface for solidity-audit-ai.

Examples
--------
    python -m auditor.cli samples/vulnerable/Reentrancy.sol
    python -m auditor.cli samples/ --html report.html --md report.md
    python -m auditor.cli contracts/ --format json
"""
from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from pathlib import Path

from auditor.engine import audit_path
from auditor.llm import get_provider
from auditor.report import to_html, to_markdown

# ANSI colors for the terminal summary.
_COLOR = {
    "Critical": "\033[97;41m",
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[96m",
    "Informational": "\033[90m",
}
_RESET = "\033[0m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _print_terminal(result) -> None:
    color = _supports_color()
    print()
    print("=" * 60)
    print(" solidity-audit-ai: audit summary")
    print("=" * 60)
    counts = result.counts_by_severity()
    for sev_label, n in counts.items():
        c = _COLOR.get(sev_label, "") if color else ""
        r = _RESET if color else ""
        bar = "█" * min(n, 40)
        print(f"  {c}{sev_label:>14}{r} | {n:>3} {bar}")
    print("-" * 60)
    print(f"  {'TOTAL':>14} | {result.total:>3}")
    print(f"  files scanned: {len(result.files)}")
    print("=" * 60)

    for i, f in enumerate(result.sorted_findings(), 1):
        c = _COLOR.get(f.severity.label, "") if color else ""
        r = _RESET if color else ""
        print(
            f"\n[{i}] {c}{f.severity.label}{r} {f.title} "
            f"({f.swc_id}), {f.location}"
        )
        if f.code:
            print(f"      {f.code}")
        print(f"      → {f.remediation}")
    if result.errors:
        print("\nWarnings:")
        for e in result.errors:
            print(f"  - {e}")
    print()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="solidity-audit-ai",
        description="AI-assisted static security auditor for Solidity smart contracts.",
    )
    p.add_argument("path", help="Path to a .sol file or a directory of contracts.")
    p.add_argument("--md", metavar="FILE", help="Write a Markdown report to FILE.")
    p.add_argument("--html", metavar="FILE", help="Write a self-contained HTML report to FILE.")
    p.add_argument(
        "--format",
        choices=["terminal", "md", "json"],
        default="terminal",
        help="What to print to stdout (default: terminal).",
    )
    p.add_argument(
        "--provider",
        default=None,
        help="LLM provider: offline | openai | anthropic (default: auto/offline).",
    )
    p.add_argument(
        "--no-enrich",
        action="store_true",
        help="Skip LLM-assisted explanations/fixes (static findings only).",
    )
    p.add_argument(
        "--slither",
        action="store_true",
        help="Also run Slither if installed (degrades to no-op otherwise).",
    )
    p.add_argument("--open", action="store_true", help="Open the HTML report in a browser.")
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "informational", "none"],
        default="none",
        help="Exit non-zero if a finding of this severity or higher exists (for CI).",
    )
    p.add_argument("--title", default="Smart Contract Audit Report", help="Report title.")
    return p


_SEV_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "informational": 1, "none": 0}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    provider = get_provider(args.provider)
    result = audit_path(
        args.path,
        provider=provider,
        enrich=not args.no_enrich,
        use_slither=args.slither,
    )

    # Output files. Status messages go to stderr so stdout stays clean for
    # machine consumption (e.g. `--format json > out.json`).
    if args.md:
        Path(args.md).write_text(to_markdown(result, args.title), encoding="utf-8")
        print(f"Wrote Markdown report: {args.md}", file=sys.stderr)
    if args.html:
        Path(args.html).write_text(to_html(result, args.title), encoding="utf-8")
        print(f"Wrote HTML report: {args.html}", file=sys.stderr)
        if args.open:
            webbrowser.open(Path(args.html).resolve().as_uri())

    # Stdout.
    if args.format == "terminal":
        _print_terminal(result)
    elif args.format == "md":
        print(to_markdown(result, args.title))
    elif args.format == "json":
        print(
            json.dumps(
                {
                    "summary": result.counts_by_severity(),
                    "total": result.total,
                    "files": result.files,
                    "provider": result.provider,
                    "errors": result.errors,
                    "findings": [f.to_dict() for f in result.sorted_findings()],
                },
                indent=2,
            )
        )

    # CI gate.
    threshold = _SEV_ORDER[args.fail_on]
    if threshold:
        worst = max((int(f.severity) for f in result.findings), default=0)
        if worst >= threshold:
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
