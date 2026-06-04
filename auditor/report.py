"""Markdown and self-contained HTML report generation."""
from __future__ import annotations

import datetime as _dt
import html
from typing import TYPE_CHECKING

from auditor.models import Severity

if TYPE_CHECKING:
    from auditor.engine import AuditResult


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #
_SEV_EMOJI = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🔵",
    "Informational": "⚪",
}


def to_markdown(result: AuditResult, title: str = "Smart Contract Audit Report") -> str:
    ts = _dt.datetime.now().strftime("%Y-%m-%d")
    counts = result.counts_by_severity()
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"_Generated {ts} · engine: solidity-audit-ai · LLM layer: {result.provider}_")
    lines.append("")
    lines.append(f"> **{_headline(result)}**, across {len(result.files)} file(s).")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in sorted(Severity, reverse=True):
        lines.append(f"| {_SEV_EMOJI[sev.label]} {sev.label} | {counts[sev.label]} |")
    lines.append(f"| **Total** | **{result.total}** |")
    lines.append("")
    lines.append(f"Files scanned: {len(result.files)}")
    if result.errors:
        lines.append("")
        lines.append("> Warnings: " + "; ".join(result.errors))
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    findings = result.sorted_findings()
    if not findings:
        lines.append("No findings. ✅ No issues detected by the static detectors.")
        lines.append("")
        lines.append(
            "> A clean run is not a guarantee of safety. These are high-signal "
            "heuristics, not a full audit."
        )
        return "\n".join(lines) + "\n"

    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {_SEV_EMOJI[f.severity.label]} {f.title}  ·  {f.severity.label}")
        lines.append("")
        lines.append(f"- **Severity:** {f.severity.label}")
        lines.append(f"- **SWC:** {f.swc_id or 'n/a'}")
        lines.append(f"- **Confidence:** {f.confidence}")
        lines.append(f"- **Location:** `{f.location}`")
        lines.append(f"- **Detector:** `{f.detector}`")
        lines.append("")
        if f.code:
            lines.append("```solidity")
            lines.append(f.code)
            lines.append("```")
            lines.append("")
        lines.append(f"**Description.** {f.description}")
        lines.append("")
        if f.explanation:
            lines.append(f"**Analysis.** {f.explanation}")
            lines.append("")
        lines.append(f"**Remediation.** {f.remediation}")
        lines.append("")
        if f.fix_suggestion:
            lines.append("**Suggested fix.**")
            lines.append("")
            lines.append("```solidity")
            lines.append(f.fix_suggestion)
            lines.append("```")
            lines.append("")
        if f.references:
            refs = " · ".join(f"[ref]({r})" for r in f.references)
            lines.append(f"_References: {refs}_")
            lines.append("")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# HTML (self-contained, no external assets)
# --------------------------------------------------------------------------- #
# Severity palette for the standalone report. Neon-on-dark crypto identity.
_SEV_CSS = {
    "Critical": ("#fb7185", "rgba(244,63,94,.14)"),
    "High": ("#fb923c", "rgba(249,115,22,.14)"),
    "Medium": ("#fbbf24", "rgba(245,158,11,.14)"),
    "Low": ("#38bdf8", "rgba(56,189,248,.14)"),
    "Informational": ("#94a3b8", "rgba(148,163,184,.14)"),
}


def _sev_key(label: str) -> str:
    return label.lower()


_HTML_HEAD = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark light">
<title>{title}</title>
<style>
/* solidity-audit-ai report: crypto-modern, dark-first, self-contained (no
   external assets). Light mode via prefers-color-scheme. */
:root {{
  --bg:#070a14; --panel:#0f1421; --panel2:#0c101c; --border:#262f47;
  --text:#e2e8f0; --muted:#94a3b8; --faint:#64748b; --soft:#141a2b;
  --code-bg:#090c16; --cyan:#22d3ee; --violet:#8b5cf6; --safe:#34d399;
  --grid:rgba(148,163,184,.05);
}}
@media (prefers-color-scheme: light) {{
  :root {{
    --bg:#f8fafc; --panel:#ffffff; --panel2:#f8fafc; --border:#e2e8f0;
    --text:#0f172a; --muted:#475569; --faint:#64748b; --soft:#f1f5f9;
    --code-bg:#f8fafc; --cyan:#0891b2; --violet:#7c3aed; --safe:#059669;
    --grid:rgba(15,23,42,.04);
  }}
}}
* {{ box-sizing: border-box; }}
html {{ -webkit-text-size-adjust: 100%; }}
body {{ font-family: "Geist", "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
       margin:0; background:var(--bg); color:var(--text); line-height:1.65;
       background-image:
         radial-gradient(46rem 46rem at 92% -10%, rgba(139,92,246,.16), transparent 60%),
         radial-gradient(50rem 50rem at -8% 2%, rgba(34,211,238,.14), transparent 55%),
         linear-gradient(var(--grid) 1px, transparent 1px),
         linear-gradient(90deg, var(--grid) 1px, transparent 1px);
       background-size: auto, auto, 56px 56px, 56px 56px;
       -webkit-font-smoothing:antialiased; }}
.wrap {{ max-width: 920px; margin: 0 auto; padding: 44px 20px 64px; }}
.brand {{ display:flex; align-items:center; gap:11px; margin-bottom:22px; }}
.brand .mark {{ width:36px; height:36px; border-radius:11px; display:grid; place-items:center;
                background:linear-gradient(135deg,var(--cyan),var(--violet)); color:#05161c; flex:none;
                box-shadow:0 0 28px -6px rgba(34,211,238,.6); }}
.brand .name {{ font-family:"Geist Mono",ui-monospace,SFMono-Regular,Menlo,monospace; font-weight:700; font-size:.95rem; letter-spacing:-.01em; }}
.brand .name span {{ background:linear-gradient(100deg,var(--cyan),var(--violet));
                     -webkit-background-clip:text; background-clip:text; color:transparent; }}
.brand .tag {{ font-size:.64rem; text-transform:uppercase; letter-spacing:.16em; color:var(--faint); }}
h1 {{ font-size: 1.9rem; font-weight:800; letter-spacing:-.02em; margin: 0 0 6px; }}
.meta {{ color: var(--muted); font-size: .83rem; margin-bottom: 22px; font-family:"Geist Mono",ui-monospace,Menlo,monospace; }}
.meta code {{ color:var(--text); }}
.glass {{ background:linear-gradient(180deg, rgba(255,255,255,.03), transparent), var(--panel);
          border:1px solid var(--border); border-radius:16px; }}
.headline {{ display:flex; align-items:center; gap:11px; padding:16px 18px; margin-bottom:14px;
             background:linear-gradient(180deg, rgba(255,255,255,.03), transparent), var(--panel);
             border:1px solid var(--border); border-radius:16px;
             box-shadow:0 20px 48px -28px rgba(0,0,0,.7); }}
.headline .dot {{ width:11px; height:11px; border-radius:999px; flex:none; box-shadow:0 0 10px 0 currentColor; }}
.headline .txt {{ font-size:1.05rem; font-weight:700; }}
.sevbar {{ display:flex; height:8px; border-radius:999px; overflow:hidden; background:var(--soft); margin:0 0 22px; }}
.sevbar span {{ display:block; height:100%; }}
.cards {{ display:grid; grid-template-columns:repeat(5,1fr); gap:10px; margin: 0 0 28px; }}
.card {{ background:var(--panel2); border:1px solid var(--border); border-radius:13px;
         padding:15px 10px; text-align:center; }}
.card .n {{ font-family:"Geist Mono",ui-monospace,Menlo,monospace; font-size:1.7rem; font-weight:700; line-height:1; text-shadow:0 0 18px currentColor; }}
.card .l {{ font-size:.64rem; text-transform:uppercase; letter-spacing:.08em; color:var(--muted); margin-top:7px; }}
.card.dim {{ opacity:.4; }}
.badge {{ display:inline-flex; align-items:center; gap:.35rem; padding:.18rem .6rem; border-radius:999px;
          font-family:"Geist Mono",ui-monospace,Menlo,monospace;
          font-size:.64rem; font-weight:700; text-transform:uppercase; letter-spacing:.06em; white-space:nowrap;
          border:1px solid currentColor; }}
.badge::before {{ content:""; width:.45rem; height:.45rem; border-radius:999px; background:currentColor; box-shadow:0 0 8px 0 currentColor; }}
.finding {{ background:linear-gradient(180deg, rgba(255,255,255,.02), transparent), var(--panel);
            border:1px solid var(--border); border-left-width:3px;
            border-radius:16px; padding:20px 22px; margin:0 0 16px;
            box-shadow:0 20px 48px -30px rgba(0,0,0,.7); }}
.finding-head {{ display:flex; align-items:flex-start; justify-content:space-between; gap:12px; }}
.finding h3 {{ margin:0; font-size:1.08rem; font-weight:700; }}
.finding h3 .idx {{ color:var(--faint); font-weight:600; font-family:"Geist Mono",ui-monospace,Menlo,monospace; }}
.chips {{ display:flex; flex-wrap:wrap; gap:6px; margin:12px 0; }}
.chip {{ display:inline-flex; align-items:center; gap:.3rem; padding:.13rem .5rem; border-radius:.45rem;
         font-family:"Geist Mono",ui-monospace,Menlo,monospace;
         font-size:.72rem; border:1px solid var(--border); background:var(--panel2); color:var(--muted); }}
.chip code, .chip a {{ color:var(--text); font-weight:600; text-decoration:none; }}
.chip a:hover {{ color:var(--cyan); }}
pre {{ background:var(--code-bg); border:1px solid var(--border); border-radius:11px; padding:13px 15px;
       overflow:auto; font-size:.8rem; line-height:1.65; margin:.6rem 0; }}
code, pre {{ font-family: "Geist Mono", ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace; }}
.section-label {{ font-size:.66rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em;
                  color:var(--muted); margin-top:14px; margin-bottom:3px; }}
.section-label.fix {{ color:var(--safe); }}
.body-text {{ color:var(--text); font-size:.92rem; }}
a {{ color:var(--cyan); }}
.refs {{ font-size:.76rem; color:var(--muted); margin-top:12px; }}
.refs a {{ color:var(--muted); text-decoration:underline; text-decoration-style:dotted; }}
.empty {{ background:var(--panel); border:1px solid var(--border); border-radius:16px; padding:44px 24px;
          text-align:center; box-shadow:0 20px 48px -30px rgba(0,0,0,.7); }}
.empty .ok {{ width:52px; height:52px; border-radius:999px; display:inline-grid; place-items:center;
              background:rgba(52,211,153,.12); color:var(--safe); margin-bottom:12px;
              box-shadow:0 0 32px -6px rgba(52,211,153,.6); }}
.empty .t {{ font-weight:700; }}
.empty .s {{ color:var(--muted); font-size:.85rem; margin-top:6px; }}
footer {{ color: var(--faint); font-size:.74rem; margin-top:40px; padding-top:20px;
          border-top:1px solid var(--border); text-align:center; font-family:"Geist Mono",ui-monospace,Menlo,monospace; }}
@media (max-width:640px) {{ .cards {{ grid-template-columns:repeat(2,1fr); }} h1 {{ font-size:1.5rem; }} }}
</style></head><body><div class="wrap">
<div class="brand">
  <span class="mark"><svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>
  <span><span class="name">solidity<span>-audit</span>-ai</span><br><span class="tag">Smart contract security audit</span></span>
</div>
"""

_HTML_FOOT = """
<footer>Generated by solidity-audit-ai · static detectors + AI-assisted remediation, fully offline.<br>
A pre-audit, not a substitute for a professional manual review. Built by Laela Zorana.</footer>
</div></body></html>
"""


def _esc(s: str) -> str:
    return html.escape(s or "")


def _headline(result: AuditResult) -> str:
    """A one-line, recruiter-readable headline: 'N findings: X Critical, ...'."""
    counts = result.counts_by_severity()
    if not result.total:
        return "No findings, clean run"
    parts = [f"{counts[s.label]} {s.label}" for s in sorted(Severity, reverse=True) if counts[s.label]]
    n = result.total
    return f"{n} finding{'s' if n != 1 else ''}: " + ", ".join(parts)


def to_html(result: AuditResult, title: str = "Smart Contract Audit Report") -> str:
    ts = _dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    counts = result.counts_by_severity()
    parts: list[str] = [_HTML_HEAD.format(title=_esc(title))]
    parts.append(f"<h1>{_esc(title)}</h1>")
    parts.append(
        f'<div class="meta">Generated {ts} · engine: <code>solidity-audit-ai</code> · '
        f"AI layer: <code>{_esc(result.provider)}</code> · files scanned: {len(result.files)}</div>"
    )

    # Headline summary sentence.
    top_color = "#34d399" if not result.total else _SEV_CSS["Critical"][0]
    if result.total:
        # color the dot by the worst present severity
        for sev in sorted(Severity, reverse=True):
            if counts[sev.label]:
                top_color = _SEV_CSS[sev.label][0]
                break
    parts.append(
        f'<div class="headline"><span class="dot" style="background:{top_color}"></span>'
        f'<span class="txt">{_esc(_headline(result))}</span></div>'
    )

    # Severity distribution bar (segmented, proportional).
    if result.total:
        parts.append('<div class="sevbar">')
        for sev in sorted(Severity, reverse=True):
            n = counts[sev.label]
            if not n:
                continue
            pct = n / result.total * 100
            fg, _bg = _SEV_CSS[sev.label]
            parts.append(
                f'<span style="width:{pct:.4f}%;background:{fg}" '
                f'title="{n} {sev.label}"></span>'
            )
        parts.append("</div>")

    # Summary stat tiles.
    parts.append('<div class="cards">')
    for sev in sorted(Severity, reverse=True):
        fg, _bg = _SEV_CSS[sev.label]
        n = counts[sev.label]
        dim = " dim" if n == 0 else ""
        parts.append(
            f'<div class="card{dim}">'
            f'<div class="n" style="color:{fg}">{n}</div>'
            f'<div class="l">{sev.label}</div></div>'
        )
    parts.append("</div>")

    findings = result.sorted_findings()
    if not findings:
        parts.append(
            '<div class="empty">'
            '<div class="ok"><svg width="24" height="24" viewBox="0 0 24 24" fill="none" '
            'stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
            '<path d="M20 6 9 17l-5-5"/></svg></div>'
            '<div class="t">No findings.</div>'
            '<div class="s">No issues detected by the static detectors. A clean run is not a '
            "guarantee of safety. These are high-signal heuristics, not a full audit.</div></div>"
        )
        parts.append(_HTML_FOOT)
        return "".join(parts)

    for i, f in enumerate(findings, 1):
        fg, bg = _SEV_CSS.get(f.severity.label, _SEV_CSS["Informational"])
        parts.append(f'<div class="finding" style="border-left-color:{fg}">')
        parts.append('<div class="finding-head">')
        parts.append(f'<h3><span class="idx">{i}.</span> {_esc(f.title)}</h3>')
        parts.append(
            f'<span class="badge" style="color:{fg};background:{bg}">{f.severity.label}</span>'
        )
        parts.append("</div>")
        parts.append('<div class="chips">')
        swc = _esc(f.swc_id)
        if swc:
            parts.append(
                f'<span class="chip">SWC <a href="https://swcregistry.io/docs/{swc}">{swc}</a></span>'
            )
        else:
            parts.append('<span class="chip">SWC <code>n/a</code></span>')
        parts.append(f'<span class="chip">Line <code>{f.line}</code></span>')
        parts.append(f'<span class="chip">Confidence <code>{_esc(f.confidence)}</code></span>')
        parts.append(f'<span class="chip">Detector <code>{_esc(f.detector)}</code></span>')
        parts.append("</div>")
        if f.code:
            parts.append(f"<pre><code>{_esc(f.code)}</code></pre>")
        parts.append(
            f'<div class="section-label">Description</div>'
            f'<div class="body-text">{_esc(f.description)}</div>'
        )
        if f.explanation:
            parts.append(
                f'<div class="section-label">Analysis</div>'
                f'<div class="body-text">{_esc(f.explanation)}</div>'
            )
        parts.append(
            f'<div class="section-label fix">Remediation</div>'
            f'<div class="body-text">{_esc(f.remediation)}</div>'
        )
        if f.fix_suggestion:
            parts.append('<div class="section-label fix">Suggested fix</div>')
            parts.append(f"<pre><code>{_esc(f.fix_suggestion)}</code></pre>")
        if f.references:
            links = " · ".join(f'<a href="{_esc(r)}">{_esc(r)}</a>' for r in f.references)
            parts.append(f'<div class="refs">References: {links}</div>')
        parts.append("</div>")

    parts.append(_HTML_FOOT)
    return "".join(parts)
