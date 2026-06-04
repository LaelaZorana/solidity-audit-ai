// solidity-audit-ai — client logic: theme toggle, sample loading, audit flow.
(function () {
  "use strict";

  // ---- Theme (light/dark) with persistence + system fallback -------------
  const root = document.documentElement;
  const THEME_KEY = "solaudit-theme";

  function applyTheme(theme) {
    if (theme === "dark") root.classList.add("dark");
    else root.classList.remove("dark");
  }
  function initTheme() {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved) applyTheme(saved);
    else applyTheme(window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  window.toggleTheme = function () {
    const isDark = root.classList.toggle("dark");
    localStorage.setItem(THEME_KEY, isDark ? "dark" : "light");
  };
  initTheme();

  // ---- Helpers -----------------------------------------------------------
  function el(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }
  const SEV_ORDER = ["Critical", "High", "Medium", "Low", "Informational"];
  function sevKey(label) { return String(label || "").toLowerCase(); }

  // ---- Sample contracts (seeded; zero-friction one-click try) ------------
  // Populated from a JSON <script> rendered by the server.
  let SAMPLES = {};
  try {
    const dataEl = el("samples-data");
    if (dataEl) SAMPLES = JSON.parse(dataEl.textContent || "{}");
  } catch (e) { SAMPLES = {}; }

  window.loadSample = function (key, andRun) {
    const ta = el("source");
    const fn = el("filename");
    const sample = SAMPLES[key];
    if (!ta || !sample) return;
    ta.value = sample.source;
    if (fn && sample.filename) fn.value = sample.filename;
    ta.focus();
    ta.scrollTop = 0;
    if (andRun) runAudit();
  };

  // ---- Render ------------------------------------------------------------
  function summaryHeadline(summary, total) {
    if (!total) return "No findings — looks clean";
    const parts = [];
    SEV_ORDER.forEach(function (s) {
      if (summary[s]) parts.push(summary[s] + " " + s);
    });
    return total + (total === 1 ? " finding" : " findings") + ": " + parts.join(", ");
  }

  function renderSummary(summary, total, provider) {
    const tiles = SEV_ORDER.map(function (s) {
      const n = summary[s] || 0;
      const dim = n === 0 ? "opacity-40" : "";
      return (
        '<div class="stat-' + sevKey(s) + ' sa-card flex flex-col items-center justify-center px-3 py-3 ' + dim + '">' +
          '<div class="stat-n text-2xl font-bold leading-none">' + n + "</div>" +
          '<div class="mt-1 text-[10px] font-semibold uppercase tracking-wider text-slate-400">' + s + "</div>" +
        "</div>"
      );
    }).join("");
    // Segmented severity distribution bar (Code4rena/CertiK pattern).
    var bar = "";
    if (total) {
      bar = '<div class="sev-bar mt-4">' + SEV_ORDER.map(function (s) {
        var n = summary[s] || 0;
        if (!n) return "";
        var pct = (n / total) * 100;
        return '<span class="seg-' + sevKey(s) + '" style="width:' + pct + '%" title="' + n + " " + s + '"></span>';
      }).join("") + "</div>";
    }
    const headlineClass = total ? "text-slate-900 dark:text-white" : "text-emerald-600 dark:text-emerald-400";
    return (
      '<div class="sa-card sa-card--glow sa-fade p-5 sm:p-6">' +
        '<div class="flex flex-wrap items-start justify-between gap-3">' +
          "<div>" +
            '<div class="text-[11px] font-semibold uppercase tracking-wider text-brand-500 dark:text-brand-400">Audit summary</div>' +
            '<h2 class="mt-1 text-xl font-bold sm:text-2xl ' + headlineClass + '">' + esc(summaryHeadline(summary, total)) + "</h2>" +
          "</div>" +
          '<span class="meta-chip">engine: offline · ' + esc(provider) + "</span>" +
        "</div>" +
        bar +
        '<div class="mt-4 grid grid-cols-5 gap-2 sm:gap-3">' + tiles + "</div>" +
      "</div>"
    );
  }

  function metaChip(label, value, isCode) {
    if (!value) return "";
    const inner = isCode ? "<code>" + esc(value) + "</code>" : esc(value);
    return '<span class="meta-chip">' + esc(label) + " " + inner + "</span>";
  }

  function findingCard(f, idx) {
    const sev = sevKey(f.severity);
    const refs = (f.references || []).map(function (r) {
      return '<a class="underline decoration-dotted hover:text-brand-600 dark:hover:text-brand-400" href="' +
        esc(r) + '" target="_blank" rel="noopener">' + esc(r.replace(/^https?:\/\//, "")) + "</a>";
    }).join(" · ");

    let body = "";
    if (f.code) body += '<pre class="code-block mt-3">' + esc(f.code) + "</pre>";
    body +=
      '<div class="mt-4 space-y-3 text-sm leading-relaxed text-slate-600 dark:text-slate-300">' +
        '<div><div class="mb-0.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Description</div>' + esc(f.description) + "</div>";
    if (f.explanation) {
      body += '<div><div class="mb-0.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Analysis</div>' + esc(f.explanation) + "</div>";
    }
    body +=
        '<div><div class="mb-0.5 text-[11px] font-semibold uppercase tracking-wider text-emerald-500">Remediation</div>' +
          '<span class="text-slate-700 dark:text-slate-200">' + esc(f.remediation) + "</span></div>" +
      "</div>";
    if (f.fix_suggestion) {
      body +=
        '<div class="mt-3">' +
          '<div class="mb-1 flex items-center justify-between">' +
            '<div class="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Suggested fix</div>' +
            '<button type="button" class="copy-btn inline-flex items-center gap-1 rounded-md border border-slate-200 px-2 py-0.5 text-[11px] font-medium text-slate-400 transition hover:border-brand-400/50 hover:text-brand-600 dark:border-white/10 dark:hover:text-brand-400" data-copy="' + esc(f.fix_suggestion) + '">Copy fix</button>' +
          "</div>" +
          '<pre class="code-block">' + esc(f.fix_suggestion) + "</pre>" +
        "</div>";
    }
    if (refs) body += '<div class="mt-3 text-xs text-slate-400">References: ' + refs + "</div>";

    return (
      '<article class="finding-' + sev + ' sa-card sa-fade overflow-hidden p-5 sm:p-6">' +
        '<div class="flex flex-wrap items-start justify-between gap-3">' +
          '<h3 class="text-base font-semibold text-slate-900 dark:text-white">' +
            '<span class="text-slate-400">' + idx + ".</span> " + esc(f.title) +
          "</h3>" +
          '<span class="sev-badge sev-' + sev + '">' + esc(f.severity) + "</span>" +
        "</div>" +
        '<div class="mt-3 flex flex-wrap gap-2">' +
          metaChip("SWC", f.swc_id || "n/a", true) +
          metaChip("Line", f.line, true) +
          metaChip("Confidence", f.confidence, false) +
          metaChip("Detector", f.detector, true) +
        "</div>" +
        body +
      "</article>"
    );
  }

  function showState(name) {
    ["empty", "loading", "error", "results"].forEach(function (s) {
      const node = el("state-" + s);
      if (node) node.hidden = s !== name;
    });
  }

  function renderResults(data) {
    const wrap = el("state-results");
    if (!wrap) return;
    let html = renderSummary(data.summary, data.total, data.provider);
    if (data.total) {
      html += '<div class="mt-5 space-y-4">';
      data.findings.forEach(function (f, i) { html += findingCard(f, i + 1); });
      html += "</div>";
    } else {
      html +=
        '<div class="sa-card sa-fade mt-5 flex flex-col items-center gap-3 p-10 text-center">' +
          '<span class="grid h-12 w-12 place-items-center rounded-full bg-emerald-50 text-emerald-600 dark:bg-emerald-500/10 dark:text-emerald-400">' +
            '<svg class="h-6 w-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6 9 17l-5-5"/></svg>' +
          "</span>" +
          '<p class="text-sm font-medium text-slate-700 dark:text-slate-200">No issues detected by the static detectors.</p>' +
          '<p class="max-w-sm text-xs text-slate-400">A clean run is not a guarantee of safety — these are high-signal heuristics, not a full audit.</p>' +
        "</div>";
    }
    wrap.innerHTML = html;
    showState("results");
  }

  // ---- Audit flow --------------------------------------------------------
  function runAudit() {
    const ta = el("source");
    if (!ta) return;
    const source = ta.value;
    const filename = (el("filename") && el("filename").value) || "Contract.sol";
    if (!source.trim()) {
      showState("empty");
      ta.focus();
      return;
    }
    showState("loading");
    // Scroll results into view on small screens.
    const out = el("results-panel");
    if (out && window.innerWidth < 1024) out.scrollIntoView({ behavior: "smooth", block: "start" });

    fetch("/api/audit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ source: source, filename: filename }),
    })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, body: j }; }); })
      .then(function (res) {
        if (!res.ok) throw new Error(res.body && res.body.error ? res.body.error : "Audit failed");
        renderResults(res.body);
      })
      .catch(function (err) {
        const node = el("state-error-msg");
        if (node) node.textContent = err.message || "Something went wrong.";
        showState("error");
      });
  }
  window.runAudit = runAudit;

  // ---- Wiring ------------------------------------------------------------
  document.addEventListener("DOMContentLoaded", function () {
    const form = el("audit-form");
    if (form) {
      form.addEventListener("submit", function (e) { e.preventDefault(); runAudit(); });
    }
    // Ctrl/Cmd+Enter submits from the textarea.
    const ta = el("source");
    if (ta) {
      ta.addEventListener("keydown", function (e) {
        if ((e.metaKey || e.ctrlKey) && e.key === "Enter") { e.preventDefault(); runAudit(); }
      });
    }
    // Delegated copy buttons.
    document.addEventListener("click", function (e) {
      const btn = e.target.closest(".copy-btn");
      if (!btn) return;
      const text = btn.getAttribute("data-copy") || "";
      if (navigator.clipboard) {
        navigator.clipboard.writeText(text).then(function () {
          const old = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(function () { btn.textContent = old; }, 1400);
        });
      }
    });
  });
})();
