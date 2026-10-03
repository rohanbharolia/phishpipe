/* ==========================================================================
   PhishPipe frontend
   Plain JS, no build step. Every API response is untrusted data: all of it is
   rendered through esc() or textContent, never injected as raw HTML.
   ========================================================================== */
"use strict";

const state = { case: null, view: "summary", cases: [], search: "" };

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

/* ---------- helpers ---------- */
function esc(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail || JSON.stringify(body);
    } catch (_) { /* non-JSON error body */ }
    throw new Error(`${res.status}: ${detail}`);
  }
  return res.json();
}

/* Neutralise live URLs in free text (evidence, context) before display. */
function defang(value) {
  return String(value ?? "").replace(/https?:\/\//gi, (m) => m.replace(/http/i, "hxxp"));
}

const CLS_LABEL = {
  true_positive: "TRUE POSITIVE",
  suspicious: "SUSPICIOUS — HUMAN REVIEW",
  false_positive: "LIKELY FALSE POSITIVE",
};
const CLS_CHIP = { true_positive: "tp", suspicious: "su", false_positive: "fp" };
const SEV_COLOR = {
  critical: "#ff4d6d", high: "#ff9f43", medium: "#ffd93d", low: "#35d49a", info: "#7f8ea3",
};

/* ---------- minimal, safe Markdown renderer ---------- */
function md(src) {
  const lines = String(src ?? "").split("\n");
  let out = "", i = 0, listType = null;

  const closeList = () => { if (listType) { out += `</${listType}>`; listType = null; } };

  const inline = (t) => {
    let s = esc(t);
    s = s.replace(/`([^`]+)`/g, (_, c) => `<code>${c}</code>`);
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    s = s.replace(/(^|[\s(])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, (m, label, url) => {
      if (!/^(https?:|#|\/)/i.test(url)) return m;
      return `<a href="${esc(url)}" target="_blank" rel="noopener noreferrer">${label}</a>`;
    });
    return s;
  };

  while (i < lines.length) {
    const line = lines[i];

    // fenced code
    if (/^```/.test(line)) {
      closeList();
      const buf = [];
      i++;
      while (i < lines.length && !/^```/.test(lines[i])) buf.push(lines[i++]);
      i++;
      out += `<pre><code>${esc(buf.join("\n"))}</code></pre>`;
      continue;
    }

    // table (header row followed by a |---|---| style separator)
    if (/^\|.*\|\s*$/.test(line) && i + 1 < lines.length && /^\|(?:\s*:?-{2,}\s*\|)+\s*$/.test(lines[i + 1])) {
      closeList();
      const cells = (r) => r.replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
      const head = cells(line);
      i += 2;
      const rows = [];
      while (i < lines.length && /^\|.*\|\s*$/.test(lines[i])) rows.push(cells(lines[i++]));
      out += "<table><thead><tr>" + head.map((h) => `<th>${inline(h)}</th>`).join("") + "</tr></thead><tbody>";
      for (const r of rows) {
        out += "<tr>" + r.map((c) => `<td>${inline(c)}</td>`).join("") + "</tr>";
      }
      out += "</tbody></table>";
      continue;
    }

    // headings
    const h = line.match(/^(#{1,4})\s+(.*)$/);
    if (h) { closeList(); const n = h[1].length; out += `<h${n}>${inline(h[2])}</h${n}>`; i++; continue; }

    // horizontal rule
    if (/^---+\s*$/.test(line)) { closeList(); out += "<hr />"; i++; continue; }

    // blockquote
    if (/^>\s?/.test(line)) {
      closeList();
      const buf = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) buf.push(lines[i++].replace(/^>\s?/, ""));
      out += `<blockquote>${inline(buf.join(" "))}</blockquote>`;
      continue;
    }

    // unordered list
    const ul = line.match(/^\s*[-*]\s+(.*)$/);
    if (ul) {
      if (listType !== "ul") { closeList(); out += "<ul>"; listType = "ul"; }
      out += `<li>${inline(ul[1])}</li>`; i++; continue;
    }

    // ordered list
    const ol = line.match(/^\s*(\d+)[.)]\s+(.*)$/);
    if (ol) {
      if (listType !== "ol") { closeList(); out += "<ol>"; listType = "ol"; }
      out += `<li>${inline(ol[2])}</li>`; i++; continue;
    }

    if (line.trim() === "") { closeList(); i++; continue; }

    closeList();
    out += `<p>${inline(line)}</p>`;
    i++;
  }
  closeList();
  return out;
}

/* ---------- status / metrics ---------- */
async function loadStatus() {
  try {
    const s = await api("/api/status");

    const modeBadge = $("#badge-mode");
    const activeLive = s.providers.filter((p) => p.available && p.name !== "offline");

    if (s.offline_mode) {
      modeBadge.textContent = "OFFLINE MODE (FORCED)";
      modeBadge.className = "badge off";
      modeBadge.title = `PHISHPIPE_OFFLINE is set — reputation providers disabled.`;
    } else if (activeLive.length) {
      modeBadge.textContent = "LIVE PROVIDERS";
      modeBadge.className = "badge live";
      modeBadge.title = `Active: ${activeLive.map((p) => p.name).join(", ")}`;
    } else {
      modeBadge.textContent = "OFFLINE — LOCAL CACHE";
      modeBadge.className = "badge off";
      modeBadge.title =
        "No reputation API keys configured. Answering from the bundled local verdict cache.";
    }

    $("#badge-detections").textContent = `detections v${s.detections.version}`;
    $("#badge-detections").title = `${s.detections.signal_count} signals · updated ${s.detections.updated}`;

    const llmBadge = $("#badge-llm");
    llmBadge.textContent = s.llm.enabled ? `LLM: ${s.llm.model}` : "TEMPLATE NARRATIVE";
    llmBadge.className = `badge ${s.llm.enabled ? "live" : ""}`;
    llmBadge.title = s.llm.note || `Narrative mode: ${s.llm.mode}`;

    $("#badge-cases").textContent = `${s.cases} case${s.cases === 1 ? "" : "s"}`;
  } catch (err) {
    console.error("status failed", err);
  }
}

async function loadMetrics() {
  try {
    const m = await api("/api/metrics");
    if (!m.total_cases) { $("#metrics").hidden = true; return; }
    const box = $("#metrics");
    box.innerHTML = [
      ["Cases", m.total_cases],
      ["Avg confidence", `${m.avg_confidence}%`],
      ["Avg triage time", `${Math.round(m.avg_processing_ms)} ms`],
      ["Needs review", m.needs_human_review],
      ["Minutes saved", `~${Math.round(m.minutes_saved)}`],
    ]
      .map(([k, v]) => `<div class="metric"><div class="k">${esc(k)}</div><div class="v">${esc(v)}</div></div>`)
      .join("");
    box.hidden = false;
  } catch (err) { console.error("metrics failed", err); }
}

/* ---------- intake ---------- */
function bindTabs(container, handler) {
  $$(".tab", container).forEach((btn) => {
    btn.addEventListener("click", () => {
      $$(".tab", container).forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      handler(btn);
    });
  });
}

function showProgress(label) {
  $("#progress-label").textContent = label || "Running pipeline…";
  $("#progress").hidden = false;
  $("#error-box").hidden = true;
  $$("button.primary").forEach((b) => (b.disabled = true));
}
function hideProgress() {
  $("#progress").hidden = true;
  $$("button.primary").forEach((b) => (b.disabled = false));
}
function showError(msg) {
  const box = $("#error-box");
  box.textContent = msg;
  box.hidden = false;
}

async function runUpload(file) {
  if (!file) return;
  showProgress(`Investigating ${file.name}…`);
  try {
    const form = new FormData();
    form.append("file", file);
    const res = await fetch("/api/investigate/upload", { method: "POST", body: form });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || res.statusText);
    }
    renderCase(await res.json());
    await Promise.all([loadCases(), loadStatus(), loadMetrics()]);
  } catch (err) {
    showError(err.message);
  } finally {
    hideProgress();
  }
}

async function runRaw() {
  const raw = $("#raw-input").value;
  if (!raw.trim()) { showError("Paste a raw message first."); return; }
  showProgress("Investigating pasted message…");
  try {
    const c = await api("/api/investigate/raw", {
      method: "POST",
      body: JSON.stringify({ raw_email: raw }),
    });
    renderCase(c);
    await Promise.all([loadCases(), loadStatus(), loadMetrics()]);
  } catch (err) {
    showError(err.message);
  } finally {
    hideProgress();
  }
}

async function runSample(name) {
  showProgress(`Investigating ${name}…`);
  try {
    const c = await api(`/api/investigate/sample/${encodeURIComponent(name)}`, { method: "POST" });
    renderCase(c);
    await Promise.all([loadCases(), loadStatus(), loadMetrics()]);
  } catch (err) {
    showError(err.message);
  } finally {
    hideProgress();
  }
}

async function loadSamples() {
  try {
    const samples = await api("/api/samples");
    const box = $("#sample-list");
    if (!samples.length) {
      box.innerHTML = `<p class="hint">No samples bundled. Add .eml files to <code>samples/</code>.</p>`;
      return;
    }
    box.innerHTML = "";
    for (const s of samples) {
      const btn = document.createElement("button");
      btn.className = "sample";
      btn.innerHTML = `${esc(s.name)}<small>${(s.size / 1024).toFixed(1)} KB</small>`;
      btn.addEventListener("click", () => runSample(s.name));
      box.appendChild(btn);
    }
  } catch (err) { console.error("samples failed", err); }
}

/* ---------- case queue ---------- */
async function loadCases() {
  try {
    const q = state.search ? `&search=${encodeURIComponent(state.search)}` : "";
    const data = await api(`/api/cases?limit=100${q}`);
    state.cases = data.items;
    $("#case-count").textContent = `(${data.total})`;
    const box = $("#case-list");
    box.innerHTML = "";
    if (!data.items.length) {
      box.innerHTML = `<p class="hint">No cases stored yet.</p>`;
      return;
    }
    for (const c of data.items) {
      const el = document.createElement("div");
      el.className = "case-item" + (state.case && state.case.id === c.id ? " active" : "");
      el.style.borderLeftColor = SEV_COLOR[c.severity] || "#263246";
      el.innerHTML = `
        <div class="cid">${esc(c.id)}</div>
        <div class="ctitle">${esc(c.subject || c.title)}</div>
        <div class="cmeta">
          <span><span class="dot" style="background:${SEV_COLOR[c.severity] || "#666"}"></span>${esc(c.severity)}</span>
          <span>${esc(c.confidence)}%</span>
        </div>`;
      el.addEventListener("click", () => openCase(c.id));
      box.appendChild(el);
    }
  } catch (err) { console.error("cases failed", err); }
}

async function openCase(id) {
  showProgress(`Loading ${id}…`);
  try {
    renderCase(await api(`/api/cases/${encodeURIComponent(id)}`));
    await loadCases();
  } catch (err) {
    showError(err.message);
  } finally {
    hideProgress();
  }
}

/* ---------- rendering ---------- */
function gauge(confidence, color) {
  const r = 58, c = 2 * Math.PI * r;
  const dash = (confidence / 100) * c;
  return `
    <div class="gauge">
      <svg width="132" height="132" viewBox="0 0 132 132">
        <circle cx="66" cy="66" r="${r}" fill="none" stroke="#263246" stroke-width="11" />
        <circle cx="66" cy="66" r="${r}" fill="none" stroke="${color}" stroke-width="11"
          stroke-linecap="round" stroke-dasharray="${dash} ${c - dash}" />
      </svg>
      <div class="val"><b>${esc(confidence)}</b><span>confidence</span></div>
    </div>`;
}

function renderCase(c) {
  state.case = c;
  $("#empty-state").hidden = true;
  $("#case-view").hidden = false;
  $("#error-box").hidden = true;

  const v = c.verdict;
  const color = SEV_COLOR[v.severity] || "#4f9cff";

  $("#verdict-hero").innerHTML = `
    ${gauge(v.confidence, color)}
    <div class="verdict-meta">
      <div class="cls" style="color:${color}">${esc(CLS_LABEL[v.classification] || v.classification)}</div>
      <h2>${esc(c.title)}</h2>
      <div class="pills">
        <span class="pill">case ${esc(c.id)}</span>
        <span class="pill">severity ${esc(v.severity)}</span>
        <span class="pill">${esc(v.signals_matched)}/${esc(v.signals_total)} signals</span>
        <span class="pill">${esc(c.metrics.total_ms)} ms</span>
        <span class="pill">${c.metrics.offline ? "offline triage" : "live reputation"}</span>
        ${v.needs_human_review ? `<span class="pill" style="border-color:#7a621f;color:#ffd93d">⚠ human review</span>` : ""}
      </div>
      ${v.mitre.map((t) => `<span class="pill technique" title="${esc(t.tactic)}">${esc(t.id)} ${esc(t.name)}</span>`).join(" ")}
      <p>${esc(v.explanation)}</p>
    </div>`;

  renderSummary(c);
  renderSignals(c);
  renderIocs(c);
  renderEnrichment(c);
  renderTimeline(c);
  renderReport(c);
  renderNotify(c);

  showView(state.view);
  document.getElementById("results").scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderSummary(c) {
  const v = c.verdict, e = c.email;
  const matched = c.signals.filter((s) => s.matched);
  $("#view-summary").innerHTML = `
    ${v.needs_human_review ? `<div class="callout warn"><strong>Escalated for human review.</strong> ${esc((c.signals.find((s) => s.id === "guard.needs_human_review") || {}).evidence || "")}</div>` : ""}
    <div class="grid2">
      <div>
        <h3>Why this score</h3>
        <ul class="reasoning">${v.reasoning.map((r) => `<li>${esc(r)}</li>`).join("")}</ul>
        <h3 style="margin-top:18px">Recommended actions</h3>
        <ol class="actions">${v.recommended_actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ol>
      </div>
      <div>
        <h3>Message</h3>
        <dl class="kv">
          <dt>Subject</dt><dd>${esc(e.subject) || "—"}</dd>
          <dt>From</dt><dd>${esc(e.from_display_name || "")} &lt;${esc(e.from_address)}&gt;</dd>
          <dt>To</dt><dd>${esc((e.to || []).join(", ")) || "—"}</dd>
          <dt>Reply-To</dt><dd>${esc(e.reply_to) || "—"}</dd>
          <dt>Return-Path</dt><dd>${esc(e.return_path) || "—"}</dd>
          <dt>SPF</dt><dd>${esc(e.auth.spf || "not evaluated")}</dd>
          <dt>DKIM</dt><dd>${esc(e.auth.dkim || "not evaluated")}</dd>
          <dt>DMARC</dt><dd>${esc(e.auth.dmarc || "not evaluated")}</dd>
          <dt>Attachments</dt><dd>${(e.attachments || []).length}</dd>
          <dt>Received hops</dt><dd>${(e.received_hops || []).length}</dd>
          <dt>Detected brands</dt><dd>${esc((c.detected_brands || []).join(", ")) || "—"}</dd>
        </dl>
        <h3 style="margin-top:18px">Matched signals (${matched.length})</h3>
        ${
          matched.length
            ? `<ul class="reasoning">${matched.map((s) => `<li><strong>${esc(s.title)}</strong> <span class="chip">${esc(s.weight >= 0 ? "+" + s.weight : s.weight)}</span></li>`).join("")}</ul>`
            : `<p class="hint">No detection signal matched.</p>`
        }
      </div>
    </div>`;
}

function renderSignals(c) {
  const rows = c.signals
    .map(
      (s) => `<tr>
        <td class="mono">${esc(s.id)}</td>
        <td><strong>${esc(s.title)}</strong><div class="hint">${esc(s.description)}</div></td>
        <td class="${s.matched ? "matched-yes" : "matched-no"}">${s.matched ? "✅ yes" : "—"}</td>
        <td class="mono ${s.weight < 0 ? "sev-low" : ""}">${s.weight >= 0 ? "+" + s.weight : s.weight}</td>
        <td class="sev-${esc(s.severity)}">${esc(s.severity)}</td>
        <td>${s.matched ? esc(defang(s.evidence)) : '<span class="hint">not matched</span>'}</td>
      </tr>`
    )
    .join("");
  $("#view-signals").innerHTML = `
    <h3>Detection signals — raw score ${c.verdict.raw_score} clamped to ${c.verdict.confidence}/100</h3>
    <table>
      <thead><tr><th>Rule</th><th>Signal</th><th>Matched</th><th>Weight</th><th>Severity</th><th>Evidence</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function renderIocs(c) {
  const byType = {};
  for (const i of c.indicators) (byType[i.type] = byType[i.type] || []).push(i);
  const typeOrder = ["url", "domain", "ip", "email", "hash", "attachment", "phone"];
  const sections = typeOrder
    .filter((t) => byType[t])
    .map((t) => {
      const rows = byType[t]
        .map(
          (i) => `<tr>
            <td class="mono">${esc(i.defanged)}</td>
            <td>${esc(i.source)}</td>
            <td>${esc(defang(i.context))}</td>
          </tr>`
        )
        .join("");
      return `<h3>${esc(t)} <span class="chip">${byType[t].length}</span></h3>
        <table><thead><tr><th>Indicator (defanged)</th><th>Source</th><th>Context</th></tr></thead><tbody>${rows}</tbody></table>`;
    })
    .join("");

  $("#view-iocs").innerHTML =
    sections ||
    `<p class="hint">No indicators extracted from this message.</p>`;

  const hashRows = (c.email.attachments || [])
    .filter((a) => a.sha256)
    .map(
      (a) => `<tr>
        <td>${esc(a.filename)}</td>
        <td>${esc(a.content_type)}</td>
        <td class="mono">${esc(a.sha256)}</td>
        <td class="mono">${esc(a.md5 || "—")}</td>
      </tr>`
    )
    .join("");
  if (hashRows) {
    $("#view-iocs").innerHTML += `
      <h3 style="margin-top:18px">Attachment hashes</h3>
      <table><thead><tr><th>File</th><th>Type</th><th>SHA-256</th><th>MD5</th></tr></thead><tbody>${hashRows}</tbody></table>`;
  }
}

function renderEnrichment(c) {
  const en = c.enrichment;
  const skipped = Object.entries(en.providers_skipped || {})
    .map(([p, r]) => `<li><code>${esc(p)}</code> — ${esc(r)}</li>`)
    .join("");

  const rows = (en.results || [])
    .map(
      (r) => `<tr>
        <td class="mono">${esc(r.provider)}</td>
        <td class="mono">${esc(defang(r.indicator))}</td>
        <td><span class="chip ${esc(r.verdict)}">${esc(r.verdict)}</span></td>
        <td class="mono">${r.score ?? "—"}</td>
        <td>${esc(r.summary)}</td>
        <td>${r.offline ? "local" : "live"}${r.reference ? ` · <a href="${esc(r.reference)}" target="_blank" rel="noopener">ref</a>` : ""}</td>
      </tr>`
    )
    .join("");

  $("#view-enrichment").innerHTML = `
    <div class="callout">
      Providers used: <strong>${esc((en.providers_used || []).join(", ") || "none")}</strong> ·
      ${esc(en.indicators_checked)} indicator(s) checked in ${esc(en.duration_ms)} ms
    </div>
    ${skipped ? `<h3>Providers skipped</h3><ul class="reasoning">${skipped}</ul>` : ""}
    <h3 style="margin-top:16px">Results</h3>
    ${
      rows
        ? `<table><thead><tr><th>Provider</th><th>Indicator</th><th>Verdict</th><th>Score</th><th>Summary</th><th>Source</th></tr></thead><tbody>${rows}</tbody></table>`
        : `<p class="hint">No enrichment performed.</p>`
    }`;
}

function renderTimeline(c) {
  const rows = (c.timeline || [])
    .map(
      (t, idx) => `<tr>
        <td>${idx + 1}</td>
        <td class="mono">${esc(t.stage)}</td>
        <td class="mono">${esc(new Date(t.started_at).toLocaleTimeString())}</td>
        <td class="mono">${esc(t.duration_ms)} ms</td>
        <td>${esc(t.detail)}</td>
      </tr>`
    )
    .join("");
  const m = c.metrics;
  $("#view-timeline").innerHTML = `
    <table><thead><tr><th>#</th><th>Stage</th><th>Started</th><th>Duration</th><th>Detail</th></tr></thead>
    <tbody>${rows}</tbody></table>
    <div class="callout" style="margin-top:16px">
      Total <strong>${esc(m.total_ms)} ms</strong> automated vs.
      <strong>${esc(m.baseline_minutes)} min</strong> manual baseline — approximately
      <strong>${esc(Math.round(m.minutes_saved))} minutes saved</strong> on this case.
    </div>`;
}

function renderReport(c) {
  $("#view-report").innerHTML = `
    <div class="copybar">
      <button class="ghost" id="copy-report">Copy Markdown</button>
      <a class="ghost" style="text-decoration:none;padding:6px 10px;border:1px solid var(--border);border-radius:8px;font-size:12px;color:var(--muted)"
         href="/api/cases/${encodeURIComponent(c.id)}/report" target="_blank" rel="noopener">Open raw</a>
    </div>
    <article class="md">${md(c.report_markdown)}</article>`;
  $("#copy-report").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(c.report_markdown);
      $("#copy-report").textContent = "Copied ✓";
      setTimeout(() => ($("#copy-report").textContent = "Copy Markdown"), 1500);
    } catch (_) { /* clipboard unavailable */ }
  });
}

function renderNotify(c) {
  const n = c.notification || {};
  $("#view-notify").innerHTML = `
    <div class="copybar"><button class="ghost" id="copy-notify">Copy notification</button></div>
    <div class="email-preview">
      <div class="subj">${esc(n.subject || "")}<span class="to">To: ${esc(n.to || "recipient")}</span></div>
      <pre>${esc(n.body || "")}</pre>
    </div>
    <p class="hint">Template written in plain language for the recipient. Adjust the sender address before sending.</p>`;
  $("#copy-notify").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(`${n.subject}\n\n${n.body}`);
      $("#copy-notify").textContent = "Copied ✓";
      setTimeout(() => ($("#copy-notify").textContent = "Copy notification"), 1500);
    } catch (_) { /* clipboard unavailable */ }
  });
}

function showView(view) {
  state.view = view;
  $$("#result-tabs .tab").forEach((b) => b.classList.toggle("active", b.dataset.view === view));
  $$(".view").forEach((v) => (v.hidden = v.dataset.view !== view));
}

/* ---------- wiring ---------- */
function init() {
  bindTabs($("#intake-tabs"), (btn) => {
    $$(".pane-body").forEach((p) => (p.hidden = p.dataset.pane !== btn.dataset.pane));
  });
  bindTabs($("#result-tabs"), (btn) => showView(btn.dataset.view));

  const fileInput = $("#file-input");
  fileInput.addEventListener("change", () => runUpload(fileInput.files[0]));

  const dz = $("#dropzone");
  ["dragenter", "dragover"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("drag"); })
  );
  ["dragleave", "drop"].forEach((ev) =>
    dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("drag"); })
  );
  dz.addEventListener("drop", (e) => runUpload(e.dataTransfer.files[0]));

  $("#run-paste").addEventListener("click", runRaw);

  let searchTimer;
  $("#case-search").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { state.search = e.target.value.trim(); loadCases(); }, 250);
  });

  loadStatus();
  loadMetrics();
  loadSamples();
  loadCases();
}

document.addEventListener("DOMContentLoaded", init);
