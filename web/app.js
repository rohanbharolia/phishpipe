/* ==========================================================================
   PhishPipe  -  Enterprise SOC Threat Reasoning Console
   Autonomous Phishing Triage & Explainable Investigation Client Logic
   ========================================================================== */

const state = {
  view: "summary",         // Active investigation view tab
  emailView: "plain",      // Sub-tab inside email inspector: 'plain' | 'html' | 'hops' | 'links'
  queueMode: "cases",      // Sidebar queue mode: 'cases' | 'campaigns'
  case: null,              // Active selected case object
  cases: [],               // Loaded list of cases
  campaigns: [],           // Loaded threat campaigns
  samples: [],             // Available test email scenarios
  statusFilter: "all",     // Case filter: 'all' | 'true_positive' | 'suspicious' | 'false_positive'
  signalFilter: "all",     // Signal filter: 'all' | 'matched' | 'high'
  searchQuery: "",         // Current search query in case queue
  loading: false,
};

const CLS_MAP = {
  true_positive:  { label: "Confirmed Phish (TP)",  color: "var(--sev-critical)", class: "badge-tp" },
  suspicious:     { label: "Suspicious Lure",       color: "var(--sev-medium)", class: "badge-su" },
  false_positive: { label: "Legitimate / Benign",   color: "var(--sev-low)", class: "badge-fp" },
};

const SEV_COLORS = {
  critical: "var(--sev-critical)",
  high:     "var(--sev-high)",
  medium:   "var(--sev-medium)",
  low:      "var(--sev-low)",
  info:     "var(--sev-info)",
};

/* ---------- DOM Helpers ---------- */
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

function esc(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function defang(val) {
  if (!val) return "";
  return String(val)
    .replace(/https?:\/\//gi, (m) => m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://")
    .replace(/\./g, "[.]")
    .replace(/@/g, "[at]");
}

function undefang(val) {
  if (!val) return "";
  return String(val)
    .replace(/hxxps?:\/\//gi, (m) => m.toLowerCase().startsWith("hxxps") ? "https://" : "http://")
    .replace(/\[\.\]/g, ".")
    .replace(/\[at\]/g, "@");
}

/* ---------- Network API Wrapper ---------- */
async function api(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const err = await res.json();
      detail = err.detail || JSON.stringify(err);
    } catch (_) {}
    throw new Error(detail);
  }
  return res.json();
}

/* ---------- Toasts & Notifications ---------- */
function showToast(msg, type = "info") {
  const container = $("#toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `soc-toast toast-${type}`;
  const icon = type === "success" ? "" : type === "error" ? "!" : "i";
  toast.innerHTML = `<span style="font-weight:700;font-size:1rem;">${icon}</span><span>${esc(msg)}</span>`;
  container.appendChild(toast);

  setTimeout(() => {
    toast.style.transition = "opacity 0.4s ease, transform 0.4s ease";
    toast.style.opacity = "0";
    toast.style.transform = "translateX(50px)";
    setTimeout(() => toast.remove(), 400);
  }, 3400);
}

/* ---------- Modal Dialog ---------- */
function showConfirm(title, desc, onConfirm) {
  const modal = $("#confirm-modal");
  if (!modal) return;
  $("#modal-title").textContent = title;
  $("#modal-desc").textContent = desc;
  modal.hidden = false;
  modal.style.display = "flex";

  const cancelBtn = $("#modal-btn-cancel");
  const confirmBtn = $("#modal-btn-confirm");

  const cleanup = () => {
    modal.hidden = true;
    modal.style.display = "none";
    cancelBtn.onclick = null;
    confirmBtn.onclick = null;
  };

  cancelBtn.onclick = cleanup;
  confirmBtn.onclick = () => {
    cleanup();
    onConfirm();
  };
}

/* ---------- Lightweight Safe Markdown Renderer ---------- */
function renderMarkdown(src) {
  if (!src) return "";
  const lines = src.split("\n");
  const out = [];
  let inCode = false;
  let inList = false;
  let inTable = false;

  const closeList = () => {
    if (inList) { out.push("</ul>"); inList = false; }
  };
  const closeTable = () => {
    if (inTable) { out.push("</tbody></table></div>"); inTable = false; }
  };

  const inline = (s) =>
    esc(s)
      .replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>")
      .replace(/\*(.+?)\*/g, "<em>$1</em>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\[([^\]]+)\]\((https?:\/\/[^\)]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');

  for (const raw of lines) {
    const line = raw.trimEnd();

    // Code blocks
    if (line.startsWith("```")) {
      closeList();
      closeTable();
      if (!inCode) {
        inCode = true;
        const lang = line.slice(3).trim();
        out.push(`<pre><code class="lang-${esc(lang)}">`);
      } else {
        inCode = false;
        out.push("</code></pre>");
      }
      continue;
    }
    if (inCode) {
      out.push(esc(raw) + "\n");
      continue;
    }

    // Horizontal Rule
    if (/^(\-\-\-|\*\*\*|___)$/.test(line.trim())) {
      closeList();
      closeTable();
      out.push("<hr style='border:none;border-top:1px solid var(--border-subtle);margin:16px 0;'/>");
      continue;
    }

    // Tables
    if (line.startsWith("|") && line.endsWith("|")) {
      closeList();
      if (!inTable) {
        inTable = true;
        out.push('<div class="cyber-table-container"><table class="cyber-table"><thead>');
        const cells = line.split("|").slice(1, -1).map((c) => `<th>${inline(c.trim())}</th>`).join("");
        out.push(`<tr>${cells}</tr></thead><tbody>`);
        continue;
      }
      // Delimiter row
      if (/^\|[\s:\-\s\|]+\|$/.test(line)) continue;
      const cells = line.split("|").slice(1, -1).map((c) => `<td>${inline(c.trim())}</td>`).join("");
      out.push(`<tr>${cells}</tr>`);
      continue;
    } else {
      closeTable();
    }

    // Headings
    if (line.startsWith("### ")) {
      closeList();
      out.push(`<h3>${inline(line.slice(4))}</h3>`);
      continue;
    }
    if (line.startsWith("## ")) {
      closeList();
      out.push(`<h2>${inline(line.slice(3))}</h2>`);
      continue;
    }
    if (line.startsWith("# ")) {
      closeList();
      out.push(`<h1>${inline(line.slice(2))}</h1>`);
      continue;
    }

    // Lists
    if (/^[\*\-]\s+/.test(line)) {
      if (!inList) { out.push("<ul>"); inList = true; }
      out.push(`<li>${inline(line.replace(/^[\*\-]\s+/, ""))}</li>`);
      continue;
    }
    if (/^\d+\.\s+/.test(line)) {
      if (!inList) { out.push("<ol>"); inList = true; }
      out.push(`<li>${inline(line.replace(/^\d+\.\s+/, ""))}</li>`);
      continue;
    }
    closeList();

    // Empty lines
    if (!line.trim()) {
      continue;
    }

    out.push(`<p>${inline(line)}</p>`);
  }

  closeList();
  closeTable();
  return out.join("");
}

/* ---------- Engine Metadata & Status Telemetry ---------- */
async function loadStatus() {
  try {
    const s = await api("/api/status");
    const modeBadge = $("#badge-mode");
    const activeLive = s.providers.filter((p) => p.available && p.name !== "offline");

    if (s.offline_mode || activeLive.length === 0) {
      modeBadge.textContent = "AIR-GAPPED (HEURISTICS)";
    } else {
      modeBadge.textContent = `LIVE INTEL (${activeLive.map((p) => p.name.toUpperCase()).join("/")})`;
    }

    $("#badge-detections").textContent = `${s.detections.signal_count} SIGNALS`;
    $("#badge-llm").textContent = s.llm.enabled ? `LLM (${s.llm.model})` : "DETERMINISTIC";
    $("#badge-cases").textContent = `${s.cases} CASES`;
    $("#case-count").textContent = s.cases;
  } catch (err) {
    console.warn("Could not fetch /api/status:", err);
  }
}

/* ---------- Metrics Ribbon ---------- */
async function loadMetrics() {
  try {
    const m = await api("/api/metrics");
    $("#metric-total").textContent = m.total_cases || 0;
    $("#metric-threats").textContent =
      (m.by_classification && m.by_classification.true_positive) || 0;
    $("#metric-latency").textContent = `${Math.round(m.avg_processing_ms || 0)} ms`;
    $("#metric-escalations").textContent = m.needs_human_review || 0;
    $("#metric-saved").textContent = `${Math.round(m.minutes_saved || 0)} min`;
    $("#case-count").textContent = m.total_cases || 0;
    $("#badge-cases").textContent = `${m.total_cases || 0} CASES`;
  } catch (err) {
    console.warn("Could not fetch /api/metrics:", err);
  }
}

/* ---------- Samples Loader ---------- */
async function loadSamples() {
  try {
    const list = await api("/api/samples");
    state.samples = list;

    const renderCard = (s) => {
      let tag = "Scenario";
      if (s.name.includes("m365")) {
        tag = "Credential Phish";
      } else if (s.name.includes("dhl")) {
        tag = "Suspicious Lure";
      } else if (s.name.includes("invoice")) {
        tag = "Malware Attachment";
      } else if (s.name.includes("legit")) {
        tag = "Legitimate Internal";
      }

      return `
        <div class="sample-run-badge" data-sample="${esc(s.name)}">
          <div class="sample-meta-group">
            <span class="sample-label-bold">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted);flex-shrink:0;"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
              ${esc(s.name.replace(/\.(eml|msg|txt)$/i, "").replace(/_/g, " "))}
            </span>
            <span class="sample-sub-tag">${esc(tag)} &bull; ${(s.size / 1024).toFixed(1)} KB</span>
          </div>
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted);"><polyline points="9 18 15 12 9 6"/></svg>
        </div>
      `;
    };

    // Populate Sidebar Samples Tab
    const sampleListEl = $("#sample-list");
    if (sampleListEl) {
      sampleListEl.innerHTML = list.map(renderCard).join("");
      $$("#sample-list .sample-run-badge").forEach((el) => {
        el.onclick = () => runSample(el.dataset.sample);
      });
    }

    // Populate Empty State Scenario Grid
    const emptyGridEl = $("#empty-sample-grid");
    if (emptyGridEl) {
      emptyGridEl.innerHTML = list.map((s) => {
        let title = s.name.replace(/\.(eml|msg|txt)$/i, "").replace(/_/g, " ");
        let desc = "Run autonomous triage pipeline";
        let svgIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>';

        if (s.name.includes("m365")) {
          title = "M365 Credential Harvest";
          desc = "Urgent credential expiration lure with brand spoofing";
          svgIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" ><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
        } else if (s.name.includes("dhl")) {
          title = "DHL Delivery Lure";
          desc = "Fake tracking portal with suspicious TLD redirect";
          svgIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" ><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/></svg>';
        } else if (s.name.includes("invoice")) {
          title = "Malicious Invoice";
          desc = "Invoice archive with dangerous double extension";
          svgIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" ><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>';
        } else if (s.name.includes("legit")) {
          title = "Legitimate IT Notice";
          desc = "Internal scheduled maintenance with aligned SPF/DKIM";
          svgIcon = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" ><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>';
        }

        return `
          <div class="quick-sample-card" data-sample="${esc(s.name)}">
            <span class="prompt-icon">${svgIcon}</span>
            <div class="prompt-info">
              <strong>${esc(title)}</strong>
              <span>${esc(desc)}</span>
            </div>
          </div>
        `;
      }).join("");

      $$("#empty-sample-grid .quick-sample-card").forEach((el) => {
        el.onclick = () => runSample(el.dataset.sample);
      });
    }
  } catch (err) {
    console.warn("Could not fetch /api/samples:", err);
  }
}

/* ---------- Case Queue ---------- */
async function loadCases() {
  try {
    const params = new URLSearchParams({ limit: "100" });
    if (state.statusFilter && state.statusFilter !== "all") {
      params.set("classification", state.statusFilter);
    }
    if (state.searchQuery && state.searchQuery.trim()) {
      params.set("search", state.searchQuery.trim());
    }

    const data = await api(`/api/cases?${params.toString()}`);
    state.cases = data.items || [];
    renderCaseList();
  } catch (err) {
    console.warn("Could not fetch /api/cases:", err);
  }
}

function renderCaseList() {
  const container = $("#case-list");
  if (!container) return;
  const countEl = $("#case-count");
  if (countEl) countEl.textContent = state.cases.length;

  if (state.cases.length === 0) {
    container.innerHTML = `
      <div style="padding:28px 16px;text-align:center;color:var(--text-muted);font-size:0.75rem;">
        No cases match current filter criteria.
      </div>
    `;
    return;
  }

  container.innerHTML = state.cases
    .map((c) => {
      const cls = CLS_MAP[c.classification] || { label: c.classification, color: "#fff", class: "" };
      const isActive = state.case && state.case.id === c.id;
      const timeAgo = formatTimeAgo(c.created_at);
      const conf = c.confidence ?? c.score ?? 0;
      const sender = c.sender || c.from_address || "unknown sender";
      const subject = c.subject || c.title || "(no subject)";

      return `
        <div class="case-item-clean ${isActive ? "active" : ""}" data-id="${esc(c.id)}">
          <div class="case-header-row">
            <span class="case-id-txt">${esc(c.id)}</span>
            <span class="case-badge-meta ${cls.class}">${esc(cls.label)}</span>
          </div>
          <div class="case-subject-line" title="${esc(subject)}">
            ${esc(subject)}
          </div>
          <div class="case-sender-snippet" title="${esc(sender)}">
            ${esc(sender)}
          </div>
          <div class="case-footer-row">
            <span>${timeAgo}</span>
            <div style="display:flex;align-items:center;gap:6px;">
              <span style="font-size:0.65rem;color:var(--text-muted);font-family:var(--font-mono);text-transform:uppercase;">${esc(c.status || "new")}</span>
              <span class="case-score-chip">
                Score: ${conf}/100
              </span>
            </div>
          </div>
        </div>
      `;
    })
    .join("");

  $$("#case-list .case-item-clean").forEach((el) => {
    el.onclick = () => openCase(el.dataset.id);
  });
}

/* ---------- Threat Campaigns Clustering ---------- */
async function loadCampaigns() {
  try {
    const data = await api("/api/campaigns");
    state.campaigns = data.campaigns || [];
    $("#camp-count").textContent = state.campaigns.length;
    renderCampaignList();
  } catch (err) {
    console.warn("Could not fetch /api/campaigns:", err);
  }
}

function renderCampaignList() {
  const container = $("#campaign-list");
  if (!container) return;

  if (state.campaigns.length === 0) {
    container.innerHTML = `
      <div style="padding:28px 16px;text-align:center;color:var(--text-muted);font-size:0.75rem;">
        No threat campaign clusters formed yet.
      </div>
    `;
    return;
  }

  container.innerHTML = state.campaigns.map((camp) => {
    const sevColor = SEV_COLORS[camp.severity] || "#38bdf8";
    return `
      <div class="campaign-card" data-key="${esc(camp.cluster_key)}">
        <div class="campaign-name" title="${esc(camp.name)}">
          ${esc(camp.name)}
        </div>
        <div class="campaign-stats-row">
          <span>${camp.case_count} incident(s)</span>
          ${camp.true_positives > 0 ? `<span class="campaign-tp-pill">${camp.true_positives} Confirmed TP</span>` : ""}
          <span style="font-weight:600;font-family:var(--font-mono);text-transform:uppercase;">${esc(camp.severity)}</span>
        </div>
      </div>
    `;
  }).join("");

  $$("#campaign-list .campaign-card").forEach((card) => {
    card.onclick = () => {
      const key = card.dataset.key;
      const cleanKey = key.replace(/^subject:/, "");
      state.searchQuery = cleanKey;
      const searchInput = $("#case-search");
      if (searchInput) searchInput.value = cleanKey;

      // Switch view back to cases
      state.queueMode = "cases";
      $("#btn-mode-cases").classList.add("active");
      $("#btn-mode-campaigns").classList.remove("active");
      $("#case-list").hidden = false;
      $("#campaign-list").hidden = true;

      loadCases();
      showToast(`Filtered queue for campaign: ${cleanKey}`, "info");
    };
  });
}

function formatTimeAgo(ts) {
  if (!ts) return "recently";
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

async function openCase(caseId) {
  try {
    showProgress("Fetching incident forensic record...");
    const c = await api(`/api/cases/${encodeURIComponent(caseId)}`);
    renderCase(c);
    renderCaseList(); // Update active highlight in queue
  } catch (err) {
    showError(`Failed to load case: ${err.message}`);
  } finally {
    hideProgress();
  }
}

/* ---------- Investigation Execution Handlers ---------- */
function showProgress(msg = "Running pipeline stages...") {
  const p = $("#progress");
  const l = $("#progress-label");
  if (p && l) {
    l.textContent = msg;
    p.hidden = false;
  }
  state.loading = true;
}

function hideProgress() {
  const p = $("#progress");
  if (p) p.hidden = true;
  state.loading = false;
}

function showError(msg) {
  const box = $("#error-box");
  if (box) {
    box.textContent = msg;
    box.hidden = false;
  }
  showToast(msg, "error");
}

async function runUpload(file) {
  if (!file) return;
  const form = new FormData();
  form.append("file", file);

  try {
    showProgress(`Ingesting & investigating ${file.name}...`);
    const c = await api("/api/investigate/upload", {
      method: "POST",
      headers: {}, // Let browser set multipart boundary
      body: form,
    });
    showToast(`Investigation ${c.id} completed!`, "success");
    await Promise.all([loadCases(), loadCampaigns(), loadMetrics(), loadStatus()]);
    renderCase(c);
  } catch (err) {
    showError(`Upload investigation failed: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function runRaw() {
  const input = $("#raw-input");
  const raw = (input ? input.value : "").trim();
  if (!raw) {
    showError("Please paste raw RFC 5322 email headers and body.");
    return;
  }

  try {
    showProgress("Forensically parsing raw RFC message...");
    const c = await api("/api/investigate/raw", {
      method: "POST",
      body: JSON.stringify({ raw_email: raw }),
    });
    showToast(`Investigation ${c.id} completed!`, "success");
    if (input) input.value = "";
    await Promise.all([loadCases(), loadCampaigns(), loadMetrics(), loadStatus()]);
    renderCase(c);
  } catch (err) {
    showError(`Raw parse failed: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function runSample(name) {
  try {
    showProgress(`Running scenario: ${name}...`);
    const c = await api(`/api/investigate/sample/${encodeURIComponent(name)}`, {
      method: "POST",
    });
    showToast(`Investigation ${c.id} generated!`, "success");
    await Promise.all([loadCases(), loadCampaigns(), loadMetrics(), loadStatus()]);
    renderCase(c);
  } catch (err) {
    showError(`Sample investigation failed: ${err.message}`);
  } finally {
    hideProgress();
  }
}

/* ---------- Case Investigation Rendering ---------- */
function renderGauge(confidence, color) {
  const radius = 48;
  const circ = 2 * Math.PI * radius;
  const pct = Math.max(0, Math.min(100, Math.round(confidence || 0)));
  const offset = circ - (pct / 100) * circ;

  return `
    <div class="gauge-wrapper">
      <svg class="gauge-svg" viewBox="0 0 120 120">
        <circle class="gauge-bg-ring" cx="60" cy="60" r="${radius}" />
        <circle class="gauge-fill-ring" cx="60" cy="60" r="${radius}"
          stroke="${color}"
          stroke-dasharray="${circ}"
          stroke-dashoffset="${offset}"
           />
      </svg>
      <div class="gauge-score-center">
        <span class="gauge-score-num" style="color:${color}">${pct}%</span>
        <span class="gauge-score-label">Confidence</span>
      </div>
    </div>
  `;
}

function renderCase(c) {
  state.case = c;
  $("#empty-state").hidden = true;
  $("#case-view").hidden = false;
  $("#error-box").hidden = true;

  const v = c.verdict;
  const clsData = CLS_MAP[v.classification] || { label: v.classification, color: "#38bdf8" };
  const sevColor = SEV_COLORS[v.severity] || clsData.color;

  // A benign / false-positive message has nothing to reset, so every
  // credential-reset affordance stays hidden unless this is a real phish.
  const isBenign = v.classification === "false_positive";

  // Toolbar
  $("#toolbar-case-id").textContent = c.id;
  $("#toolbar-timestamp").textContent = `Ingested: ${new Date(c.created_at || Date.now()).toLocaleString()}`;

  // Interactive Case Status Selector
  const curStatus = c.status || "new";
  const statusGroupHtml = `
    <div class="status-workflow-group" title="Update Triage Status">
      <button class="status-wf-btn ${curStatus === "new" ? "active" : ""}" data-st="new">New</button>
      <button class="status-wf-btn ${curStatus === "triaged" ? "active" : ""}" data-st="triaged">Triaged</button>
      <button class="status-wf-btn ${curStatus === "escalated" ? "active" : ""}" data-st="escalated">Escalated</button>
      <button class="status-wf-btn ${curStatus === "closed" ? "active" : ""}" data-st="closed">Closed</button>
    </div>
  `;
  const leftToolbar = $(".toolbar-left");
  const existingWf = leftToolbar.querySelector(".status-workflow-group");
  if (existingWf) existingWf.remove();
  leftToolbar.insertAdjacentHTML("beforeend", statusGroupHtml);

  // Wire status update buttons
  $$(".status-wf-btn").forEach((btn) => {
    btn.onclick = async () => {
      const newStatus = btn.dataset.st;
      if (newStatus === state.case.status) return;
      try {
        await api(`/api/cases/${encodeURIComponent(state.case.id)}/status`, {
          method: "PATCH",
          body: JSON.stringify({ status: newStatus }),
        });
        state.case.status = newStatus;
        $$(".status-wf-btn").forEach((b) => b.classList.toggle("active", b.dataset.st === newStatus));
        showToast(`Case ${state.case.id} marked as ${newStatus.toUpperCase()}`, "success");
        await Promise.all([loadCases(), loadMetrics()]);
      } catch (err) {
        showError(`Could not update status: ${err.message}`);
      }
    };
  });

  // MITRE ATT&CK Matrix strip
  const mitreHtml = (v.mitre || []).length
    ? `<div class="mitre-matrix-strip">
         <span class="mitre-label">MITRE ATT&amp;CK:</span>
         ${v.mitre.map((m) => `
           <a href="https://attack.mitre.org/techniques/${encodeURIComponent(m.id.replace(/\./g, "/"))}/"
              target="_blank" rel="noopener" class="mitre-badge"
              title="${esc(m.tactic)}: ${esc(m.name)}">
             ${esc(m.id)} &bull; ${esc(m.name)}
           </a>
         `).join("")}
       </div>`
    : "";

  const clickTelemetry = c.click_telemetry || {};
  const hasClick = Boolean(clickTelemetry.has_positive_click || (clickTelemetry.events && clickTelemetry.events.length > 0));
  const credsCompromised = Boolean(clickTelemetry.credentials_compromised || (clickTelemetry.events && clickTelemetry.events.some((e) => e.credentials_submitted)));
  const clickCount = clickTelemetry.click_count || (clickTelemetry.events ? clickTelemetry.events.length : 0);

  // Credential reset is offered ONLY where gateway telemetry actually confirmed
  // a positive click -- and never on a benign verdict. Everything else has no
  // credentials to reset.
  const showCredReset = hasClick && !isBenign;
  const btnResetCreds = $("#btn-action-reset");
  if (btnResetCreds) btnResetCreds.style.display = showCredReset ? "" : "none";

  const clickBannerHtml = showCredReset ? `
    <div class="positive-click-alert-strip">
      <div class="pca-left">
        <div class="pca-icon">
          <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
        </div>
        <div class="pca-info">
          <div class="pca-heading">
            <span>CRITICAL: POSITIVE USER CLICK CONFIRMED</span>
            ${credsCompromised ? '<span class="badge-creds-compromised">CREDENTIALS COMPROMISED</span>' : '<span class="badge-link-clicked">PAYLOAD VISITED</span>'}
          </div>
          <div class="pca-sub">
            Gateway telemetry confirms recipient traversed phishing payload (${clickCount} event${clickCount > 1 ? 's' : ''} recorded). Case automatically escalated to <strong>CRITICAL</strong>. Immediate tenant containment playbooks activated.
          </div>
        </div>
      </div>
      <div class="pca-actions">
        <button class="btn-danger-sm" onclick="confirmAndExecuteAction('reset_credentials', 'Reset User Credentials')">Emergency Creds Reset</button>
      </div>
    </div>
  ` : "";

  // Verdict Hero Card
  $("#verdict-hero").innerHTML = `
    ${clickBannerHtml}
    <div class="verdict-hero-body">
      ${renderGauge(v.confidence, sevColor)}
      <div class="verdict-details-col">
      <div class="verdict-classification-badge" style="color:${sevColor}">
        <span class="pulse-dot" style="background:${sevColor};"></span>
        <span>${clsData.label}</span>
      </div>
      <h2 class="verdict-title">${esc(c.title || c.email.subject || "Phishing Investigation")}</h2>
      <div class="verdict-pills-row">
        <span class="v-pill">Severity: <span class="v-pill-val" style="color:${sevColor}">${esc(v.severity.toUpperCase())}</span></span>
        <span class="v-pill">Signals: <span class="v-pill-val">${esc(v.signals_matched)}/${esc(v.signals_total || 37)} fired</span></span>
        <span class="v-pill">Latency: <span class="v-pill-val">${esc(c.metrics?.total_ms || 25)} ms</span></span>
        <span class="v-pill">Engine: <span class="v-pill-val">${c.metrics.offline ? "Air-Gapped Local" : "Live Threat Feed"}</span></span>
        ${v.needs_human_review ? `<span class="v-pill v-pill-warn">Escalation Required</span>` : ""}
      </div>
      ${mitreHtml}
      <div class="verdict-explanation-box">
        <strong>Executive Assessment:</strong> ${esc(v.explanation)}
      </div>
    </div>
  `;

  // Render subviews
  renderSummaryView(c);
  renderEmailView(c);
  renderSignalsView(c);
  renderIocsView(c);
  renderEnrichmentView(c);
  renderTimelineView(c);
  renderReportView(c);
  renderNotifyView(c);
  renderNotesView(c);

  showView(state.view);
}

function showView(viewName) {
  state.view = viewName;
  $$("#result-tabs .view-tab").forEach((btn) => {
    const isTarget = btn.dataset.view === viewName;
    btn.classList.toggle("active", isTarget);
    btn.setAttribute("aria-selected", isTarget ? "true" : "false");
  });
  $$(".view-panel").forEach((panel) => {
    const isTarget = panel.dataset.view === viewName;
    if (isTarget) {
      panel.removeAttribute("hidden");
      panel.classList.add("active");
      panel.style.display = "flex";
    } else {
      panel.setAttribute("hidden", "");
      panel.classList.remove("active");
      panel.style.display = "none";
    }
  });
}

/* View 1: Summary & Actions */
function renderSummaryView(c) {
  const v = c.verdict;
  const auth = c.email.auth_results || {};

  const reasons = (v.reasoning || []).map((r) => `<li class="reasoning-item">${esc(r)}</li>`).join("");
  // Fallback checklist for verdicts that carry no actions. A credential reset
  // is only offered when telemetry confirmed a positive click.
  const ct = c.click_telemetry || {};
  const clickObserved = Boolean(
    ct.has_positive_click || (ct.events && ct.events.length > 0)
  );
  const fallbackActions = v.classification === "false_positive"
    ? [
        "Record as a false positive and close the case with the evidence attached.",
        "No user notification required unless the recipient reported it.",
      ]
    : [
        "Quarantine email across all tenant mailboxes",
        "Block identified domains and URLs at Secure Web Gateway",
        ...(clickObserved
          ? ["Force credential reset and revoke active sessions for targeted user"]
          : []),
      ];
  const actions = (v.recommended_actions || fallbackActions).map((a) => `
    <li class="action-check-item">
      <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
      <span>${esc(a)}</span>
    </li>
  `).join("");

  const quishingAlert = c.quishing ? `
    <div class="quishing-alert-banner" style="background:rgba(239,68,68,0.12); border:1px solid rgba(239,68,68,0.35); border-radius:6px; padding:12px 16px; margin-bottom:16px; display:flex; align-items:center; gap:12px;">
      <span style="font-size:1.4rem;">📱</span>
      <div>
        <div style="font-weight:700; color:#fca5a5; font-size:0.82rem; text-transform:uppercase; letter-spacing:0.04em;">QR Code Phishing (Quishing) Lure Detected</div>
        <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:2px;">${esc(c.quishing.summary || c.quishing.evidence)}</div>
      </div>
    </div>
  ` : "";

  const typosquatAlert = (c.typosquatting && c.typosquatting.length > 0) ? `
    <div class="typosquat-alert-banner" style="background:rgba(234,179,8,0.12); border:1px solid rgba(234,179,8,0.35); border-radius:6px; padding:12px 16px; margin-bottom:16px; display:flex; align-items:center; gap:12px;">
      <span style="font-size:1.4rem;">🎭</span>
      <div>
        <div style="font-weight:700; color:#fde047; font-size:0.82rem; text-transform:uppercase; letter-spacing:0.04em;">Brand Lookalike / Typosquatting Detected</div>
        <div style="font-size:0.75rem; color:var(--text-secondary); margin-top:2px;">
          ${c.typosquatting.map((t) => `Domain <code>${esc(t.domain)}</code> targets protected brand <strong>${esc(t.brand).toUpperCase()}</strong> (${esc(t.type)})`).join("<br>")}
        </div>
      </div>
    </div>
  ` : "";

  $("#view-summary").innerHTML = `
    ${quishingAlert}
    ${typosquatAlert}
    <div class="grid-2col">
      <div class="panel-sub-card">
        <h3>
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
          Why This Verdict Was Reached
        </h3>
        <ul class="reasoning-list">${reasons || "<li class='reasoning-item'>No critical risk indicators observed.</li>"}</ul>
      </div>

      <div class="panel-sub-card">
        <h3>
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
          Recommended Incident Playbook
        </h3>
        <ul class="action-check-list">${actions}</ul>
      </div>
    </div>

    <div class="panel-sub-card" style="margin-top:20px;">
      <h3>
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Perimeter Authentication Verification (SPF / DKIM / DMARC)
      </h3>
      <div class="auth-badges-grid">
        <div class="auth-card ${auth.spf === 'pass' ? 'pass' : (auth.spf ? 'fail' : 'neutral')}">
          <span class="auth-title-bold">SPF Record</span>
          <span class="auth-val-badge">${esc(auth.spf || "Not Evaluated")}</span>
        </div>
        <div class="auth-card ${auth.dkim === 'pass' ? 'pass' : (auth.dkim ? 'fail' : 'neutral')}">
          <span class="auth-title-bold">DKIM Signature</span>
          <span class="auth-val-badge">${esc(auth.dkim || "Not Evaluated")}</span>
        </div>
        <div class="auth-card ${auth.dmarc === 'pass' ? 'pass' : (auth.dmarc ? 'fail' : 'neutral')}">
          <span class="auth-title-bold">DMARC Alignment</span>
          <span class="auth-val-badge">${esc(auth.dmarc || "Not Evaluated")}</span>
        </div>
      </div>
    </div>

    <div class="panel-sub-card" style="margin-top:20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
        <h3 style="margin:0;">
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M10 14L21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>
          Time-of-Click Gateway Forensics &amp; Positive Confirmation Telemetry
        </h3>
        <button class="btn-playbook action-click" onclick="openClickModal()" title="Correlate or simulate gateway click event">
          <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M10 14L21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>
          <span>Verify / Register Click</span>
        </button>
      </div>
      ${(c.click_telemetry && c.click_telemetry.events && c.click_telemetry.events.length > 0) ? `
        <div class="click-telemetry-table-wrapper">
          <table class="click-telemetry-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Target URL (Defanged)</th>
                <th>Target User</th>
                <th>Client IP</th>
                <th>Gateway Outcome</th>
                <th>Credentials Status</th>
                <th>Telemetry Source</th>
              </tr>
            </thead>
            <tbody>
              ${c.click_telemetry.events.map((evt) => `
                <tr>
                  <td style="font-family:var(--font-mono); font-size:0.68rem; color:var(--text-muted); white-space:nowrap;">${esc(new Date(evt.timestamp).toLocaleString())}</td>
                  <td style="font-family:var(--font-mono); font-size:0.70rem; color:var(--accent-primary); word-break:break-all;">${esc(defang(evt.url))}</td>
                  <td style="font-size:0.72rem; color:var(--text-primary);">${esc(evt.user_email || "Target Recipient")}</td>
                  <td style="font-family:var(--font-mono); font-size:0.70rem; color:var(--text-muted);">${esc(evt.client_ip || "unknown")}</td>
                  <td><span class="click-outcome-pill click-outcome-${esc(evt.outcome)}">${esc(evt.outcome)}</span></td>
                  <td>${evt.credentials_submitted ? '<span class="badge-creds-compromised" style="font-size:0.6rem;">YES - COMPROMISED</span>' : '<span style="color:var(--text-muted); font-size:0.68rem;">Not Submitted</span>'}</td>
                  <td style="font-size:0.68rem; color:var(--text-muted);">${esc(evt.source || "web_proxy")}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : `
        <div style="padding:14px 16px; margin-top:10px; background:#060910; border:1px solid var(--border-subtle); border-radius:var(--radius-sm); font-size:0.73rem; color:var(--text-muted); display:flex; align-items:center; justify-content:space-between; gap:12px;">
          <span>No user click telemetry recorded yet. If the recipient clicked or navigated to any link in this email, click <strong>Verify / Register Click</strong> to register gateway telemetry and trigger automated incident escalation.</span>
        </div>
      `}
    </div>
  `;
}

/* View 2: Email Inspector & Forensic Deep Dive */
function renderEmailView(c) {
  const e = c.email;

  const fromDomain = (e.from_address || "").split("@")[1] || "";
  const returnDomain = (e.return_path || "").split("@")[1] || "";
  const isMismatched = returnDomain && fromDomain && fromDomain.toLowerCase() !== returnDomain.toLowerCase();

  const attachmentsRows = (e.attachments || []).map((a) => `
    <tr>
      <td><strong>${esc(a.filename)}</strong></td>
      <td>${esc(a.content_type)}</td>
      <td class="num-cell">${(a.size_bytes / 1024).toFixed(1)} KB</td>
      <td class="mono-cell defanged-token">${esc(a.sha256 || " - ")}</td>
      <td>
        <button class="btn-ioc-tool" onclick="copyText('${esc(a.sha256)}')">Copy SHA256</button>
      </td>
    </tr>
  `).join("");

  // Prepare safe sandboxed HTML if available
  const hasHtml = Boolean(e.body_html && e.body_html.trim());
  const safePlainText = defang(e.body_plain || e.body_html || "(Empty email body)");

  // 1. Mail Relay Hops Trace HTML
  const chain = c.received_chain || { hops: [] };
  const hopsList = (chain.hops || []).map((h, i) => {
    const isFirst = i === 0;
    const isLast = i === chain.hops.length - 1;
    return `
      <div class="hop-item-node ${isFirst ? 'first-hop' : ''} ${isLast ? 'last-hop' : ''}">
        <div class="hop-card-body">
          <div class="hop-card-top">
            <span class="hop-step-badge">Hop #${i + 1} ${isFirst ? '(ORIGIN)' : isLast ? '(INTERNAL GATEWAY)' : ''}</span>
            ${h.ip ? `<span class="hop-ip-tag">${esc(h.ip)}</span>` : ''}
          </div>
          <div class="hop-relay-details">
            <div><strong>From:</strong> <code>${esc(h.from_host || 'N/A')}</code></div>
            <div><strong>By:</strong> <code>${esc(h.by_host || 'N/A')}</code></div>
            <div><strong>Protocol:</strong> <span>${esc(h.with_protocol || 'SMTP')}</span></div>
            <div><strong>Timestamp:</strong> <span>${esc(h.timestamp || 'N/A')}</span></div>
          </div>
          ${h.raw ? `<div class="hop-raw-snippet" title="Raw Received Header">${esc(h.raw)}</div>` : ''}
        </div>
      </div>
    `;
  }).join("");

  // 2. Links & Anchor Mismatch Matrix HTML
  const linkRows = (c.links || []).map((l) => {
    const defangedUrl = defang(l.url);
    const riskBadges = [];
    if (l.typosquatting) riskBadges.push(`<span class="link-matrix-badge badge-mismatch-alert">LOOKALIKE: ${esc((l.typosquatting.brand || 'BRAND')).toUpperCase()}</span>`);
    if (l.mismatched) riskBadges.push(`<span class="link-matrix-badge badge-mismatch-alert">MISMATCH</span>`);
    if (l.is_ip_host) riskBadges.push(`<span class="link-matrix-badge badge-risk-flag">IP HOST</span>`);
    if (l.is_suspicious_tld) riskBadges.push(`<span class="link-matrix-badge badge-risk-flag">SUSP TLD</span>`);
    if (l.is_punycode) riskBadges.push(`<span class="link-matrix-badge badge-risk-flag">PUNYCODE</span>`);
    if (l.has_credential_token) riskBadges.push(`<span class="link-matrix-badge badge-risk-flag">AUTH TOKEN</span>`);
    if (l.is_shortener) riskBadges.push(`<span class="link-matrix-badge badge-risk-flag">SHORTENER</span>`);
    if (riskBadges.length === 0) riskBadges.push(`<span class="link-matrix-badge badge-match-clean">CLEAN</span>`);

    return `
      <tr>
        <td style="font-weight:600;color:var(--text-primary);max-width:180px;word-break:break-all;">
          ${esc(l.anchor_text || "(No anchor text / image link)")}
        </td>
        <td>
          <div style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-primary);word-break:break-all;">
            ${esc(defangedUrl)}
          </div>
        </td>
        <td class="mono-cell" style="color:var(--text-secondary);">${esc(l.host || 'unknown')}</td>
        <td><div style="display:flex;flex-wrap:wrap;gap:4px;">${riskBadges.join("")}</div></td>
        <td>
          <div style="display:flex;gap:4px;">
            <button class="btn-ioc-tool" onclick="copyText('${esc(defangedUrl)}')">Copy URL</button>
            <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(l.url)}" target="_blank" rel="noopener" class="btn-ioc-tool">VT</a>
          </div>
        </td>
      </tr>
    `;
  }).join("");

  $("#view-email").innerHTML = `
    <div class="email-inspector-card">
      <div class="email-headers-block">
        <div class="header-row-item">
          <span class="header-key">Subject:</span>
          <span class="header-value"><strong>${esc(e.subject || "(no subject)")}</strong></span>
        </div>
        <div class="header-row-item">
          <span class="header-key">From:</span>
          <span class="header-value">${esc(e.from_display_name ? `"${e.from_display_name}" ` : "")}&lt;${esc(e.from_address)}&gt;</span>
        </div>
        <div class="header-row-item">
          <span class="header-key">Return-Path:</span>
          <span class="header-value">
            &lt;${esc(e.return_path || e.from_address)}&gt;
            ${isMismatched ? `<span class="mismatch-alert-tag">Domain Mismatch (${esc(returnDomain)})</span>` : ""}
          </span>
        </div>
        <div class="header-row-item">
          <span class="header-key">To:</span>
          <span class="header-value">${esc((e.to || []).join(", ") || "undisclosed-recipients")}</span>
        </div>
        <div class="header-row-item">
          <span class="header-key">Date:</span>
          <span class="header-value">${esc(e.date_header || e.date || "Unknown date")}</span>
        </div>
        <div class="header-row-item">
          <span class="header-key">Message-ID:</span>
          <span class="header-value mono-cell">${esc(e.message_id || " - ")}</span>
        </div>
      </div>

      ${attachmentsRows ? `
        <div class="panel-sub-card">
          <h3>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>
            Email Attachments (${e.attachments.length})
          </h3>
          <div class="cyber-table-container">
            <table class="cyber-table">
              <thead><tr><th>Filename</th><th>Content Type</th><th class="num-cell">Size</th><th>SHA-256 Hash</th><th>Action</th></tr></thead>
              <tbody>${attachmentsRows}</tbody>
            </table>
          </div>
        </div>
      ` : ""}

      <div class="email-body-preview-box">
        <div class="email-subnav-bar">
          <button class="email-subnav-btn ${state.emailView === 'plain' ? 'active' : ''}" data-sub="plain">
            Defanged Plaintext
          </button>
          ${hasHtml ? `
            <button class="email-subnav-btn ${state.emailView === 'html' ? 'active' : ''}" data-sub="html">
              Sandboxed Rendered HTML
            </button>
          ` : ""}
          <button class="email-subnav-btn ${state.emailView === 'hops' ? 'active' : ''}" data-sub="hops">
            Mail Routing Hops Trace (${(chain.hops || []).length})
          </button>
          <button class="email-subnav-btn ${state.emailView === 'links' ? 'active' : ''}" data-sub="links">
            Link &amp; Anchor Matrix (${(c.links || []).length})
          </button>
        </div>

        <!-- Subpane 1: Plaintext -->
        <div id="email-view-plain" ${state.emailView === 'plain' ? '' : 'hidden'}>
          <div class="email-plaintext-render">${esc(safePlainText)}</div>
        </div>

        <!-- Subpane 2: HTML Sandbox -->
        ${hasHtml ? `
          <div id="email-view-html" ${state.emailView === 'html' ? '' : 'hidden'}>
            <iframe class="email-html-sandbox-frame" id="email-sandbox-frame" sandbox="allow-same-origin"></iframe>
          </div>
        ` : ""}

        <!-- Subpane 3: Mail Routing Hops Trace -->
        <div id="email-view-hops" ${state.emailView === 'hops' ? '' : 'hidden'}>
          <div class="hops-trace-container">
            <div class="hops-header-summary">
              <div>
                <strong>Routing Chain:</strong> ${chain.hop_count || 0} MTA Hops &bull; Origin IP: <code>${esc(chain.origin_ip || 'N/A')}</code> &bull; Origin HELO: <code>${esc(chain.origin_helo || 'N/A')}</code>
              </div>
              <span style="font-size:0.68rem;color:var(--text-muted);font-family:var(--font-mono);">
                First Ingest: ${esc(chain.first_received || 'N/A')}
              </span>
            </div>
            <div class="hop-timeline">
              ${hopsList || '<div style="padding:14px;color:var(--text-muted);">No Received header hops found in message.</div>'}
            </div>
          </div>
        </div>

        <!-- Subpane 4: Links & Anchor Matrix -->
        <div id="email-view-links" ${state.emailView === 'links' ? '' : 'hidden'}>
          <div style="padding:14px;">
            <div style="margin-bottom:10px;font-size:0.75rem;color:var(--text-muted);">
              Correlates visible anchor text against actual HTTP destination to spot homoglyph lookalikes, punycode tricks, and credential harvester lures.
            </div>
            <div class="cyber-table-container">
              <table class="cyber-table">
                <thead>
                  <tr>
                    <th>Anchor Text Shown</th>
                    <th>Destination URL (Defanged)</th>
                    <th>Destination Host</th>
                    <th>Risk Indicators</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  ${linkRows || '<tr><td colspan="5" style="text-align:center;color:var(--text-muted);">No hyperlinks detected in email.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        </div>

      </div>
    </div>
  `;

  // Wire email inspector sub-tabs
  $$(".email-subnav-btn").forEach((btn) => {
    btn.onclick = () => {
      state.emailView = btn.dataset.sub;
      $$(".email-subnav-btn").forEach((b) => b.classList.toggle("active", b.dataset.sub === state.emailView));
      $("#email-view-plain").hidden = state.emailView !== "plain";
      if ($("#email-view-html")) $("#email-view-html").hidden = state.emailView !== "html";
      $("#email-view-hops").hidden = state.emailView !== "hops";
      $("#email-view-links").hidden = state.emailView !== "links";

      if (state.emailView === "html" && hasHtml) {
        loadSandboxIframe(e.body_html);
      }
    };
  });

  if (state.emailView === "html" && hasHtml) {
    loadSandboxIframe(e.body_html);
  }
}

function loadSandboxIframe(htmlContent) {
  const iframe = $("#email-sandbox-frame");
  if (!iframe) return;
  // Defang links and script tags
  let safeHtml = (htmlContent || "")
    .replace(/<script [^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
    .replace(/href=["'](http[^"']+)["']/gi, 'href="#" title="Defanged link: $1" target="_self"');
  iframe.srcdoc = `<!DOCTYPE html><html><head><meta charset="utf-8"><style>body{font-family:sans-serif;font-size:13px;color:#1e293b;padding:16px;line-height:1.5;}a{color:#0284c7;}</style></head><body>${safeHtml}</body></html>`;
}

/* View 3: Signals Table */
function renderSignalsView(c) {
  let signals = c.signals || [];
  if (state.signalFilter === "matched") {
    signals = signals.filter((s) => s.matched);
  } else if (state.signalFilter === "high") {
    signals = signals.filter((s) => s.severity === "critical" || s.severity === "high");
  }

  const rows = signals.map((s) => `
    <tr>
      <td>
        <span class="mono-cell" style="color:var(--text-primary);font-weight:600;">${esc(s.id)}</span>
      </td>
      <td>
        <strong>${esc(s.title)}</strong>
        <div style="font-size:0.7rem;color:var(--text-muted);margin-top:2px;">${esc(s.description)}</div>
      </td>
      <td>
        ${s.matched ? `<span class="status-badge-match">TRIGGERED</span>` : `<span class="status-badge-no">NOT OBSERVED</span>`}
      </td>
      <td class="num-cell">
        <span class="weight-chip ${s.weight < 0 ? 'weight-neg' : 'weight-pos'}">
          ${s.weight >= 0 ? "+" + s.weight : s.weight}
        </span>
      </td>
      <td>
        <span style="color:${SEV_COLORS[s.severity] || '#fff'};font-weight:700;text-transform:uppercase;font-size:0.68rem;font-family:var(--font-mono);">
          ${esc(s.severity)}
        </span>
      </td>
      <td>
        ${s.matched ? `<span class="defanged-token">${esc(defang(s.evidence))}</span>` : `<span style="color:var(--text-muted);font-size:0.72rem;"> - </span>`}
      </td>
    </tr>
  `).join("");

  $("#view-signals").innerHTML = `
    <div style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
      <div>
        <h3 style="font-size:0.95rem;font-weight:700;">Detection Signals Audit Log (${signals.length} rules)</h3>
        <span style="font-size:0.72rem;color:var(--text-muted);font-family:var(--font-mono);">
          Raw heuristic sum: <strong>${c.verdict.raw_score}</strong> &rarr; Clamped confidence: <strong>${c.verdict.confidence}/100</strong>
        </span>
      </div>
      <div class="filter-chips">
        <button class="filter-chip ${state.signalFilter === 'all' ? 'active' : ''}" data-sfilter="all">All (${(c.signals || []).length})</button>
        <button class="filter-chip ${state.signalFilter === 'matched' ? 'active' : ''}" data-sfilter="matched">Triggered Only (${(c.signals || []).filter(s => s.matched).length})</button>
        <button class="filter-chip ${state.signalFilter === 'high' ? 'active' : ''}" data-sfilter="high">High/Critical</button>
      </div>
    </div>
    <div class="cyber-table-container">
      <table class="cyber-table">
        <thead>
          <tr>
            <th>Signal ID</th>
            <th>Rule Definition</th>
            <th>Trigger Status</th>
            <th class="num-cell">Weight</th>
            <th>Severity</th>
            <th>Forensic Evidence</th>
          </tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="6" style="text-align:center;">No signals match filter.</td></tr>'}</tbody>
      </table>
    </div>
  `;

  // Wire signal filter buttons
  $$("#view-signals .filter-chip").forEach((btn) => {
    btn.onclick = () => {
      state.signalFilter = btn.dataset.sfilter;
      renderSignalsView(c);
    };
  });
}

/* View 4: IOCs & Artifacts */
function renderIocsView(c) {
  let indicators = (c.indicators && c.indicators.length) ? [...c.indicators] : [];
  if (!indicators.length) {
    const seen = new Set();
    const addInd = (type, value, source, context = "") => {
      if (!value || seen.has(type + ":" + value.toLowerCase())) return;
      seen.add(type + ":" + value.toLowerCase());
      indicators.push({
        type,
        value,
        defanged: defang(value),
        source,
        context
      });
    };
    if (c.email) {
      (c.email.urls || []).forEach(u => addInd("url", u, "body", "Extracted URL from message body"));
      (c.email.domains || []).forEach(d => addInd("domain", d, "body", "Extracted domain"));
      if (c.email.from_address) {
        addInd("email", c.email.from_address, "header", "Sender address");
        const parts = c.email.from_address.split("@");
        if (parts.length === 2 && parts[1]) addInd("domain", parts[1], "header", "Sender domain");
      }
      if (c.email.reply_to) addInd("email", c.email.reply_to, "header", "Reply-To address");
      (c.email.attachments || []).forEach(a => {
        if (a.filename) addInd("attachment", a.filename, "attachment", a.content_type || "file");
        if (a.sha256) addInd("hash", a.sha256, "attachment", a.filename || "file hash");
      });
    }
  }

  // Ensure click telemetry events are integrated as IOCs
  if (c.click_telemetry && c.click_telemetry.events) {
    const existingValues = new Set(indicators.map(i => (i.value || "").toLowerCase()));
    c.click_telemetry.events.forEach(evt => {
      if (evt.url && !existingValues.has(evt.url.toLowerCase())) {
        existingValues.add(evt.url.toLowerCase());
        indicators.push({
          type: "url",
          value: evt.url,
          defanged: defang(evt.url),
          source: "click_telemetry",
          context: `Confirmed user click by ${evt.user_email || "user"}`
        });
        try {
          const parsed = new URL(evt.url);
          const d = parsed.hostname;
          if (d && !existingValues.has(d.toLowerCase())) {
            existingValues.add(d.toLowerCase());
            indicators.push({
              type: "domain",
              value: d,
              defanged: defang(d),
              source: "click_telemetry",
              context: `Domain in confirmed user click ${evt.url}`
            });
          }
        } catch (_) {}
      }
      if (evt.client_ip && !existingValues.has(evt.client_ip.toLowerCase())) {
        existingValues.add(evt.client_ip.toLowerCase());
        indicators.push({
          type: "ip",
          value: evt.client_ip,
          defanged: defang(evt.client_ip),
          source: "click_telemetry",
          context: "Client IP recorded by gateway"
        });
      }
    });
  }

  // Sync back to case in memory
  c.indicators = indicators;

  const byType = {};
  for (const i of indicators) (byType[i.type] = byType[i.type] || []).push(i);
  const typeOrder = ["url", "domain", "ip", "email", "hash", "attachment", "phone"];

  const sections = typeOrder
    .filter((t) => byType[t])
    .map((t) => {
      const rows = byType[t].map((i) => {
        const raw = undefang(i.value || i.defanged);
        let pivots = "";

        if (t === "domain" || t === "url") {
          pivots = `
            <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(raw)}" target="_blank" rel="noopener" class="btn-ioc-tool">VT</a>
            <a href="https://urlscan.io/search/#${encodeURIComponent(raw)}" target="_blank" rel="noopener" class="btn-ioc-tool">urlscan</a>
          `;
        } else if (t === "ip") {
          pivots = `
            <a href="https://www.abuseipdb.com/check/${encodeURIComponent(raw)}" target="_blank" rel="noopener" class="btn-ioc-tool">AbuseIPDB</a>
            <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(raw)}" target="_blank" rel="noopener" class="btn-ioc-tool">VT</a>
          `;
        } else if (t === "hash") {
          pivots = `
            <a href="https://www.virustotal.com/gui/search/${encodeURIComponent(raw)}" target="_blank" rel="noopener" class="btn-ioc-tool">VT</a>
          `;
        }

        const defVal = i.defanged || defang(i.value);
        return `
          <tr>
            <td><span class="defanged-token">${esc(defVal)}</span></td>
            <td><span class="v-pill">${esc(i.source)}</span></td>
            <td style="font-size:0.75rem;">${esc(defang(i.context))}</td>
            <td>
              <div class="ioc-actions">
                <button class="btn-ioc-tool" onclick="copyText('${esc(defVal)}')">Copy Defanged</button>
                <button class="btn-ioc-tool" onclick="copyText('${esc(raw)}')">Copy Raw</button>
                ${pivots}
              </div>
            </td>
          </tr>
        `;
      }).join("");

      return `
        <div style="margin-bottom:24px;">
          <h3 style="font-size:0.85rem;font-weight:700;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.04em;color:var(--text-primary);">
            ${esc(t)} Indicators (${byType[t].length})
          </h3>
          <div class="cyber-table-container">
            <table class="cyber-table">
              <thead><tr><th>Indicator (Defanged)</th><th>Source Header</th><th>Extracted Context</th><th>Analyst Pivots</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      `;
    }).join("");

  $("#view-iocs").innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
      <h3 style="font-size:0.95rem;font-weight:700;">Extracted Forensic Indicators (IOCs)</h3>
      <div style="display:flex;gap:8px;">
        <button class="btn-ghost-sm" id="btn-copy-all-iocs">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span>Copy All Defanged</span>
        </button>
      </div>
    </div>
    ${sections || `<p class="sample-header-note">No indicators extracted from this email.</p>`}
  `;

  const copyAllBtn = $("#btn-copy-all-iocs");
  if (copyAllBtn) {
    copyAllBtn.onclick = () => {
      const allDefanged = (c.indicators || []).map((i) => i.defanged || defang(i.value)).filter(Boolean).join("\n");
      copyText(allDefanged);
      showToast("Copied all defanged IOCs to clipboard!", "success");
    };
  }
}

/* View 5: Enrichment */
function renderEnrichmentView(c) {
  const en = c.enrichment || {};
  const rows = (en.results || []).map((r) => `
    <tr>
      <td class="mono-cell"><strong>${esc(r.provider)}</strong></td>
      <td><span class="defanged-token">${esc(defang(r.indicator))}</span></td>
      <td><span class="status-badge-match">${esc(r.verdict)}</span></td>
      <td class="num-cell mono-cell">${r.score ?? " - "}</td>
      <td style="font-size:0.75rem;">${esc(r.summary)}</td>
      <td><span class="v-pill">${r.offline ? "Local Heuristics" : "Live Feed"}</span></td>
    </tr>
  `).join("");

  const skipped = Object.entries(en.providers_skipped || {}).map(([p, r]) => `
    <li class="reasoning-item"><code>${esc(p)}</code>: ${esc(r)}</li>
  `).join("");

  $("#view-enrichment").innerHTML = `
    <div class="panel-sub-card" style="margin-bottom:20px;">
      <h3>Enrichment Telemetry</h3>
      <p style="font-size:0.8rem;color:var(--text-secondary);margin-bottom:8px;">
        Evaluated <strong>${esc(en.indicators_checked || 0)}</strong> indicators in <strong>${esc(en.duration_ms || 0)} ms</strong>. Active providers: <strong>${esc((en.providers_used || []).join(", ") || "Local Heuristics")}</strong>.
      </p>
      ${skipped ? `<div style="margin-top:10px;"><strong style="font-size:0.72rem;color:var(--text-muted);">Unconfigured API Providers:</strong><ul class="reasoning-list" style="margin-top:4px;">${skipped}</ul></div>` : ""}
    </div>

    <h3 style="font-size:0.95rem;font-weight:700;margin-bottom:10px;">Reputation Query Results</h3>
    <div class="cyber-table-container">
      <table class="cyber-table">
        <thead><tr><th>Provider</th><th>Indicator</th><th>Verdict</th><th class="num-cell">Score</th><th>Summary</th><th>Source</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="6" style="text-align:center;">No enrichment queries performed.</td></tr>'}</tbody>
      </table>
    </div>
  `;
}

/* View 6: Timeline Waterfall */
const STAGE_META_MAP = {
  ingest:          { label: "Ingest",          color: "#06b6d4", bg: "rgba(6, 182, 212, 0.12)",  border: "rgba(6, 182, 212, 0.3)" },
  extract:         { label: "Extract",         color: "#3b82f6", bg: "rgba(59, 130, 246, 0.12)", border: "rgba(59, 130, 246, 0.3)" },
  enrich:          { label: "Enrich",          color: "#818cf8", bg: "rgba(129, 140, 248, 0.12)", border: "rgba(129, 140, 248, 0.3)" },
  analyze:         { label: "Analyze",         color: "#c084fc", bg: "rgba(192, 132, 252, 0.12)", border: "rgba(192, 132, 252, 0.3)" },
  reason:          { label: "Reason",          color: "#f59e0b", bg: "rgba(245, 158, 11, 0.12)", border: "rgba(245, 158, 11, 0.3)" },
  report:          { label: "Report",          color: "#10b981", bg: "rgba(16, 185, 129, 0.12)", border: "rgba(16, 185, 129, 0.3)" },
  click_telemetry: { label: "Click Telemetry", color: "#f43f5e", bg: "rgba(244, 63, 94, 0.12)", border: "rgba(244, 63, 94, 0.35)" },
  containment:     { label: "Containment",     color: "#f97316", bg: "rgba(249, 115, 22, 0.12)", border: "rgba(249, 115, 22, 0.35)" },
};

function renderTimelineView(c) {
  const timeline = c.timeline || [];
  const m = c.metrics || {};
  const totalMs = m.total_ms || timeline.reduce((acc, t) => acc + (t.duration_ms || 0), 0) || 25;
  const baselineMin = m.baseline_minutes || 45;
  const minutesSaved = m.minutes_saved != null && m.minutes_saved > 0
    ? m.minutes_saved
    : Math.max(0, Math.round(baselineMin - (totalMs / 60000)));

  // Calculate speedup factor
  const totalSec = Math.max(0.001, totalMs / 1000);
  const baselineSec = baselineMin * 60;
  const multiplier = Math.round(baselineSec / totalSec);

  const rows = timeline.map((t, idx) => {
    const sName = (t.stage || "").toLowerCase();
    const meta = STAGE_META_MAP[sName] || { label: t.stage, color: "#94a3b8", bg: "rgba(148, 163, 184, 0.1)", border: "rgba(148, 163, 184, 0.2)" };
    const dur = t.duration_ms ?? 0;
    const pct = Math.min(100, Math.max(4, Math.round((dur / totalMs) * 100)));

    return `
      <tr>
        <td class="mono-cell" style="color:var(--text-muted);font-weight:600;">#${idx + 1}</td>
        <td>
          <span class="stage-badge-cell" style="color:${meta.color};background:${meta.bg};border:1px solid ${meta.border};">
            <span style="width:5px;height:5px;border-radius:50%;background:${meta.color};"></span>
            ${esc(meta.label)}
          </span>
        </td>
        <td class="waterfall-track-col">
          <div style="display:flex;align-items:center;gap:8px;">
            <div class="waterfall-bar-track">
              <div class="waterfall-bar-fill" style="width:${pct}%;background:${meta.color};box-shadow:0 0 8px ${meta.color};"></div>
            </div>
            <span class="mono-cell" style="font-size:0.68rem;color:var(--text-muted);width:38px;text-align:right;">${dur}ms</span>
          </div>
        </td>
        <td class="mono-cell" style="color:var(--text-muted);font-size:0.68rem;">
          ${esc(t.started_at ? new Date(t.started_at).toLocaleTimeString() : "--:--:--")}
        </td>
        <td style="font-size:0.74rem;color:var(--text-secondary);line-height:1.4;">
          ${esc(t.detail || "")}
        </td>
      </tr>
    `;
  }).join("");

  $("#view-timeline").innerHTML = `
    <div class="waterfall-kpi-banner">
      <div class="kpi-banner-left">
        <div class="kpi-banner-title">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--accent-primary);"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <span>Autonomous Pipeline Velocity</span>
          <span class="velocity-badge">${multiplier.toLocaleString()}x Speedup</span>
        </div>
        <p class="kpi-banner-desc">
          Total automated pipeline runtime: <strong>${esc(totalMs)} ms</strong> compared to <strong>${esc(baselineMin)} min</strong> manual human triage baseline.
        </p>
      </div>
      <div class="kpi-banner-right">
        <div class="kpi-saved-number">${esc(Math.round(minutesSaved))} min</div>
        <div class="kpi-saved-label">Time Saved This Case</div>
      </div>
    </div>

    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">
      <h3 style="font-size:0.92rem;font-weight:700;display:flex;align-items:center;gap:8px;">
        <span>Forensic Stage-by-Stage Waterfall</span>
        <span style="font-size:0.68rem;font-family:var(--font-mono);font-weight:600;color:var(--text-muted);background:#0e1422;border:1px solid var(--border-subtle);padding:1px 6px;border-radius:var(--radius-xs);">${timeline.length} Stages</span>
      </h3>
      <span style="font-size:0.68rem;color:var(--text-muted);font-family:var(--font-mono);">Cumulative Latency: ${esc(totalMs)} ms</span>
    </div>

    <div class="cyber-table-container">
      <table class="cyber-table">
        <thead>
          <tr>
            <th style="width:36px;">#</th>
            <th style="width:140px;">Stage</th>
            <th style="width:200px;">Execution Trace</th>
            <th style="width:90px;">Time</th>
            <th>Operation Details</th>
          </tr>
        </thead>
        <tbody>
          ${rows || '<tr><td colspan="5" style="text-align:center;padding:24px;color:var(--text-muted);">No timeline stages recorded for this case.</td></tr>'}
        </tbody>
      </table>
    </div>
  `;
}

/* View 7: Full Report */
function renderReportView(c) {
  const md = c.report_markdown || "_Compiling deterministic incident investigation report..._";
  $("#view-report").innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
      <h3 style="font-size:0.95rem;font-weight:700;">Deterministic Incident Investigation Report</h3>
      <div style="display:flex;gap:8px;">
        <button class="btn-ghost-sm" id="btn-copy-report">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
          <span>Copy Markdown</span>
        </button>
        <button class="btn-ghost-sm" id="btn-download-report">
          <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          <span>Download .md</span>
        </button>
        <a class="btn-ghost-sm" href="/api/cases/${encodeURIComponent(c.id)}/report" target="_blank" rel="noopener">Open Raw</a>
      </div>
    </div>
    <div class="report-markdown-box">${renderMarkdown(md)}</div>
  `;

  if (!c.report_markdown) {
    fetch(`/api/cases/${encodeURIComponent(c.id)}/report`)
      .then((r) => r.text())
      .then((text) => {
        if (text && text.trim()) {
          c.report_markdown = text;
          const box = document.querySelector(".report-markdown-box");
          if (box) box.innerHTML = renderMarkdown(text);
        }
      })
      .catch(() => {});
  }

  $("#btn-copy-report").onclick = () => {
    copyText(c.report_markdown);
    showToast("Incident report markdown copied!", "success");
  };

  $("#btn-download-report").onclick = () => {
    const blob = new Blob([c.report_markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Report_${c.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Downloaded Report_${c.id}.md`, "success");
  };
}

/* View 8: User Notification */
function renderNotifyView(c) {
  const n = c.notification || {};
  $("#view-notify").innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:10px;">
      <h3 style="font-size:0.95rem;font-weight:700;">Automated Recipient Security Advisory</h3>
      <button class="btn-ghost-sm" id="btn-copy-notify">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
        <span>Copy Advisory Template</span>
      </button>
    </div>
    <div class="notification-email-composer">
      <div class="notif-header-band">
        <span class="notif-subj">${esc(n.subject || "Security Notification")}</span>
        <span class="notif-to">To: <strong>${esc(n.to || "reporting-user@company.com")}</strong></span>
      </div>
      <div class="notif-body-pre">${esc(n.body || "")}</div>
    </div>
  `;

  $("#btn-copy-notify").onclick = () => {
    copyText(`Subject: ${n.subject}\nTo: ${n.to}\n\n${n.body}`);
    showToast("User notification template copied!", "success");
  };
}

/* View 9: SOC Case Notes & Playbook Audit Trail */
function renderNotesView(c) {
  const tagsList = (c.tags || []).map((t) => `
    <span class="tag-chip">
      <span>#${esc(t)}</span>
      <button class="tag-remove-btn" onclick="removeTag('${esc(t)}')">&times;</button>
    </span>
  `).join("");

  const notesList = (c.notes || []).map((n) => `
    <div class="note-item-card">
      <div class="note-item-header">
        <span class="note-author-pill"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--text-muted);"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ${esc(n.author || 'analyst')}</span>
        <div style="display:flex;align-items:center;gap:8px;">
          <span>${formatTimeAgo(n.created_at)}</span>
          <button class="note-del-btn" onclick="deleteNote('${esc(n.id)}')">Delete</button>
        </div>
      </div>
      <div class="note-body-text">${esc(n.text)}</div>
    </div>
  `).join("");

  const actionsList = (c.playbook_actions_taken || []).map((a) => `
    <div class="audit-action-row">
      <div>
        <strong style="color:var(--text-primary);text-transform:uppercase;">${esc(a.action)}</strong>
        <span style="color:var(--text-secondary);margin-left:8px;">${esc(a.detail)}</span>
      </div>
      <div style="display:flex;align-items:center;gap:8px;font-family:var(--font-mono);font-size:0.68rem;color:var(--text-muted);">
        <span style="color:var(--sev-low);font-weight:700;">${esc(a.status || 'SUCCESS').toUpperCase()}</span>
        <span>${formatTimeAgo(a.executed_at)}</span>
      </div>
    </div>
  `).join("");

  $("#view-notes").innerHTML = `
    <div class="notes-container">

      <!-- Case Tags Section -->
      <div class="tags-manager-strip">
        <strong style="font-size:0.75rem;color:var(--text-secondary);">Case Tags:</strong>
        ${tagsList || '<span style="font-size:0.72rem;color:var(--text-muted);">No tags assigned</span>'}
        <input type="text" class="tag-add-input" id="tag-input" placeholder="+ Add Tag" />
      </div>

      <!-- Add Note Input Box -->
      <div class="note-input-box">
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <h3 style="font-size:0.85rem;font-weight:700;">Add Investigation Note</h3>
          <div style="display:flex;align-items:center;gap:6px;">
            <span style="font-size:0.72rem;color:var(--text-muted);">Author:</span>
            <input type="text" id="note-author" value="analyst" style="background:var(--surface-inset);border:1px solid var(--border-subtle);border-radius:var(--radius-xs);padding:3px 8px;font-size:0.72rem;color:var(--text-primary);width:100px;" />
          </div>
        </div>
        <textarea id="note-text" rows="3" class="cyber-textarea" style="margin-bottom:0;" placeholder="Document technical observations, escalation rationale, or IOC correlations..."></textarea>
        <div style="display:flex;justify-content:flex-end;">
          <button class="btn-primary-action" id="btn-submit-note" style="width:auto;padding:6px 16px;">Post Note</button>
        </div>
      </div>

      <!-- Notes Timeline -->
      <div>
        <h3 style="font-size:0.9rem;font-weight:700;margin-bottom:10px;">Analyst Notes (${(c.notes || []).length})</h3>
        <div class="notes-timeline-list">
          ${notesList || '<div style="padding:14px;color:var(--text-muted);font-size:0.75rem;">No notes recorded for this case yet.</div>'}
        </div>
      </div>

      <!-- Playbook Remediation Audit Trail -->
      <div style="margin-top:14px;">
        <h3 style="font-size:0.9rem;font-weight:700;margin-bottom:10px;">Playbook Execution &amp; Containment History</h3>
        <div style="display:flex;flex-direction:column;gap:8px;">
          ${actionsList || '<div style="padding:14px;color:var(--text-muted);font-size:0.75rem;">No automated playbook containment actions executed yet.</div>'}
        </div>
      </div>

    </div>
  `;

  // Wire tag input
  const tagInput = $("#tag-input");
  if (tagInput) {
    tagInput.onkeydown = async (e) => {
      if (e.key === "Enter" && tagInput.value.trim()) {
        const tag = tagInput.value.trim().toLowerCase();
        try {
          await api(`/api/cases/${encodeURIComponent(c.id)}/tags`, {
            method: "POST",
            body: JSON.stringify({ tag }),
          });
          tagInput.value = "";
          const updated = await api(`/api/cases/${encodeURIComponent(c.id)}`);
          renderCase(updated);
          showToast(`Added tag #${tag}`, "success");
        } catch (err) {
          showError(`Could not add tag: ${err.message}`);
        }
      }
    };
  }

  // Wire submit note
  const submitNoteBtn = $("#btn-submit-note");
  if (submitNoteBtn) {
    submitNoteBtn.onclick = async () => {
      const text = ($("#note-text").value || "").trim();
      const author = ($("#note-author").value || "").trim() || "analyst";
      if (!text) {
        showError("Note content cannot be empty.");
        return;
      }
      try {
        await api(`/api/cases/${encodeURIComponent(c.id)}/notes`, {
          method: "POST",
          body: JSON.stringify({ text, author }),
        });
        const updated = await api(`/api/cases/${encodeURIComponent(c.id)}`);
        renderCase(updated);
        showToast("Note added to investigation log", "success");
      } catch (err) {
        showError(`Could not post note: ${err.message}`);
      }
    };
  }
}

// Global Tag & Note Handlers
window.removeTag = async function(tag) {
  if (!state.case) return;
  try {
    await api(`/api/cases/${encodeURIComponent(state.case.id)}/tags/${encodeURIComponent(tag)}`, { method: "DELETE" });
    const updated = await api(`/api/cases/${encodeURIComponent(state.case.id)}`);
    renderCase(updated);
    showToast(`Removed tag #${tag}`, "info");
  } catch (err) {
    showError(`Could not remove tag: ${err.message}`);
  }
};

window.deleteNote = async function(noteId) {
  if (!state.case) return;
  try {
    await api(`/api/cases/${encodeURIComponent(state.case.id)}/notes/${encodeURIComponent(noteId)}`, { method: "DELETE" });
    const updated = await api(`/api/cases/${encodeURIComponent(state.case.id)}`);
    renderCase(updated);
    showToast("Note deleted", "info");
  } catch (err) {
    showError(`Could not delete note: ${err.message}`);
  }
};

/* ---------- Playbook Actions Execution ---------- */
async function executeAction(actionName, label) {
  if (!state.case) return;
  const cid = state.case.id;
  try {
    showProgress(`Executing playbook action: ${label}...`);
    const res = await api(`/api/cases/${encodeURIComponent(cid)}/actions/${encodeURIComponent(actionName)}`, {
      method: "POST",
      body: JSON.stringify({}),
    });
    showToast(`Executed: ${label}`, "success");
    const updated = await api(`/api/cases/${encodeURIComponent(cid)}`);
    renderCase(updated);
    await Promise.all([loadCases(), loadMetrics()]);
  } catch (err) {
    showError(`Failed to execute ${label}: ${err.message}`);
  } finally {
    hideProgress();
  }
}

/* ---------- Two-Step Action Confirmation Safeguards ---------- */
function confirmAndExecuteAction(actionName, label) {
  if (!state.case) return;
  // Credential reset exists only where telemetry confirmed a positive click;
  // everything else (and every benign verdict) has nothing to reset.
  if (actionName === "reset_credentials") {
    const ct = state.case.click_telemetry || {};
    const clickObserved = Boolean(
      ct.has_positive_click || (ct.events && ct.events.length > 0)
    );
    const benign =
      state.case.verdict && state.case.verdict.classification === "false_positive";
    if (!clickObserved || benign) return;
  }
  const cid = state.case.id;
  const prompts = {
    quarantine: {
      title: "Confirm Mailbox Quarantine",
      desc: `Execute tenant-wide mailbox quarantine for incident ${cid}? This will withdraw the message immediately from recipient mailboxes and move it to the secure SOC quarantine repository.`,
    },
    block_domain: {
      title: "Confirm Perimeter Domain Block",
      desc: `Block sender domain for incident ${cid} at perimeter firewalls and DNS resolvers? This will prevent any internal host from resolving or establishing sessions with this external domain.`,
    },
    reset_credentials: {
      title: "Confirm Emergency Credential Revocation",
      desc: `Trigger emergency password reset for incident ${cid}? Active SSO/SAML tokens and enterprise sessions for the targeted user will be terminated immediately.`,
    },
    notify_webhook: {
      title: "Confirm Incident Webhook Dispatch",
      desc: `Dispatch real-time security alert webhook for incident ${cid} to external SIEM/SOAR/ChatOps endpoints?`,
    },
  };

  const p = prompts[actionName] || {
    title: `Confirm Action: ${label}`,
    desc: `Are you sure you want to execute "${label}" for case ${cid}?`,
  };

  showConfirm(p.title, p.desc, () => executeAction(actionName, label));
}
window.confirmAndExecuteAction = confirmAndExecuteAction;

/* ---------- Positive Click Telemetry Modal & Execution ---------- */
function openClickModal() {
  if (!state.case) return;
  const modal = $("#click-modal");
  if (!modal) return;

  const urlSelect = $("#click-url-select");
  const userInput = $("#click-user-input");
  const ipInput = $("#click-ip-input");
  const outcomeSelect = $("#click-outcome-select");
  const credsCheck = $("#click-creds-input");
  const notesInput = $("#click-notes-input");

  // Populate URLs from case indicators, links, or email URLs
  const urls = [];
  if (state.case.links && state.case.links.length > 0) {
    state.case.links.forEach((l) => { if (l.url && !urls.includes(l.url)) urls.push(l.url); });
  }
  if (state.case.email && state.case.email.urls && state.case.email.urls.length > 0) {
    state.case.email.urls.forEach((u) => { if (u && !urls.includes(u)) urls.push(u); });
  }
  if (urls.length === 0) {
    urls.push("https://login-verify-account.security-portal.xyz/auth");
  }

  urlSelect.innerHTML = urls.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join("");

  const recip = (state.case.email && state.case.email.to && state.case.email.to[0]) ? state.case.email.to[0] : "analyst.target@company.com";
  userInput.value = recip;
  ipInput.value = "10.0.4.112";
  outcomeSelect.value = "allowed";
  credsCheck.checked = false;
  if (notesInput) notesInput.value = "";

  modal.hidden = false;
  modal.style.display = "flex";

  const cancelBtn = $("#click-btn-cancel");
  const confirmBtn = $("#click-btn-confirm");

  const cleanup = () => {
    modal.hidden = true;
    modal.style.display = "none";
    cancelBtn.onclick = null;
    confirmBtn.onclick = null;
  };

  cancelBtn.onclick = cleanup;
  confirmBtn.onclick = async () => {
    const selectedUrl = urlSelect.value;
    const userEmail = userInput.value.trim();
    const clientIp = ipInput.value.trim();
    const outcome = outcomeSelect.value;
    const creds = credsCheck.checked;
    const notes = notesInput ? notesInput.value.trim() : "";

    cleanup();

    try {
      showProgress("Registering positive click forensics telemetry...");
      const res = await api(`/api/cases/${encodeURIComponent(state.case.id)}/click-event`, {
        method: "POST",
        body: JSON.stringify({
          url: selectedUrl,
          user_email: userEmail,
          client_ip: clientIp,
          outcome: outcome,
          credentials_submitted: creds,
          details: notes || `Gateway telemetry audit: ${outcome} for ${userEmail}`,
        }),
      });

      showToast(`Positive Click Confirmed! Case escalated to ${res.escalated_severity.toUpperCase()}`, "success");
      const updated = await api(`/api/cases/${encodeURIComponent(state.case.id)}`);
      renderCase(updated);
      await Promise.all([loadCases(), loadMetrics()]);
    } catch (err) {
      showError(`Failed to record click telemetry: ${err.message}`);
    } finally {
      hideProgress();
    }
  };
}
window.openClickModal = openClickModal;


/* ---------- STIX 2.1 & Sigma Exports ---------- */
async function exportStixBundle() {
  if (!state.case) return;
  try {
    showProgress("Generating STIX 2.1 JSON bundle...");
    const bundle = await api(`/api/cases/${encodeURIComponent(state.case.id)}/stix`);
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.case.id}_stix2.1.json`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${state.case.id}_stix2.1.json`, "success");
  } catch (err) {
    showError(`Failed to export STIX: ${err.message}`);
  } finally {
    hideProgress();
  }
}

async function exportSigmaRule() {
  if (!state.case) return;
  try {
    showProgress("Generating SIEM Sigma YAML rule...");
    const res = await fetch(`/api/cases/${encodeURIComponent(state.case.id)}/sigma`);
    if (!res.ok) throw new Error("Could not generate rule");
    const yamlText = await res.text();
    const blob = new Blob([yamlText], { type: "application/x-yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.case.id}_sigma.yml`;
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${state.case.id}_sigma.yml`, "success");
  } catch (err) {
    showError(`Failed to export Sigma rule: ${err.message}`);
  } finally {
    hideProgress();
  }
}

/* ---------- Global Utilities & Export ---------- */
async function copyText(txt) {
  try {
    await navigator.clipboard.writeText(txt);
    showToast("Copied to clipboard!", "success");
  } catch (_) {
    showToast("Clipboard access denied", "error");
  }
}
window.copyText = copyText;

function exportCaseJson() {
  if (!state.case) return;
  const blob = new Blob([JSON.stringify(state.case, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${state.case.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
  showToast(`Exported ${state.case.id}.json`, "success");
}

function deleteCurrentCase() {
  if (!state.case) return;
  const id = state.case.id;
  showConfirm("Delete Investigation Case", `Permanently delete case ${id} from local database?`, async () => {
    try {
      await api(`/api/cases/${encodeURIComponent(id)}`, { method: "DELETE" });
      showToast(`Case ${id} deleted successfully.`, "info");
      state.case = null;
      $("#case-view").hidden = true;
      $("#empty-state").hidden = false;
      await Promise.all([loadCases(), loadCampaigns(), loadMetrics()]);
    } catch (err) {
      showError(`Failed to delete case: ${err.message}`);
    }
  });
}

function resetDatabase() {
  showConfirm("Reset SOC Database", "Clear all stored cases and reset to empty state?", async () => {
    try {
      await api("/api/reset", { method: "POST" });
      showToast("Database reset successfully.", "info");
      state.case = null;
      $("#case-view").hidden = true;
      $("#empty-state").hidden = false;
      await Promise.all([loadCases(), loadCampaigns(), loadMetrics(), loadStatus()]);
    } catch (err) {
      showError(`Reset failed: ${err.message}`);
    }
  });
}

/* ---------- App Initialization & Events ---------- */
function init() {
  initTheme();
  // Ensure modal is hidden on start
  const m = $("#confirm-modal");
  if (m) {
    m.hidden = true;
    m.style.display = "none";
    $("#modal-btn-cancel").addEventListener("click", () => {
      m.hidden = true;
      m.style.display = "none";
    });
    m.addEventListener("click", (e) => {
      if (e.target.id === "confirm-modal") {
        m.hidden = true;
        m.style.display = "none";
      }
    });
  }

  // Intake tabs
  $$("#intake-tabs .intake-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      $$("#intake-tabs .intake-tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      const targetPane = tab.dataset.pane;
      $$(".intake-card .tab-body").forEach((b) => {
        b.hidden = b.dataset.pane !== targetPane;
      });
    });
  });

  // Dropzone drag-and-drop
  const dropzone = $("#dropzone");
  const fileInput = $("#file-input");

  if (dropzone && fileInput) {
    dropzone.addEventListener("dragover", (e) => {
      e.preventDefault();
      dropzone.classList.add("drag-active");
    });
    ["dragleave", "dragend"].forEach((ev) => {
      dropzone.addEventListener(ev, () => dropzone.classList.remove("drag-active"));
    });
    dropzone.addEventListener("drop", (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag-active");
      if (e.dataTransfer.files && e.dataTransfer.files[0]) {
        runUpload(e.dataTransfer.files[0]);
      }
    });
    fileInput.addEventListener("change", (e) => {
      if (e.target.files && e.target.files[0]) {
        runUpload(e.target.files[0]);
      }
    });
  }

  // Raw RFC paste
  const runPasteBtn = $("#run-paste");
  if (runPasteBtn) runPasteBtn.addEventListener("click", runRaw);

  // Investigation view tabs
  $$("#result-tabs .view-tab").forEach((btn) => {
    btn.addEventListener("click", () => showView(btn.dataset.view));
  });

  // Case Search & Filtering
  const searchInput = $("#case-search");
  let searchDebounce = null;
  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      clearTimeout(searchDebounce);
      searchDebounce = setTimeout(() => {
        state.searchQuery = e.target.value;
        loadCases();
      }, 250);
    });
  }

  $$("#filter-chips .filter-chip").forEach((chip) => {
    chip.addEventListener("click", () => {
      $$("#filter-chips .filter-chip").forEach((c) => c.classList.remove("active"));
      chip.classList.add("active");
      state.statusFilter = chip.dataset.filter;
      loadCases();
    });
  });

  // Mode Toggle: Cases vs Campaigns
  const btnCases = $("#btn-mode-cases");
  const btnCamps = $("#btn-mode-campaigns");
  if (btnCases && btnCamps) {
    btnCases.onclick = () => {
      state.queueMode = "cases";
      btnCases.classList.add("active");
      btnCamps.classList.remove("active");
      $("#case-list").hidden = false;
      $("#campaign-list").hidden = true;
    };
    btnCamps.onclick = () => {
      state.queueMode = "campaigns";
      btnCamps.classList.add("active");
      btnCases.classList.remove("active");
      $("#case-list").hidden = true;
      $("#campaign-list").hidden = false;
      loadCampaigns();
    };
  }

  // Ingestion Watcher Scan
  const btnScanInbox = $("#btn-scan-inbox");
  if (btnScanInbox) {
    btnScanInbox.onclick = async () => {
      try {
        showProgress("Scanning inbox directory for pending email files...");
        const res = await api("/api/watch/scan", { method: "POST", body: JSON.stringify({}) });
        showToast(`Inbox Watcher: processed ${res.processed} file(s)`, "success");
        await Promise.all([loadCases(), loadCampaigns(), loadMetrics(), loadStatus()]);
      } catch (err) {
        showError(`Watcher scan failed: ${err.message}`);
      } finally {
        hideProgress();
      }
    };
  }

  // Toolbar Actions
  $("#btn-copy-case-id").onclick = () => {
    if (state.case) {
      copyText(state.case.id);
      showToast(`Copied ${state.case.id}`, "success");
    }
  };
  $("#btn-export-json").onclick = exportCaseJson;
  $("#btn-export-stix").onclick = exportStixBundle;
  $("#btn-export-sigma").onclick = exportSigmaRule;
  $("#btn-delete-case").onclick = deleteCurrentCase;
  $("#btn-reset-db").onclick = resetDatabase;
  $("#btn-refresh-cases").onclick = () => {
    loadCases();
    loadCampaigns();
    loadMetrics();
    showToast("Case queue refreshed", "info");
  };

  // Playbook Action Buttons with Confirmation Safeguards
  const btnQuarantine = $("#btn-action-quarantine");
  if (btnQuarantine) btnQuarantine.onclick = () => confirmAndExecuteAction("quarantine", "Quarantine Message");

  const btnBlock = $("#btn-action-block");
  if (btnBlock) btnBlock.onclick = () => confirmAndExecuteAction("block_domain", "Block Domain");

  const btnReset = $("#btn-action-reset");
  if (btnReset) btnReset.onclick = () => confirmAndExecuteAction("reset_credentials", "Reset User Credentials");

  const btnNotify = $("#btn-action-notify");
  if (btnNotify) btnNotify.onclick = () => confirmAndExecuteAction("notify_webhook", "Dispatch Webhook Alert");

  const btnRecordClick = $("#btn-record-click");
  if (btnRecordClick) btnRecordClick.onclick = openClickModal;

  // Keyboard Shortcuts
  window.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (m && !m.hidden) {
        m.hidden = true;
        m.style.display = "none";
      }
      const clickM = $("#click-modal");
      if (clickM && !clickM.hidden) {
        clickM.hidden = true;
        clickM.style.display = "none";
      }
    }
    if ((e.ctrlKey && e.key === "k") || (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA")) {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    }
    if (state.case && !e.ctrlKey && !e.altKey && !e.metaKey && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
      const tabs = ["summary", "email", "signals", "iocs", "enrichment", "timeline", "report", "notify", "notes"];
      const num = parseInt(e.key, 10);
      if (num >= 1 && num <= tabs.length) {
        showView(tabs[num - 1]);
      }
    }
  });

  // Initial Load
  Promise.all([loadStatus(), loadMetrics(), loadSamples(), loadCampaigns(), loadCases()]).then(() => {
    if (state.cases.length > 0 && !state.case) {
      openCase(state.cases[0].id);
    }
  });

  // Keep the console live: new intake, escalations, click telemetry and
  // playbook updates appear within seconds without a page reload.
  setInterval(async () => {
    try {
      await Promise.all([loadStatus(), loadMetrics(), loadCampaigns(), loadCases()]);
      if (state.case && state.case.id) {
        try {
          const fresh = await api(`/api/cases/${state.case.id}`);
          if (fresh && fresh.id === state.case.id) renderCase(fresh);
        } catch (_) { /* keep showing the last rendered case */ }
      }
    } catch (e) {
      console.warn("auto-refresh", e);
    }
  }, 5000);
}

document.addEventListener("DOMContentLoaded", init);


/* ---------- Dark / Light Mode Theme Engine ---------- */
function initTheme() {
  const toggleBtn = $("#btn-theme-toggle");
  const labelSpan = $("#theme-label-text");

  function getSystemPreference() {
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
  }

  function getActiveTheme() {
    const attr = document.documentElement.getAttribute("data-theme");
    if (attr === "light" || attr === "dark") return attr;
    return getSystemPreference();
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    try {
      localStorage.setItem("phishpipe-theme", theme);
    } catch (e) {}
    if (labelSpan) {
      labelSpan.textContent = theme === "light" ? "Light" : "Dark";
    }
    if (toggleBtn) {
      toggleBtn.title = `Switch to ${theme === "light" ? "Dark" : "Light"} Mode`;
      toggleBtn.setAttribute("aria-label", `Switch to ${theme === "light" ? "Dark" : "Light"} Mode`);
    }
  }

  // Initial sync
  let initial = "dark";
  try {
    const saved = localStorage.getItem("phishpipe-theme");
    if (saved === "light" || saved === "dark") {
      initial = saved;
    } else if (getSystemPreference() === "light") {
      initial = "light";
    }
  } catch (e) {}
  applyTheme(initial);

  if (toggleBtn) {
    toggleBtn.addEventListener("click", () => {
      const active = getActiveTheme();
      const next = active === "light" ? "dark" : "light";
      applyTheme(next);
      showToast(`Switched to ${next.toUpperCase()} theme`, "info");
    });
  }

  // Dynamic OS preference listener
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
      let saved = null;
      try {
        saved = localStorage.getItem("phishpipe-theme");
      } catch (err) {}
      if (!saved) {
        applyTheme(e.matches ? "light" : "dark");
      }
    });
  }
}
