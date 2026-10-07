import re
from pathlib import Path

WEB_DIR = Path(__file__).resolve().parent.parent / "web"

with open(WEB_DIR / "styles.css", "r", encoding="utf-8") as f:
    css = f.read()

with open(WEB_DIR / "app.js", "r", encoding="utf-8") as f:
    js = f.read()

html_template = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="PhishPipe - Enterprise SOC Phishing Triage and Threat Reasoning Console." />
  <meta name="theme-color" content="#06080f" />
  <title>PhishPipe - Autonomous SOC Phishing Investigation Console</title>
  
  <!-- Modern Fonts -->
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600;700&display=swap" rel="stylesheet" />

  <style>
/* CSS PLACEHOLDER */
  </style>
  <link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cpath d='M16 2.5 4.5 7v9.2c0 6.6 4.7 11.7 11.5 13.3 6.8-1.6 11.5-6.7 11.5-13.3V7Z' fill='%2338bdf8'/%3E%3Cpath d='M10.5 11.5h11l-4.3 5.1v5l-2.4 1.4v-6.4Z' fill='%2306080f'/%3E%3C/svg%3E" />
</head>
<body class="soc-console">

  <!-- Background Structural Grid -->
  <div class="cyber-grid" aria-hidden="true"></div>

  <!-- ================= TOPBAR ================= -->
  <header class="topbar">
    <div class="brand">
      <div class="logo-wrapper">
        <svg viewBox="0 0 32 32" width="28" height="28" class="brand-shield" fill="none">
          <path d="M16 2.5 4.5 7v9.2c0 6.6 4.7 11.7 11.5 13.3 6.8-1.6 11.5-6.7 11.5-13.3V7Z" fill="rgba(59, 130, 246, 0.12)" stroke="#3b82f6" stroke-width="1.8" stroke-linejoin="round"/>
          <path d="M10.5 11.5h11l-4.3 5.1v5l-2.4 1.4v-6.4Z" fill="#3b82f6"/>
        </svg>
      </div>
      <div class="brand-text">
        <div class="brand-title">
          <h1>PhishPipe</h1>
          <span class="brand-tag">SOC TIER-1 ENGINE</span>
        </div>
        <p class="brand-sub">Autonomous Phishing Triage &bull; Explainable Threat Reasoning</p>
      </div>
    </div>

    <!-- Live Telemetry Engine Status -->
    <div class="statusbar" id="statusbar">
      <div class="status-pill" id="pill-mode" title="Reputation engine mode">
        <span class="pulse-dot"></span>
        <span class="pill-label">ENGINE:</span>
        <span class="pill-val" id="badge-mode">AIR-GAPPED (HEURISTICS)</span>
      </div>
      <div class="status-pill" id="pill-detections" title="Active detection rules">
        <span class="pill-icon"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></span>
        <span class="pill-val" id="badge-detections">37 SIGNALS</span>
      </div>
      <div class="status-pill" id="pill-llm" title="Report generation mode">
        <span class="pill-icon"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg></span>
        <span class="pill-val" id="badge-llm">DETERMINISTIC</span>
      </div>
      <div class="status-pill cases-pill" id="pill-cases" title="Total cases in database">
        <span class="pill-icon"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg></span>
        <span class="pill-val" id="badge-cases">0 CASES</span>
      </div>
    </div>

    <!-- Quick Console Actions -->
    <div class="top-actions">
      <button class="btn-icon-subtle" id="btn-reset-db" title="Reset demo database">
        <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 12a9 9 0 0 1 15-6.7L21 8M21 3v5h-5M21 12a9 9 0 0 1-15 6.7L3 16M3 21v-5h5"/></svg>
        <span>Reset DB</span>
      </button>
      <a href="/docs" target="_blank" rel="noopener" class="btn-ghost-sm" title="View interactive OpenAPI docs">
        <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
        <span>API Docs</span>
      </a>
    </div>
  </header>

  <!-- ================= EXECUTIVE TELEMETRY RIBBON ================= -->
  <section class="telemetry-strip" id="metrics-strip" aria-label="SOC Fleet Metrics">
    <div class="telemetry-card">
      <div class="telemetry-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7"/></svg>
      </div>
      <div class="telemetry-content">
        <span class="telemetry-title">Total Ingested</span>
        <span class="telemetry-val" id="metric-total">0</span>
      </div>
    </div>
    <div class="telemetry-card threat-card">
      <div class="telemetry-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
      </div>
      <div class="telemetry-content">
        <span class="telemetry-title">Confirmed Threats</span>
        <span class="telemetry-val" id="metric-threats">0</span>
      </div>
    </div>
    <div class="telemetry-card">
      <div class="telemetry-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <div class="telemetry-content">
        <span class="telemetry-title">Avg Triage Latency</span>
        <span class="telemetry-val" id="metric-latency">0 ms</span>
      </div>
    </div>
    <div class="telemetry-card review-card">
      <div class="telemetry-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      </div>
      <div class="telemetry-content">
        <span class="telemetry-title">Needs Escalation</span>
        <span class="telemetry-val" id="metric-escalations">0</span>
      </div>
    </div>
    <div class="telemetry-card saved-card">
      <div class="telemetry-icon">
        <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 14 14"/></svg>
      </div>
      <div class="telemetry-content">
        <span class="telemetry-title">Analyst Time Saved</span>
        <span class="telemetry-val" id="metric-saved">0 min</span>
      </div>
    </div>
  </section>

  <!-- ================= WORKSPACE LAYOUT ================= -->
  <main class="soc-layout">

    <!-- LEFT COLUMN: Intake & Case Queue -->
    <aside class="sidebar-pane">

      <!-- Ingest & Investigate Panel -->
      <section class="console-card intake-card" id="intake-card">
        <div class="card-header-clean" id="intake-card-header" style="cursor: pointer;">
          <div class="header-title-group">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
            <h2>Ingest &amp; Investigate</h2>
          </div>
          <div style="display:flex;align-items:center;gap:6px;">
            <span class="tag-privacy">Air-Gapped</span>
            <button class="btn-icon-tiny" id="btn-toggle-intake" title="Toggle ingest panel">
              <svg id="intake-chevron" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" style="transition:transform 0.2s ease;"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
          </div>
        </div>
        <div id="intake-collapsible-body">

        <div class="intake-tabs" id="intake-tabs" role="tablist">
          <button class="intake-tab active" data-pane="upload" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
            <span>Upload</span>
          </button>
          <button class="intake-tab" data-pane="sample" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Scenarios</span>
          </button>
          <button class="intake-tab" data-pane="paste" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
            <span>Raw RFC</span>
          </button>
        </div>

        <!-- Tab 1: Upload -->
        <div class="tab-body" data-pane="upload">
          <label class="pro-dropzone" id="dropzone" for="file-input">
            <input type="file" id="file-input" accept=".eml,.msg,.txt" hidden />
            <div class="dz-beacon">
              <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
                <path d="M4 14.899A7 7 0 1 1 15.71 8h1.79a4.5 4.5 0 0 1 2.5 8.242"/>
                <path d="M12 12v9"/><path d="m16 16-4-4-4 4"/>
              </svg>
            </div>
            <div class="dz-text">
              <strong>Select or Drop Email File</strong>
              <span class="dz-formats">RFC822 (.eml) &bull; Outlook (.msg) &bull; Text (.txt)</span>
            </div>
            <span class="dz-badge">Max 25 MB &bull; Deterministic Heuristics</span>
          </label>
        </div>

        <!-- Tab 2: Samples / Scenarios -->
        <div class="tab-body" data-pane="sample" hidden>
          <div class="sample-header-note">Preloaded scenarios for regression tests &amp; demo triage:</div>
          <div id="sample-list" class="sample-cards-grid"></div>
        </div>

        <!-- Tab 3: Paste Raw RFC -->
        <div class="tab-body" data-pane="paste" hidden>
          <textarea id="raw-input" rows="7" spellcheck="false" class="cyber-textarea"
            placeholder="From: attacker@malicious.xyz&#10;To: target@victim.org&#10;Subject: Urgent Password Expiration&#10;Authentication-Results: spf=fail dkim=fail&#10;&#10;Please verify credentials immediately..."></textarea>
          <button class="btn-primary-action w-100" id="run-paste">
            <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            <span>Analyze Raw Headers &amp; Body</span>
          </button>
        </div>

        <!-- Pipeline Progress Indicator -->
        <div class="progress-indicator" id="progress" hidden>
          <div class="progress-track"><div class="progress-fill"></div></div>
          <div class="progress-status">
            <span class="spinner-cyber"></span>
            <span id="progress-label">Running Pipeline Stages...</span>
          </div>
        </div>
        <div class="error-banner" id="error-box" hidden></div>
        </div>
      </section>

      <!-- Case Queue Panel -->
      <section class="console-card queue-card">
        <div class="card-header-clean">
          <div class="header-title-group">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
            <h2>Case Queue</h2>
            <span class="count-bubble" id="case-count">0</span>
          </div>
          <div style="display:flex;align-items:center;gap:6px;">
            <button class="btn-playbook action-intel" id="btn-scan-inbox" title="Scan inbox folder for incoming emails">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
              <span>Scan Inbox</span>
            </button>
            <button class="btn-icon-subtle" id="btn-refresh-cases" title="Refresh case queue">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
            </button>
          </div>
        </div>

        <!-- Mode Toggle: Cases vs Campaigns -->
        <div class="queue-mode-toggle">
          <button class="queue-mode-btn active" id="btn-mode-cases">All Cases</button>
          <button class="queue-mode-btn" id="btn-mode-campaigns">Threat Campaigns (<span id="camp-count">0</span>)</button>
        </div>

        <!-- Search & Filter Controls -->
        <div class="queue-controls">
          <div class="cyber-search">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input type="search" id="case-search" placeholder="Search subject, sender, case ID... (/)" />
          </div>

          <!-- Verdict Filter Pills -->
          <div class="filter-chips" id="filter-chips">
            <button class="filter-chip active" data-filter="all">All</button>
            <button class="filter-chip chip-tp" data-filter="true_positive">Threats</button>
            <button class="filter-chip chip-su" data-filter="suspicious">Suspicious</button>
            <button class="filter-chip chip-fp" data-filter="false_positive">Benign</button>
          </div>
        </div>

        <!-- Scrollable Case List -->
        <div id="case-list" class="case-list-scrollable"></div>
        <div id="campaign-list" class="case-list-scrollable" hidden></div>
      </section>
    </aside>

    <!-- RIGHT COLUMN: Case Triage & Deep Inspection -->
    <section class="results-pane" id="results">

      <!-- Empty State -->
      <div class="empty-stage" id="empty-state">
        <div class="radar-ring" aria-hidden="true">
          <div class="radar-sweep"></div>
          <svg viewBox="0 0 96 96" width="56" height="56" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">
            <path d="M48 10 14 24v28c0 22.5 14.5 43.5 34 49 19.5-5.5 34-26.5 34-49V24L48 10Z" stroke="#3b82f6" fill="rgba(59, 130, 246, 0.08)"/>
            <path d="m32 44 11 11 21-21" stroke="#3b82f6" stroke-width="2.5"/>
          </svg>
        </div>
        <h2>Awaiting Telemetry Ingestion</h2>
        <p class="empty-desc">Select an incident from the queue, upload an email artifact (.eml/.msg), or launch a preloaded scenario below.</p>

        <div class="quick-sample-prompts" id="empty-sample-grid">
          <!-- Populated dynamically with sample cards -->
        </div>
      </div>

      <!-- Active Case View -->
      <div id="case-view" class="active-case-container" hidden>

        <!-- Top Case Control Toolbar -->
        <div class="case-toolbar">
          <div class="toolbar-left">
            <span class="case-id-badge" id="btn-copy-case-id" title="Click to copy Case ID">
              <span class="copy-icon-sm"><svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></span>
              <span class="id-txt" id="toolbar-case-id">PHI-XXXX</span>
            </span>
            <span class="timestamp-meta" id="toolbar-timestamp">Just now</span>
          </div>

          <div class="toolbar-actions">
            <div class="toolbar-playbook-group">
              <button class="btn-playbook action-quarantine" id="btn-action-quarantine" title="Quarantine email in all tenant mailboxes">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                <span>Quarantine</span>
              </button>
              <button class="btn-playbook action-block" id="btn-action-block" title="Block sender domain at edge firewall">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
                <span>Block Domain</span>
              </button>
              <button class="btn-playbook action-reset" id="btn-action-reset" title="Force password reset for targeted user">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                <span>Reset Creds</span>
              </button>
              <button class="btn-playbook action-intel" id="btn-action-notify" title="Dispatch alert webhook to Slack/Teams/SIEM">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
                <span>Webhook</span>
              </button>
              <button class="btn-playbook action-click" id="btn-record-click" title="Register / Verify Positive User Click Telemetry">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h6v6M10 14L21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/></svg>
                <span>Verify Click</span>
              </button>
            </div>

            <div class="toolbar-playbook-group">
              <button class="btn-ghost-sm" id="btn-export-stix" title="Export OASIS STIX 2.1 Threat Intel Bundle">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>
                <span>STIX 2.1</span>
              </button>
              <button class="btn-ghost-sm" id="btn-export-sigma" title="Export SIEM Detection Rule in Sigma YAML">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
                <span>Sigma</span>
              </button>
              <button class="btn-ghost-sm" id="btn-export-json" title="Export case as JSON">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                <span>JSON</span>
              </button>
              <button class="btn-ghost-sm btn-danger-subtle" id="btn-delete-case" title="Delete this case from database">
                <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                <span>Delete</span>
              </button>
            </div>
          </div>
        </div>

        <!-- Hero Verdict Card -->
        <div class="verdict-hero-card" id="verdict-hero">
          <!-- Populated dynamically via renderCase -->
        </div>

        <!-- Investigation Deep Dive Tabs -->
        <nav class="result-tabs-bar" id="result-tabs" role="tablist">
          <button class="view-tab active" data-view="summary" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
            <span>Overview &amp; Playbook</span>
          </button>
          <button class="view-tab" data-view="email" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
            <span>Email Inspector</span>
          </button>
          <button class="view-tab" data-view="signals" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
            <span>Detections &amp; Signals</span>
          </button>
          <button class="view-tab" data-view="iocs" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            <span>IOCs &amp; Artifacts</span>
          </button>
          <button class="view-tab" data-view="enrichment" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <span>Enrichment</span>
          </button>
          <button class="view-tab" data-view="timeline" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            <span>Stage Waterfall</span>
          </button>
          <button class="view-tab" data-view="report" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            <span>Incident Report</span>
          </button>
          <button class="view-tab" data-view="notify" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 17H2a3 3 0 0 0 3-3V9a7 7 0 0 1 14 0v5a3 3 0 0 0 3 3zm-8.27 4a2 2 0 0 1-3.46 0"/></svg>
            <span>User Advisory</span>
          </button>
          <button class="view-tab" data-view="notes" role="tab">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
            <span>Notes &amp; Audit</span>
          </button>
        </nav>

        <!-- Dynamic View Panes -->
        <div class="view-content-area">
          <div class="view-panel active" data-view="summary" id="view-summary"></div>
          <div class="view-panel" data-view="email" id="view-email" hidden style="display:none;"></div>
          <div class="view-panel" data-view="signals" id="view-signals" hidden style="display:none;"></div>
          <div class="view-panel" data-view="iocs" id="view-iocs" hidden style="display:none;"></div>
          <div class="view-panel" data-view="enrichment" id="view-enrichment" hidden style="display:none;"></div>
          <div class="view-panel" data-view="timeline" id="view-timeline" hidden style="display:none;"></div>
          <div class="view-panel" data-view="report" id="view-report" hidden style="display:none;"></div>
          <div class="view-panel" data-view="notify" id="view-notify" hidden style="display:none;"></div>
          <div class="view-panel" data-view="notes" id="view-notes" hidden style="display:none;"></div>
        </div>

      </div>
    </section>
  </main>

  <!-- Toast Notification Container -->
  <div class="toast-container" id="toast-container" aria-live="polite"></div>

  <!-- Confirmation Modal -->
  <div class="soc-modal-backdrop" id="confirm-modal" hidden style="display:none;">
    <div class="soc-modal">
      <div class="modal-icon warning"><svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--sev-medium);"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
      <h3 id="modal-title">Confirm Action</h3>
      <p id="modal-desc">Are you sure you want to proceed?</p>
      <div class="modal-actions">
        <button class="btn-ghost-sm" id="modal-btn-cancel">Cancel</button>
        <button class="btn-danger-sm" id="modal-btn-confirm">Proceed</button>
      </div>
    </div>
  </div>

  <!-- Positive Click Telemetry Modal -->
  <div class="soc-modal-backdrop" id="click-modal" hidden style="display:none;">
    <div class="soc-modal" style="max-width: 480px;">
      <div class="modal-icon warning">
        <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2" style="color:var(--sev-critical);">
          <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
          <line x1="12" y1="9" x2="12" y2="13"/>
          <line x1="12" y1="17" x2="12.01" y2="17"/>
        </svg>
      </div>
      <h3 id="click-modal-title">Register Positive User Click Telemetry</h3>
      <p style="font-size:0.75rem; color:var(--text-muted); margin-bottom:8px;">
        Correlate real-time Secure Web Gateway (SWG) or Mail Gateway time-of-click telemetry. Registering a positive click will immediately escalate this incident to <strong>CRITICAL</strong> severity, inject compromise tags, and activate emergency containment playbooks.
      </p>
      
      <div style="display:flex; flex-direction:column; gap:10px; margin: 8px 0;">
        <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px;">
          <span>Target URL Clicked:</span>
          <select id="click-url-select" class="soc-select"></select>
        </label>
        
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
          <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px;">
            <span>Target User Email:</span>
            <input type="text" id="click-user-input" class="soc-input" placeholder="user@company.com" />
          </label>
          <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px;">
            <span>Source Client IP:</span>
            <input type="text" id="click-ip-input" class="soc-input" placeholder="10.0.1.45" />
          </label>
        </div>

        <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px;">
          <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px;">
            <span>Gateway Outcome:</span>
            <select id="click-outcome-select" class="soc-select">
              <option value="allowed">Allowed / Delivered</option>
              <option value="warned">Warned &amp; Proceeded</option>
              <option value="isolated">Isolated (RBI)</option>
              <option value="blocked">Blocked at Gateway</option>
            </select>
          </label>
          <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px; justify-content:center;">
            <span style="display:flex; align-items:center; gap:6px; cursor:pointer; margin-top:14px;">
              <input type="checkbox" id="click-creds-input" style="accent-color:var(--sev-critical); width:15px; height:15px;" />
              <span style="color:#fca5a5; font-weight:600;">Credentials Submitted</span>
            </span>
          </label>
        </div>

        <label style="font-size:0.72rem; color:var(--text-secondary); display:flex; flex-direction:column; gap:4px;">
          <span>Forensic Notes:</span>
          <input type="text" id="click-notes-input" class="soc-input" placeholder="e.g. Proxy log correlation ID #PX-98214" />
        </label>
      </div>

      <div class="modal-actions">
        <button class="btn-ghost-sm" id="click-btn-cancel">Cancel</button>
        <button class="btn-danger-sm" id="click-btn-confirm">Confirm &amp; Escalate Case</button>
      </div>
    </div>
  </div>

  <footer class="soc-footer">
    <div class="footer-left">
      <span class="badge-dot-clean"></span>
      <span>PhishPipe SOC Console &bull; Air-Gapped Triage &bull; Defanged Indicators</span>
    </div>
    <div class="footer-right">
      <a href="/docs" target="_blank" rel="noopener">Swagger API</a>
      <span class="sep">&bull;</span>
      <a href="/api/openapi.json" target="_blank" rel="noopener">OpenAPI 3.1 Spec</a>
      <span class="sep">&bull;</span>
      <span>Signals Version 1.0.0</span>
    </div>
  </footer>

  <script>
/* JS PLACEHOLDER */
  </script>
</body>
</html>
"""

# Replace placeholders
final_html = html_template.replace("/* CSS PLACEHOLDER */", css)
final_html = final_html.replace("/* JS PLACEHOLDER */", js)

with open(WEB_DIR / "index.html", "w", encoding="utf-8") as f:
    f.write(final_html)

print(f"index.html bundled successfully! ({len(final_html)} bytes)")
