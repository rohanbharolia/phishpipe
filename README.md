# PhishPipe — Automated Phishing Investigation Pipeline

An offline-first SOC tool that takes a raw email (upload, paste, or sample), runs a full
investigation — extract → enrich → analyze → case → report → notify — and returns an
analyst-ready verdict with a plain-English confidence explanation.

**114 tests pass. No API keys required. No Docker required.**

---

## Quick start

```powershell
# 1. Install dependencies (Python 3.12+)
pip install -r requirements.txt

# 2. Run the API + web UI
python -m uvicorn api.main:app --reload --port 8000

# 3. Open the UI
start http://127.0.0.1:8000
```

Run the test suite:

```powershell
python -m pytest
```

Run all four samples end-to-end from the CLI:

```powershell
python tools\smoke_samples.py
```

---

## What it does

```
   .eml / text / paste / sample
            │
            ▼
   ┌────────────────┐
   │ 1. INGEST      │  RFC822 / headers-only / HTML / auto-detect
   └───────┬────────┘
           ▼
   ┌────────────────┐
   │ 2. EXTRACT     │  URLs, IPs, domains, attachments, auth results,
   └───────┬────────┘  brands, urgency/threat language, Received chain
           ▼
   ┌────────────────┐
   │ 3. ENRICH      │  pluggable providers — every one is optional
   └───────┬────────┘  offline verdict dataset works with zero keys
           ▼
   ┌────────────────┐
   │ 4. ANALYZE     │  signals.yaml → weighted additive score (0–100)
   └───────┬────────┘  → confidence band + plain-English explanation
           ▼
   ┌────────────────┐
   │ 5. CASE        │  SQLite persistence, MITRE ATT&CK mapping
   └───────┬────────┘  auto-triage: severity / status / recommended actions
           ▼
   ┌────────────────┐
   │ 6. REPORT      │  deterministic Markdown template, always
   └───────┬────────┘  optional LLM narrative polish if a key exists
           ▼
   ┌────────────────┐
   │ 7. NOTIFY      │  ready-to-send recipient message: subject +
   └────────────────┘  plain-language body, rendered in the UI
```

---

## Why it works without API keys

| Concern | Offline answer |
| --- | --- |
| URL / domain reputation | `data/offline_verdicts.json` — curated known-bad/known-good entries keyed by lowercased indicator (domains, IPs, hashes, email domains), plus deterministic structural heuristics (punycode, dynamic-DNS, IP hosts, `@`-obfuscation, homoglyphs) |
| SPF / DKIM / DMARC | Parsed straight from the `Authentication-Results` header and evaluated locally |
| Attachment inspection | Filename/extension-chain analysis (double extension), declared-MIME vs extension mismatch, macro-instruction language, password-protected-archive hints |
| Case management | SQLite (`data/cases.db`) — no TheHive / OpenCTI / Docker |
| Report writing | Deterministic Markdown template that renders even with zero signals fired |
| User notification | Always produced as a ready-to-send message (recipient address, subject, plain-language body) rendered in the UI's notification pane |
| LLM narrative | Opt-in only; falls back to the template automatically |

Every provider follows the same contract: **never raise, never hang, always return a
structured result.** Network providers use short timeouts and no retries; a failure is
converted into a result object and the pipeline moves on. Providers whose key is absent
are *skipped*, not errored — `GET /api/status` lists both `providers` and
`providers_skipped` with the reason.

---

## Optional provider keys

Set any of these to activate live enrichment. Everything else keeps working untouched.

| Env var | Enables | Fallback when unset |
| --- | --- | --- |
| `VT_API_KEY` | VirusTotal URL/file reputation | offline verdict dataset + heuristics |
| `URLSCAN_API_KEY` | urlscan.io URL scanning | offline verdict dataset + heuristics |
| `ABUSEIPDB_API_KEY` | AbuseIPDB IP reputation | offline structural heuristics |
| `OPENAI_API_KEY` / `LLM_API_KEY` | LLM narrative polish on the summary/notification | deterministic template |
| `LLM_BASE_URL` / `LLM_MODEL` | Override the OpenAI-compatible endpoint/model (defaults `https://api.openai.com/v1`, `gpt-4o-mini`) | defaults |
| `PHISHPIPE_OFFLINE` | Force offline mode even when keys are present (`1`/`true`/`yes`/`on`) — deterministic demos and CI | — |
| `PHISHPIPE_BASELINE_MINUTES` | Manual-triage baseline used for the "time saved" metric (default `45`) | `45` |

`GET /api/status` reports which providers are live, which are skipped and why, plus the
LLM status and the loaded detection version.

---

## Detection logic as data

All detection logic lives in **`detections/signals.yaml`** — versioned, reviewable, and
tunable as a plain Git diff. No redeploys.

```yaml
version: "1.0.0"

scoring:
  true_positive_threshold: 70    # confidence >= this  -> true positive
  suspicious_threshold: 30       # confidence >= this  -> suspicious, else false positive
  critical_severity_threshold: 90
  high_severity_threshold: 70
  medium_severity_threshold: 40
  low_severity_threshold: 15
  critical_signal_auto_escalate: true
```

Each signal declares a signed `weight`, a `severity`, a `category`, and the ATT&CK
techniques it maps to. Positive weights push the score up, negative weights are
mitigating factors:

```yaml
signals:
  - id: identity.brand_impersonation
    title: Brand impersonation detected
    description: The message imitates a well-known brand outside the sender's own domain.
    weight: 15
    severity: high
    category: identity
    techniques: [T1566, T1598]

  - id: auth.all_pass_aligned
    title: SPF, DKIM and DMARC all pass
    description: Full authentication chain verified and aligned - a strong mitigating factor.
    weight: -20
    severity: info
    category: auth
    techniques: []
```

The file also carries `wordlists{}` (phrase lists, allow/deny lists used by the
extractor) and `mitre{}` (the ATT&CK technique catalogue), so **tuning a rule or adding a
phrase is a one-line diff.** Bump `version`, open a PR, and the change is reviewable in
isolation. `GET /api/detections` returns the loaded ruleset + version + thresholds at
runtime, so an analyst can always see *which* ruleset produced a verdict.

### Confidence explanation

Score = `clamp(Σ matched weights, 0, 100)`, then mapped to a classification band
(`>= 70` true positive, `>= 30` suspicious, else false positive) and a severity band.
Every verdict ships with the factors that produced it — verbatim from a real DHL sample
report:

> **9/37 detection signals matched for a raw score of 54 clamped to 54/100.**
> Highest-impact signals: Reputation service reports malicious (+25); SPF, DKIM and DMARC
> all pass (−20); Display name impersonates a known brand or person (+15); Brand
> impersonation detected (+15); Message originates outside the expected mail path (+6).
> Score sits between 30 and 70 — insufficient evidence for an automatic verdict.
> Mitigating factors reduced the score: SPF, DKIM and DMARC all pass.

Every matched signal also lists its evidence ("Display name 'DHL Express' claims 'dhl'
but sender domain is `parcel-redelivery-dhl.click`"), and unmatched signals are shown
with `_not matched_` so the analyst can see what *didn't* fire.

Severity auto-escalation to `critical` is governed by `critical_signal_auto_escalate`
and restricted to `SELF_EVIDENCE_CATEGORIES = {"content", "attachment"}` — a critical
hit must be self-evident in the message itself, so a third-party reputation hit alone
can never push a medium-confidence message into critical.

---

## API surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health`, `/api/health` | liveness probe |
| `GET` | `/api/status` | providers live/skipped + reasons, LLM status, detection version, limits, case count |
| `GET` | `/api/detections` | loaded ruleset + thresholds + signal catalogue + MITRE map |
| `GET` | `/api/metrics` | case counters, classification/severity histogram, generated timestamp |
| `GET` | `/api/samples` | list bundled `.eml` fixtures |
| `POST` | `/api/investigate/upload` | multipart `.eml` / `.msg` / `.txt` upload (25 MiB cap) |
| `POST` | `/api/investigate/raw` | raw RFC5322 text as `{"raw_email": "..."}` |
| `POST` | `/api/investigate/sample/{name}` | run one of the bundled samples |
| `GET` | `/api/cases?limit=&offset=&classification=&severity=&status=&search=` | paginated case list; `total` honours active filters |
| `GET` | `/api/cases/{id}` | single case |
| `PATCH` | `/api/cases/{id}/status` | analyst triage — `new` / `triaged` / `escalated` / `closed` |
| `GET` | `/api/cases/{id}/report?format=markdown\|json` | rendered Markdown report (or report + notification JSON) |
| `DELETE` | `/api/cases/{id}` | delete a case |
| `POST` | `/api/reset` | clear stored cases (demo reset) |
| `GET` | `/api/openapi.json` | machine-readable API description |

---

## Sample results

`python tools\smoke_samples.py` output:

| Sample | Classification | Severity | Score | Why |
| --- | --- | --- | --- | --- |
| `legit_it_maintenance_notice.eml` | `false_positive` | `info` | **0** | Allow-listed internal sender + SPF/DKIM/DMARC pass + clean reputation → negative weights clamp the score to 0 |
| `phish_dhl_redelivery.eml` | `suspicious` | `medium` | **54** | Lookalike domain + display-name spoof + reputation hit, but auth all passes (−20) and there is no credential URL — inconclusive, needs a human |
| `phish_invoice_attachment.eml` | `true_positive` | `critical` | **100** | Macro-instruction language + double-extension + macro-enabled attachment + failing auth |
| `phish_m365_credential_harvest.eml` | `true_positive` | `critical` | **100** | Microsoft brand impersonation + harvest URL + mismatched link + urgency/threat language |

The legit sample scoring **0** matters: it proves the rules don't flag everything — and
`phish_dhl` stopping at **54/suspicious** proves a reputation hit alone can't inflate a
message into critical.

---

## Project layout

```
SOC1/
├── phishpipe/           # core pipeline package
│   ├── config.py        # env-driven settings, paths, provider keys
│   ├── models.py        # Pydantic models: Indicator, Signal, Verdict, Case, Notification
│   ├── ingest.py        # RFC822 / headers / HTML parsing
│   ├── extract.py       # URLs, brands, attachments, auth results, urgency
│   ├── enrich.py        # pluggable providers + offline verdict dataset
│   ├── detections.py    # YAML ruleset loader + weighted scorer
│   ├── analyze.py       # scoring, confidence band, explanation
│   ├── narrative.py     # deterministic template + optional LLM polish
│   ├── report.py        # Markdown report assembly
│   ├── casestore.py     # SQLite case persistence
│   └── pipeline.py      # stage orchestration + timing
├── detections/
│   └── signals.yaml     # ★ all detection logic as data (versioned)
├── data/
│   ├── offline_verdicts.json
│   └── cases.db         # runtime (gitignored)
├── api/main.py          # FastAPI app
├── web/                 # index.html / styles.css / app.js
├── samples/             # 4 .eml fixtures
├── tests/               # 114 tests
├── tools/               # smoke_samples.py, check_syntax.py
└── docs/ARCHITECTURE.md
```

---

## Design principles

1. **Offline-first.** Every capability has a local answer; network is a bonus.
2. **Never fail closed.** A missing key degrades a provider, never the pipeline.
3. **Detection is data.** Rules are YAML, diffs are reviews, versions are traceable.
4. **Explainable by default.** Every score ships with the factors that produced it.
5. **Analyst in the loop.** The report ends with a recommended action; a human confirms.

---

## License

MIT — see `LICENSE`.
