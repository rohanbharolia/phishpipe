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
   └───────┬────────┘  brands, urgency language, thread position
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
   └───────┬────────┘  auto-triage: disposition / severity / action
           ▼
   ┌────────────────┐
   │ 6. REPORT      │  deterministic Markdown template, always
   └───────┬────────┘  optional LLM narrative polish if a key exists
           ▼
   ┌────────────────┐
   │ 7. NOTIFY      │  webhook / SMTP if configured, otherwise a
   └────────────────┘  rendered in-app notification preview
```

---

## Why it works without API keys

| Concern | Offline answer |
| --- | --- |
| URL / domain reputation | `data/offline_verdicts.json` — curated known-bad + known-good entries, SHA-256 hashed URL keys, plus heuristic scoring (punycode, dynamic-DNS, IP hosts, `@`-obfuscation, homoglyphs) |
| SPF / DKIM / DMARC | Parsed straight from the `Authentication-Results` header and evaluated locally |
| Attachment detonation | Local type sniffing (magic bytes), double-extension and macro heuristics, ZIP/Office inspection |
| Case management | SQLite (`data/cases.db`) — no TheHive / OpenCTI / Docker |
| Report writing | Deterministic Markdown template that renders even with zero signals fired |
| Notifications | Webhook/SMTP when configured, otherwise an in-app preview pane |
| LLM narrative | Opt-in only; falls back to the template automatically |

Every provider follows the same contract: **never raise, never hang, always return a
structured `ProviderResult`.** Network providers carry a hard timeout, a circuit breaker
after repeated failures, and are skipped entirely when their key is absent.

---

## Optional provider keys

Set any of these to activate live enrichment. Everything else keeps working untouched.

| Env var | Enables | Fallback when unset |
| --- | --- | --- |
| `ABUSEIPDB_KEY` | AbuseIPDB blacklist check | offline verdict dataset + heuristics |
| `VIRUSTOTAL_KEY` | VirusTotal URL/file verdict | offline verdict dataset |
| `URLHAUS_KEY` | URLhaus malware-URL feed | offline verdict dataset |
| `OPENPHISH_KEY` | OpenPhish phishing feed | offline verdict dataset |
| `OTX_KEY` | AlienVault OTX pulse lookup | offline verdict dataset |
| `OPENAI_API_KEY` / `LLM_API_KEY` | LLM narrative polish on the report | deterministic template |
| `SMTP_HOST` (+ `SMTP_USER`, `SMTP_PASS`, `SMTP_PORT`) | Real email delivery of the alert | in-app notification preview |
| `WEBHOOK_URL` | POST the alert to a webhook | in-app notification preview |

`GET /api/providers` reports which providers are live and which are offline.

---

## Detection logic as data

All detection logic lives in **`detections/signals.yaml`** — versioned, reviewable, and
tunable as a plain Git diff. No redeploys.

```yaml
version: "1.0.0"
scoring:
  base: 0
  clamp: [0, 100]          # additive score is clamped to 0–100
  thresholds:
    info: 0
    low: 35
    medium: 55
    high: 75
    critical: 90
```

Each signal declares a `weight`, a `description`, and where it gets its evidence:

```yaml
signals:
  urgent_language:
    weight: 15
    description: "Uses urgency or deadline pressure language"
    category: content
    words: ["urgent", "immediately", "within 24 hours", "suspended", "verify your account"]
```

**Tuning a rule is a one-line diff.** Bump `version`, open a PR, and the change is
reviewable in isolation. `GET /api/detections` returns the loaded ruleset + version at
runtime, so the analyst can always see *which* ruleset produced a verdict.

### Confidence explanation

The analyzer produces a human-readable explanation alongside the score, e.g.:

> **Confidence: high (score 78).** This message is likely malicious. Contributing
> factors: credential-harvesting URL on a lookalike domain (weight 25), brand
> impersonation of *Microsoft* (weight 20), urgent deadline pressure (weight 15),
> sender domain registered 3 days ago (weight 18). Offsetting factor: message passed
> SPF/DKIM/DMARC alignment (−10). Auto-escalated to **critical** because attachment
> content matched a known-malicious pattern.

Severity auto-escalation to `critical` is restricted to
`SELF_EVIDENCE_CATEGORIES = {"content", "attachment"}` — a reputation hit alone can
never push a medium-confidence message into critical.

---

## API surface

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health`, `/api/health` | liveness + detection version + provider status |
| `GET` | `/api/status` | pipeline stage timings, rule version, provider flags |
| `GET` | `/api/detections` | loaded ruleset + version + active weights |
| `GET` | `/api/metrics` | counters, score histogram, rate-limited, mean latency |
| `POST` | `/api/investigate/upload` | multipart `.eml` / `.txt` / `.html` upload |
| `POST` | `/api/investigate/raw` | raw message body as JSON |
| `GET` | `/api/investigate/sample/{name}` | run one of the bundled samples |
| `GET` | `/api/cases` | paginated case list (`?status=&severity=&q=`) |
| `GET` | `/api/cases/{id}` | single case |
| `PATCH` | `/api/cases/{id}` | analyst triage (status / severity / notes) |
| `GET` | `/api/cases/{id}/report` | rendered Markdown report |
| `POST` | `/api/reset` | clear stored cases (dev) |

---

## Sample results

`python tools\smoke_samples.py` output:

| Sample | Disposition | Severity | Score | Why |
| --- | --- | --- | --- | --- |
| `legit_receipt.eml` | `false_positive` | `info` | **0** | Genuine receipt, no signals fired — correctly *not* flagged |
| `dhl_tracking.eml` | `suspicious` | `medium` | **54** | Lookalike domain + urgency, but no direct credential URL |
| `invoice_2024.eml` | `true_positive` | `critical` | **100** | Macro-enabled invoice attachment + credential URL |
| `m365_verify.eml` | `true_positive` | `critical` | **100** | Microsoft impersonation + harvest URL + urgent deadline |

The legit sample scoring **0** matters: it proves the rules don't just fire on everything.

---

## Project layout

```
SOC1/
├── phishpipe/           # core pipeline package
│   ├── config.py        # env-driven settings, paths, provider keys
│   ├── models.py        # dataclasses: Message, Finding, Verdict, Case
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
