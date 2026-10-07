# PhishPipe — Architecture

> Version 1.0.0 · detection ruleset `detections/signals.yaml` v1.0.0

---

## 1. Design goals

| Goal | How the architecture delivers it |
| --- | --- |
| **Offline-first** | Every stage has a local implementation; network enrichment is layered on top, never required. |
| **Never fail or hang without keys** | Providers are discovered from env vars, use short timeouts with no retries, and each returns a structured `EnrichmentResult` even on error. |
| **Tunable without redeploys** | Detection logic is a data file (`detections/signals.yaml`), cached on `(path, mtime)` so edits are picked up on reload, versioned in Git. |
| **Explainable** | The analyzer emits per-signal contributions and a plain-English narrative alongside the numeric score. |
| **Analyst-in-the-loop** | The pipeline *recommends*; it never auto-closes. Cases persist to SQLite for human triage. |

---

## 2. Stage graph

```
            ┌──────────────────────────────────────────────────────────┐
            │                     api/main.py (FastAPI)               │
            │   /api/investigate/upload · /api/investigate/raw · /api/cases/...  │
            └────────────────────────────┬─────────────────────────────┘
                                         │  Pipeline.run(RawEmail)
                                         ▼
   ┌────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌────────┐   ┌────────┐
   │ INGEST │──▶│ EXTRACT │──▶│ ENRICH  │──▶│ ANALYZE │──▶│  CASE  │──▶│ REPORT │
   └────────┘   └─────────┘   └─────────┘   └─────────┘   └────────┘   └────┬───┘
      raw         findings      verdicts      score/band     SQLite          │
      email       + evidence    + provider    + explanation   + MITRE         ▼
                                 results                                    ┌────────┐
                                                                            │ NOTIFY │
                                                                            └────────┘
```

Each stage is a pure-ish function over typed models (`phishpipe/models.py`) and records a
duration; the report's *Investigation timeline* section shows per-stage timings so the
analyst can see where time is spent.

---

## 3. Stage contracts

### 3.1 Ingest — `phishpipe/ingest.py`

Input: bytes or text. Output: a normalized `ParsedEmail`.

- Auto-detects format: full RFC822 (`email` stdlib parser), headers-only dump, or bare HTML/plain body.
- Parses `From`, `Reply-To`, `Return-Path`, `Subject`, `Date`, `Message-ID`, `Received` chain.
- Resolves the **displayed sender** vs the **actual envelope/mail-from** — the classic phishing tell.
- Uses the stdlib `email` parser (`policy=compat32`), which tolerates malformed MIME and mixed encodings instead of raising.

### 3.2 Extract — `phishpipe/extract.py`

Produces the two structures the scorer consumes:

- `list[Indicator]` (`models.py`) — `{type, value, source, context}` for url / domain /
  ip / email / hash / attachment / phone, each with a defanging property.
- `ContentProfile` (`extract.py`) — everything the scorer reasons about: urgency / threat
  / sensitive-request / macro-instruction hits, generic-greeting hit, brands mentioned,
  links (with anchor text), attachments (filename, declared MIME, size, extension
  chain), sender / reply-to / return-path / origin domains, display-name spoofing, brand
  impersonation, allow-list state, suspicious TLDs, shorteners, IP links, mismatched
  links, credential-harvest URLs, punycode.

Also extracts:

- **Authentication results** — SPF / DKIM / DMARC parsed from `Authentication-Results` and evaluated locally.
- **Received chain** — hops, originating IP/HELO, first-received timestamp (`build_received_chain`).
- **Brand impersonation & Lookalikes (`phishpipe/homoglyph.py`)** — match against official `brand_domains`, plus deterministic visual leetspeak normalization (`micr0s0ft` → `microsoft`, `paypa1` → `paypal`) and Levenshtein distance checks for typosquatting. Lookalike findings are attached to `LinkDetail.typosquatting` and surfaced in the report.
- **Quishing (QR Phishing) Detection** — detects prompts instructing recipients to scan QR codes on mobile cameras to bypass perimeter controls, and flags QR code attachments.
- **Host sanity** — Python 3.12 `urlparse` can raise `ValueError` on bracketed IPv4 (`http://[1.2.3.4]/`), so `_manual_host()` provides a regex fallback.

### 3.3 Enrich — `phishpipe/enrich.py`

Pluggable provider registry. Provider contract (`EnrichmentProvider` ABC):

```python
class EnrichmentProvider(ABC):
    name: str
    kind: str                      # "reputation" (HTTP) | "local" (offline)

    @abstractmethod
    def is_available(self) -> tuple[bool, str]: ...
        # (available, reason_when_not) - False when the env key is absent

    @abstractmethod
    def lookup(self, indicator: Indicator) -> EnrichmentResult: ...
        # verdict for one indicator. Must never raise.
```

Hard rules enforced by the base class:

1. `is_available()` returns `(False, "missing VT_API_KEY environment variable")` when the key is absent → the provider is **skipped**, not errored.
2. Network calls use a short explicit `timeout` and **no retries**, so an enrichment step can never hang an investigation.
3. Exceptions are caught and converted to an `EnrichmentResult` with an `error` field — the provider must never break the pipeline.
4. Every result carries `offline: bool`, and the bundle carries `providers_used` / `providers_skipped` — the UI badge reads these, so an "offline only" label can never be a lie.

**Offline verdict dataset** (`data/offline_verdicts.json`):

- Keys are **lowercased indicators** (domains, IPs, hashes, email domains) with a curated
  `{verdict, score, category, campaign}` entry each.
- Curated known-bad and known-good entries so demos run with zero outbound traffic.
- Deterministic structural heuristics for anything not in the dataset: punycode,
  dynamic-DNS, IP hosts, `@`-obfuscation, homoglyph characters, excessive subdomains.
- Ships with a disclaimer that it is a demo dataset, not a threat-intel feed.

### 3.4 Analyze — `phishpipe/detections.py` + `analyze.py`

The heart of the system. Rules live in `detections/signals.yaml`:

```yaml
version: "1.0.0"
scoring:
  true_positive_threshold: 70    # confidence >= this -> true positive
  suspicious_threshold: 30       # >= this -> suspicious, else false positive
  critical_severity_threshold: 90
  high_severity_threshold: 70
  medium_severity_threshold: 40
  low_severity_threshold: 15
  critical_signal_auto_escalate: true

signals:
  - id: content.credential_harvest_url
    title: Credential-harvesting URL pattern
    weight: 12
    severity: high
    category: content
    techniques: [T1566.002]
```

**Scoring model — weighted additive, clamped:**

```
score = clamp( Σ weight(signal matched), 0, 100 )     # analyze._confidence()
classification = score >= 70 ? true_positive
               : score >= 30 ? suspicious : false_positive
severity      = band(score) via critical/high/medium/low thresholds
```

- Only signals with a *matched* condition contribute; weights are signed, so mitigating
  factors **subtract** (e.g. `auth.all_pass_aligned` = −20, `identity.allowlisted_sender` = −30).
- Enrichment feeds the scorer too: a reputation hit adds weight (`enrich.malicious` = +25),
  all-clean subtracts (`enrich.all_clean` = −10).
- The result is clamped to `[0, 100]` so stacked signals can't produce a nonsensical value.

**Confidence band** derived from score thresholds, then **severity auto-escalation**:

```python
SELF_EVIDENCE_CATEGORIES = {"content", "attachment"}
# escalates only when a matched signal has severity == "critical"
# and its category is self-evident AND critical_signal_auto_escalate is true
```

Escalation to `critical` requires the driving evidence to be *self-evident* — content the
analyst can see in the message, or an attachment — **not** a third-party reputation hit.
This is what keeps the DHL sample at `suspicious/medium/54` rather than inflating it to
critical on the strength of a domain-list hit alone.

**Explanation generation:** for each matched signal the analyzer emits
`{id, title, weight, severity, evidence}`, lists unmatched signals as `_not matched_`,
and summarizes the result ("9/37 detection signals matched for a raw score of 54
clamped to 54/100", highest-impact signals, mitigating factors, escalation rationale).
`narrative.py` renders this into section 1 of the report and the UI's summary view.

### 3.5 Case — `phishpipe/casestore.py`

SQLite (`data/cases.db`) instead of TheHive/OpenCTI — there is no Docker in this
environment, and a local file keeps the project runnable anywhere.

- Prefixed, sortable case ID (`PHI-YYYYMMDD-xxxxxxxx`), status workflow
  (`new → triaged → escalated → closed`), classification, severity, detection version.
- Query filters: `classification`, `severity`, `status`, free-text `search`
  (subject / sender / ID), with `limit`/`offset` paging.
- **Analyst Notes & Tags**: `CaseNote` records timestamped analyst comments; tags enable custom campaign labelling and triage filtering.
- **Playbook Execution**: Records automated and manual containment actions (`quarantine`, `block_domain`, `reset_credentials`, `notify_webhook`) into the audit trail.
- **Positive Click Correlation (`record_click`)**: Correlates web proxy/gateway time-of-click telemetry. Automatically escalates case to **CRITICAL**, appends compromise tags, records audit evidence, and injects emergency credential/EDR containment playbooks.
- **Campaign Clustering (`get_campaigns`)**: Clusters stored cases by sender domain or normalized subject line to track active adversary campaigns across the enterprise.
- MITRE ATT&CK mappings come from the ruleset's `mitre` catalogue, attached per signal.

### 3.6 Report — `phishpipe/report.py` + `narrative.py`

- **Deterministic Markdown template, always.** It renders even when zero signals fire.
- **LLM polish is opt-in** (`OPENAI_API_KEY` / `LLM_API_KEY`). When enabled the model is
  given the *already-scored* facts (classification, confidence, severity, signals,
  recommended actions) with the instruction not to invent indicators, scores or
  conclusions; if the call fails or returns nothing usable, `narrative.py` falls back to
  the template. The numeric verdict never comes from the LLM.
- All URLs in the report and UI are **defanged** (`_defang()`) so a report can be pasted
  into Slack without becoming a live link.
- Markdown tables are rendered by `web/app.js:md()`; the separator-row regex is
  deliberately tolerant so any table in any generated report renders.

### 3.7 Notify — `phishpipe/narrative.py`

Produces a `NotificationMessage` — recipient address, subject line (prefix depends on
classification), and a plain-language body written for a non-technical recipient
("what this means for you" / "what happens next"). It is **always generated** — for
false positives too, as a "no action required" note — and rendered in the UI's
*User notification* tab and embedded as section 11 of the report.

---

### 3.8 Threat Intel Export (STIX 2.1) — `phishpipe/stix.py`

Generates standard OASIS STIX 2.1 JSON bundles (`GET /api/cases/{id}/stix`) with deterministic UUIDv5 identifiers:
- Maps atomic indicators (URLs, domains, IPs, file hashes) into typed STIX indicators with defanged names and pattern expressions.
- Maps detected MITRE ATT&CK techniques to `attack-pattern` SDOs.
- Emits explicit `relationship` objects (`indicates`) linking observables to attack patterns.
- Includes a top-level `report` SDO bundling the entire investigation.

### 3.9 SIEM Detection Rules (Sigma) — `phishpipe/sigma.py`

Generates multi-logsource Sigma detection rules in YAML (`GET /api/cases/{id}/sigma`) for direct ingestion into Splunk, Elastic, Sentinel, and QRadar. Maps case indicators across network proxy, DNS query, destination IP, and file hash selections.

### 3.10 Mailbox Intake Watcher & Webhooks — `phishpipe/watcher.py` & `phishpipe/webhook.py`

- **Intake Watcher**: Continuously or on-demand polls an inbox directory for pending email files (`.eml`, `.msg`, `.txt`), automatically executes the investigation pipeline, and archives processed files.
- **Webhook Dispatcher**: Formats and dispatches incident cards to Slack or generic SIEM webhooks upon high-severity confirmation.

## 4. API layer — `api/main.py`

Thin transport over `Pipeline`. Responsibilities:

- Request validation (25 MiB upload cap, empty-body checks, path-traversal guard on samples).
- Case list/get/status/delete + report rendering (`?format=markdown|json`).
- `/api/status`: provider availability + skip reasons, LLM status, detection version, limits.
- `/api/metrics`: case counters and classification/severity histograms from `CaseStore.stats()`.
- Static file serving for `web/` at `/`, plus `/api/openapi.json`.
- `/health` alias for liveness probes (in addition to `/api/health`).

## 5. Frontend — `web/`

Vanilla HTML/CSS/JS, no build step.

- Three intake modes: **upload**, **paste raw**, **run a sample**.
- Verdict gauge + 7 result tabs: **Summary, Signals, IOCs, Enrichment, Timeline,
  Full report, User notification**.
- Case queue with severity/status filters and analyst triage via
  `PATCH /api/cases/{id}/status`.
- Metrics strip polled from `/api/metrics` (case count, avg confidence, avg triage time).
- `md()` renders the Markdown report; `defang()` neutralizes URLs before display.

---

## 6. Cross-cutting concerns

**Failure isolation.** Each stage catches, records, and degrades. A provider blowing up
never takes down an investigation; its result is marked `offline: true` and it lands in
`providers_skipped` with a reason.

**No hangs.** Network calls carry explicit timeouts with no retries; a slow or dead
provider degrades to an error result instead of blocking the pipeline.

**Testability.** 129 tests cover each stage in isolation plus full pipeline runs against
the four bundled samples. `tools/smoke_samples.py` runs the same four end-to-end.

**Traceability.** Every case stores the detection `version` and per-signal weights that
produced its score, so an old case can always be explained against the ruleset that
scored it.

---

## 7. Extension points

| To add… | Do this |
| --- | --- |
| A new signal | Add an entry under `signals:` in `detections/signals.yaml`, bump `version`, open a PR. No code change. |
| A new provider | Subclass `EnrichmentProvider` in `phishpipe/enrich.py`, add it to `build_providers()`, register its env var in `config.PROVIDER_ENV_VARS`. |
| A new report section | Extend the template in `narrative.py` / `report.py` — the LLM (if enabled) is given the facts, never the structure. |
| A new intake format | Add a branch in `ingest.py`'s format auto-detection. |
| A new protected brand | Add the brand and official domain to `TARGET_BRANDS` in `phishpipe/homoglyph.py` and `brand_domains` in `detections/signals.yaml`. |
| A new webhook integration | Extend `phishpipe/webhook.py` with custom card payload builders (e.g. MS Teams, PagerDuty). |
