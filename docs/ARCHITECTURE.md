# PhishPipe — Architecture

> Version 1.0.0 · detection ruleset `detections/signals.yaml` v1.0.0

---

## 1. Design goals

| Goal | How the architecture delivers it |
| --- | --- |
| **Offline-first** | Every stage has a local implementation; network enrichment is layered on top, never required. |
| **Never fail or hang without keys** | Providers are discovered lazily from env vars, wrapped in timeouts + a circuit breaker, and each returns a structured `ProviderResult` even on error. |
| **Tunable without redeploys** | Detection logic is a data file (`detections/signals.yaml`), loaded and hot-reloadable, versioned in Git. |
| **Explainable** | The analyzer emits per-signal contributions and a plain-English narrative alongside the numeric score. |
| **Analyst-in-the-loop** | The pipeline *recommends*; it never auto-closes. Cases persist to SQLite for human triage. |

---

## 2. Stage graph

```
            ┌──────────────────────────────────────────────────────────┐
            │                     api/main.py (FastAPI)               │
            │   /investigate/upload · /investigate/raw · /cases/...    │
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
duration; the pipeline returns stage timings so the UI and `/api/status` can show where
time is spent.

---

## 3. Stage contracts

### 3.1 Ingest — `phishpipe/ingest.py`

Input: bytes or text. Output: a normalized `Message`.

- Auto-detects format: full RFC822 (`email` stdlib parser), headers-only dump, or bare HTML/plain body.
- Parses `From`, `Reply-To`, `Return-Path`, `Subject`, `Date`, `Message-ID`, `Received` chain.
- Resolves the **displayed sender** vs the **actual envelope/mail-from** — the classic phishing tell.
- Tolerates malformed MIME (defects are recorded, not raised) and mixed encodings.

### 3.2 Extract — `phishpipe/extract.py`

Produces `Finding` objects, each carrying `category`, `value`, `evidence`, `weight_source`.

- **URLs** — defanged (`hxxp://`, `[.]`, `(.)`) and raw forms, deduped, host-normalized.
- **Domains / IPs** — registrable domain extraction, punycode detection, IP-literal hosts.
- **Attachments** — filename, declared MIME, sniffed MIME (magic bytes), size, extension-chain analysis.
- **Brand impersonation** — match against `brand_domains` wordlist, then confirm the sender is *not* the official domain via `_is_official_brand_sender()`. Suppressed for allow-listed/internal senders.
- **Authentication results** — SPF / DKIM / DMARC parsed from `Authentication-Results` and evaluated locally.
- **Urgency / threat language** — keyword match against the ruleset wordlist.
- **Thread position** — is this a cold-open reply, a reply-injected message, or a new thread.
- **Host sanity** — Python 3.12 `urlparse` can raise `ValueError` on bracketed IPv4 (`http://[1.2.3.4]/`), so `_manual_host()` provides a regex fallback.

### 3.3 Enrich — `phishpipe/enrich.py`

Pluggable provider registry. Provider contract:

```python
class Provider(Protocol):
    name: str
    def available(self) -> bool: ...          # env key present?
    def enrich(self, target, kind) -> ProviderResult: ...
```

Hard rules enforced by the base class:

1. `available()` returns `False` when the key is absent → the provider is **skipped**, not errored.
2. Every call is wrapped in a **timeout**; failures increment a **circuit breaker**, after which the provider is skipped for the remainder of the run.
3. Exceptions are caught and converted to `ProviderResult(ok=False, reason=...)`.
4. Results always land in `enrichment.results_offline_only` or `results_live` — the UI badge reads this, so a "LIVE PROVIDERS" label can never be a lie.

**Offline verdict dataset** (`data/offline_verdicts.json`):

- SHA-256 hashed URL keys for exact matches (privacy-preserving, no raw URL stored).
- Curated known-bad and known-good domain lists.
- Heuristic scoring for anything not in the dataset: punycode, dynamic-DNS, IP hosts, `@`-obfuscation, homoglyph characters, excessive subdomains.

### 3.4 Analyze — `phishpipe/detections.py` + `analyze.py`

The heart of the system. Rules live in `detections/signals.yaml`:

```yaml
version: "1.0.0"
scoring:
  base: 0
  clamp: [0, 100]
  thresholds: { info: 0, low: 35, medium: 55, high: 75, critical: 90 }
signals:
  credential_harvest_url:
    weight: 25
    category: content
    description: "URL points at a credential-harvesting path or lookalike host"
```

**Scoring model — weighted additive, clamped:**

```
score = clamp( Σ weight(signal fired) + Σ Δ(weight from enrichment) , 0, 100 )
```

- Only signals with a *matched* condition contribute.
- Enrichment can **add** (reputation hit) or **subtract** (SPF+DKIM+DMARC alignment pass) weight.
- The result is clamped to `[0, 100]` so stacked signals can't produce a nonsensical value.

**Confidence band** derived from score thresholds, then **severity auto-escalation**:

```python
SELF_EVIDENCE_CATEGORIES = {"content", "attachment"}
```

Escalation to `critical` requires the driving evidence to be *self-evident* — content the
analyst can see in the message, or an attachment — **not** a third-party reputation hit.
This is what keeps the DHL sample at `suspicious/medium/54` rather than inflating it to
critical on the strength of a domain-list hit alone.

**Explanation generation:** for each fired signal the analyzer emits
`{signal, weight, description, matched_evidence}`, plus offsets (e.g. "passed
SPF/DKIM/DMARC alignment, −10"), plus any escalation rationale. `narrative.py` renders
these into the paragraph shown in the UI's *Confidence* tab.

### 3.5 Case — `phishpipe/casestore.py`

SQLite (`data/cases.db`) instead of TheHive/OpenCTI — there is no Docker in this
environment, and a local file keeps the project runnable anywhere.

- Auto-increment case ID, status workflow (`new → triaged → closed`), severity, analyst notes.
- Query filters: `status`, `severity`, free-text `q` (subject / sender / ID).
- `total` reflects the **filtered** count, not the table count.
- MITRE ATT&CK mappings come from the ruleset's `mitre` catalogue, attached per signal.

### 3.6 Report — `phishpipe/report.py` + `narrative.py`

- **Deterministic Markdown template, always.** It renders even when zero signals fire.
- **LLM polish is opt-in** (`OPENAI_API_KEY` / `LLM_API_KEY`); the LLM may reword
  *narrative* sections but cannot alter scores, verdicts, or evidence tables.
- All URLs in the report and UI are **defanged** (`_defang()`) so a report can be pasted
  into Slack without becoming a live link.
- Markdown tables are rendered by `web/app.js:md()`; the separator-row regex is
  deliberately tolerant so any table in any generated report renders.

### 3.7 Notify — `phishpipe/narrative.py` / `report.py`

- `WEBHOOK_URL` → POST the alert JSON.
- `SMTP_*` → send the Markdown alert by email.
- Neither configured → the alert is still fully rendered in the **notification preview**
  pane of the UI. Notification is never silently skipped.

---

## 4. API layer — `api/main.py`

Thin transport over `Pipeline`. Responsibilities:

- Request validation (upload size limits, format sniffing).
- Case CRUD + report rendering.
- `/api/metrics`: counters, score histogram, mean latency, rate-limited count.
- Static file serving for `web/` at `/`.
- `/health` alias for liveness probes (in addition to `/api/health`).

## 5. Frontend — `web/`

Vanilla HTML/CSS/JS, no build step.

- Three intake modes: **upload**, **paste raw**, **run a sample**.
- Verdict gauge + 7 result tabs (Summary, Extracted, Enrichment, Confidence, MITRE, Report, Notification).
- Case queue with status/severity filters and analyst triage (PATCH).
- Metrics strip polled from `/api/metrics`.
- `md()` renders the Markdown report; `defang()` neutralizes URLs before display.

---

## 5. Cross-cutting concerns

**Failure isolation.** Each stage catches, records, and degrades. A provider blowing up
never takes down an investigation; the result simply marks that provider as
`offline_only`.

**No hangs.** Network calls carry explicit timeouts; the circuit breaker stops retrying
a dead provider mid-run.

**Testability.** 114 tests cover each stage in isolation plus full pipeline runs against
the four bundled samples. `tools/smoke_samples.py` runs the same four end-to-end.

**Traceability.** Every case stores the detection `version` and per-signal weights that
produced its score, so an old case can always be explained against the ruleset that
scored it.

---

## 6. Extension points

| To add… | Do this |
| --- | --- |
| A new signal | Add an entry under `signals:` in `detections/signals.yaml`, bump `version`, open a PR. No code change. |
| A new provider | Implement the `Provider` protocol in `phishpipe/enrich.py`, register it, add its env var to `config.py`. |
| A new report section | Extend the template in `narrative.py` — the LLM (if enabled) may reword but not restructure. |
| A new intake format | Add a branch in `ingest.py`'s format auto-detection. |
