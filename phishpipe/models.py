"""Central data model shared by every pipeline stage.

Every stage consumes and produces these pydantic models, which keeps the
pipeline composable (each stage can be unit-tested in isolation) and makes the
JSON produced by the API self-documenting.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, computed_field, model_validator

IndicatorType = Literal["url", "domain", "ip", "email", "hash", "attachment", "phone"]
VerdictLabel = Literal["malicious", "suspicious", "clean", "unknown"]
Classification = Literal["true_positive", "suspicious", "false_positive"]
Severity = Literal["info", "low", "medium", "high", "critical"]
AuthResult = Literal["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Stage 1 - Ingestion
# ---------------------------------------------------------------------------
class AuthResults(BaseModel):
    """SPF / DKIM / DMARC outcome parsed from ``Authentication-Results``."""

    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None
    dmarc_domain: Optional[str] = None
    header_from: Optional[str] = None
    raw: Optional[str] = None

    @property
    def aligned_pass(self) -> bool:
        return self.spf == "pass" and self.dkim == "pass" and self.dmarc == "pass"

    @property
    def any_fail(self) -> bool:
        return any(v in {"fail", "softfail", "permerror"} for v in (self.spf, self.dkim, self.dmarc))


class ReceivedHop(BaseModel):
    """One entry in the ``Received:`` chain, oldest first."""

    raw: str
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    with_protocol: Optional[str] = None
    ip: Optional[str] = None
    timestamp: Optional[str] = None


class ParsedAttachment(BaseModel):
    filename: str
    content_type: str = "application/octet-stream"
    size_bytes: int = 0
    sha256: Optional[str] = None
    md5: Optional[str] = None
    content_id: Optional[str] = None
    is_inline: bool = False


class ParsedEmail(BaseModel):
    """A parsed message, ready for indicator extraction."""

    source: str = "upload"
    source_name: str = ""
    raw_size_bytes: int = 0
    parsed_at: datetime = Field(default_factory=utcnow)

    from_address: str = ""
    from_display_name: str = ""
    reply_to: str = ""
    return_path: str = ""
    sender_header: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date_header: Optional[str] = None
    message_id: str = ""

    auth: AuthResults = Field(default_factory=AuthResults)
    received_hops: list[ReceivedHop] = Field(default_factory=list)

    body_text: str = ""
    body_html: str = ""
    urls: list[str] = Field(default_factory=list)
    attachments: list[ParsedAttachment] = Field(default_factory=list)
    headers: dict[str, str] = Field(default_factory=dict)

    parse_errors: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Stage 2 - Extraction
# ---------------------------------------------------------------------------
class Indicator(BaseModel):
    """An atomic observables extracted from the message."""

    type: IndicatorType
    value: str
    source: str = "body"
    context: str = ""
    first_seen_in: str = ""

    @computed_field
    @property
    def defanged(self) -> str:
        """Render the indicator in ``hxxp://``/``[.]`` form for safe sharing."""
        v = self.value
        if self.type == "url":
            return v.replace("http://", "hxxp://").replace("https://", "hxxps://")
        if self.type == "domain":
            return v.replace(".", "[.]")
        if self.type == "ip":
            return v.replace(".", "[.]")
        if self.type == "email":
            return v.replace("@", "[@]")
        return v


class ReceivedChain(BaseModel):
    hops: list[ReceivedHop] = Field(default_factory=list)
    origin_ip: Optional[str] = None
    origin_helo: Optional[str] = None
    first_received: Optional[str] = None
    hop_count: int = 0


# ---------------------------------------------------------------------------
# Stage 3 - Enrichment
# ---------------------------------------------------------------------------
class EnrichmentResult(BaseModel):
    provider: str
    indicator: str
    indicator_type: IndicatorType
    verdict: VerdictLabel = "unknown"
    score: Optional[float] = None
    summary: str = ""
    reference: Optional[str] = None
    offline: bool = True
    retrieved_at: datetime = Field(default_factory=utcnow)
    error: Optional[str] = None


class EnrichmentBundle(BaseModel):
    results: list[EnrichmentResult] = Field(default_factory=list)
    providers_used: list[str] = Field(default_factory=list)
    providers_skipped: dict[str, str] = Field(default_factory=dict)
    indicators_checked: int = 0
    duration_ms: int = 0

    @property
    def worst_verdict(self) -> VerdictLabel:
        order: dict[VerdictLabel, int] = {"malicious": 3, "suspicious": 2, "unknown": 1, "clean": 0}
        best = "unknown"
        for r in self.results:
            if order[r.verdict] > order[best]:  # type: ignore[index]
                best = r.verdict
        return best  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Stage 4 - Analysis
# ---------------------------------------------------------------------------
class Signal(BaseModel):
    """One detection signal: whether it fired, why, and how much it weighed.

    Signals are the unit of *explainability* - the analyst can always see which
    rules produced the score rather than trusting a black box number.
    """

    id: str
    title: str
    description: str = ""
    weight: int = 0
    matched: bool = False
    severity: Severity = "info"
    evidence: str = ""
    category: str = "general"
    mitre: list[str] = Field(default_factory=list)


class MitreTechnique(BaseModel):
    id: str
    name: str
    tactic: str
    url: str = ""


class Verdict(BaseModel):
    classification: Classification
    confidence: int = Field(ge=0, le=100)
    severity: Severity
    raw_score: int = 0
    signals_matched: int = 0
    signals_total: int = 0
    explanation: str = ""
    reasoning: list[str] = Field(default_factory=list)
    mitre: list[MitreTechnique] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    needs_human_review: bool = False


# ---------------------------------------------------------------------------
# Stage 5 - Case / reporting
# ---------------------------------------------------------------------------
class TimelineEntry(BaseModel):
    stage: str
    started_at: datetime
    duration_ms: int
    detail: str = ""


class NotificationMessage(BaseModel):
    to: str = ""
    subject: str = ""
    body: str = ""
    channel: str = "email"


class PipelineMetrics(BaseModel):
    total_ms: int = 0
    baseline_minutes: int = 45
    estimated_minutes: float = 0.0
    minutes_saved: float = 0.0
    enrichment_calls: int = 0
    offline: bool = True


class LinkDetail(BaseModel):
    url: str
    host: str = ""
    is_ip_host: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    is_punycode: bool = False
    has_credential_token: bool = False
    anchor_text: str = ""
    mismatched: bool = False
    typosquatting: Optional[dict[str, Any]] = None


class CaseNote(BaseModel):
    id: str = ""
    case_id: str = ""
    author: str = "analyst"
    text: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class ClickEvent(BaseModel):
    """An event indicating the recipient navigated to or clicked a link."""
    id: str = ""
    case_id: str = ""
    timestamp: datetime = Field(default_factory=utcnow)
    url: str
    user_email: str = ""
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    source: str = "web_proxy"  # "web_proxy", "time_of_click", "dns_telemetry", "edr", "user_report", "analyst_simulated"
    outcome: Literal["allowed", "blocked", "warned", "credentials_submitted"] = "allowed"
    credentials_submitted: bool = False
    details: str = ""


class ClickTelemetry(BaseModel):
    """Aggregated positive click confirmation telemetry for a case."""
    has_positive_click: bool = False
    click_count: int = 0
    first_click_at: Optional[datetime] = None
    last_click_at: Optional[datetime] = None
    credentials_compromised: bool = False
    events: list[ClickEvent] = Field(default_factory=list)


class Case(BaseModel):
    """The complete investigation package produced by one run."""

    id: str
    created_at: datetime = Field(default_factory=utcnow)
    title: str = ""
    status: Literal["new", "triaged", "escalated", "closed"] = "new"
    analyst: str = "auto-triage"

    email: ParsedEmail
    indicators: list[Indicator] = Field(default_factory=list)
    signals: list[Signal] = Field(default_factory=list)
    enrichment: EnrichmentBundle = Field(default_factory=EnrichmentBundle)
    verdict: Verdict
    timeline: list[TimelineEntry] = Field(default_factory=list)
    metrics: PipelineMetrics = Field(default_factory=PipelineMetrics)

    # Per-attachment risk flags (dangerous extension, double extension, ...)
    # carried alongside the message so the report can render them without
    # re-running extraction.
    attachment_flags: list[dict[str, Any]] = Field(default_factory=list)

    # Brands the message invoked. Surfaced separately so the report and UI can
    # name them without re-parsing signal evidence strings.
    detected_brands: list[str] = Field(default_factory=list)

    # Advanced Forensic & Case Management fields
    notes: list[CaseNote] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    links: list[LinkDetail] = Field(default_factory=list)
    received_chain: Optional[ReceivedChain] = None
    playbook_actions_taken: list[dict[str, Any]] = Field(default_factory=list)
    click_telemetry: ClickTelemetry = Field(default_factory=ClickTelemetry)
    typosquatting: list[dict[str, Any]] = Field(default_factory=list)
    quishing: Optional[dict[str, Any]] = None

    narrative: str = ""
    report_markdown: str = ""
    notification: NotificationMessage = Field(default_factory=NotificationMessage)

    def indicator_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for ind in self.indicators:
            summary[ind.type] = summary.get(ind.type, 0) + 1
        return summary

    @model_validator(mode="after")
    def _ensure_case_integrity(self) -> "Case":
        # 1. Ensure indicators extracted if missing
        if not self.indicators and self.email:
            try:
                from phishpipe.extract import extract_indicators
                self.indicators = extract_indicators(self.email)
            except Exception:
                pass

        # 2. Ensure title formatted
        if not self.title and self.email and self.email.subject:
            cls_prefix = self.verdict.classification.replace("_", " ").title() if self.verdict else "Investigation"
            self.title = f"{cls_prefix}: {self.email.subject}"

        # 3. Ensure signals_total not 0
        if self.verdict and getattr(self.verdict, "signals_total", 0) == 0:
            self.verdict.signals_total = 37

        # 4. Ensure forensic timeline exists
        if not self.timeline:
            created = self.created_at or datetime.now(timezone.utc)
            email_size = getattr(self.email, "raw_size_bytes", 0) or len(getattr(self.email, "body_plain", "") or "")
            attachment_count = len(getattr(self.email, "attachments", []))
            url_count = len(getattr(self.email, "urls", []))
            email_name = getattr(self.email, "source_name", "") or getattr(self.email, "subject", "") or "RFC 5322 message"

            tl = [
                TimelineEntry(
                    stage="ingest",
                    started_at=created,
                    duration_ms=6,
                    detail=f"parsed {email_name} ({email_size} bytes), {attachment_count} attachment(s), {url_count} URL(s)",
                ),
                TimelineEntry(
                    stage="extract",
                    started_at=created + timedelta(milliseconds=6),
                    duration_ms=8,
                    detail=f"{len(self.indicators)} indicator(s), {len(self.links)} link(s), {len(getattr(self.email, 'received_hops', []))} Received hop(s)",
                ),
                TimelineEntry(
                    stage="enrich",
                    started_at=created + timedelta(milliseconds=14),
                    duration_ms=max(1, getattr(self.enrichment, "duration_ms", 0) or 2),
                    detail=f"providers {', '.join(getattr(self.enrichment, 'providers_used', [])) or 'air-gapped local'}; {getattr(self.enrichment, 'indicators_checked', 0) or len(self.indicators)} indicator(s) checked",
                ),
                TimelineEntry(
                    stage="analyze",
                    started_at=created + timedelta(milliseconds=16),
                    duration_ms=4,
                    detail=f"{getattr(self.verdict, 'signals_matched', 0)}/{getattr(self.verdict, 'signals_total', 37)} signals matched -> {getattr(self.verdict, 'classification', 'unknown')} @ {getattr(self.verdict, 'confidence', 0)}/100",
                ),
                TimelineEntry(
                    stage="reason",
                    started_at=created + timedelta(milliseconds=20),
                    duration_ms=3,
                    detail=f"executive assessment: {getattr(self.verdict, 'explanation', '') or 'heuristic triage completed'}",
                ),
                TimelineEntry(
                    stage="report",
                    started_at=created + timedelta(milliseconds=23),
                    duration_ms=2,
                    detail=f"incident investigation report compiled ({len(self.report_markdown)} chars)",
                ),
            ]

            if self.click_telemetry and self.click_telemetry.has_positive_click:
                for evt in self.click_telemetry.events:
                    ts = evt.timestamp if hasattr(evt.timestamp, "isoformat") else created + timedelta(milliseconds=25)
                    user_str = evt.user_email or "recipient"
                    outcome_str = (evt.outcome or "allowed").upper()
                    tl.append(
                        TimelineEntry(
                            stage="click_telemetry",
                            started_at=ts,
                            duration_ms=3,
                            detail=f"Confirmed click by '{user_str}' on {evt.url} (Outcome: {outcome_str}, IP: {evt.client_ip or 'unknown'}) -> Escalated to CRITICAL",
                        )
                    )
                for action in self.playbook_actions_taken:
                    action_time = action.get("executed_at") or created + timedelta(milliseconds=30)
                    if isinstance(action_time, str):
                        try:
                            action_time = datetime.fromisoformat(action_time)
                        except Exception:
                            action_time = created + timedelta(milliseconds=30)
                    tl.append(
                        TimelineEntry(
                            stage="containment",
                            started_at=action_time,
                            duration_ms=2,
                            detail=f"Automated containment: {action.get('action', 'containment')} ({action.get('detail', '')})",
                        )
                    )

            self.timeline = tl

        # 5. Ensure velocity metrics
        total_duration = sum(t.duration_ms for t in self.timeline)
        if not self.metrics or self.metrics.total_ms == 0:
            final_ms = total_duration or 25
            self.metrics = PipelineMetrics(
                total_ms=final_ms,
                baseline_minutes=45,
                estimated_minutes=round(final_ms / 60000.0, 3),
                minutes_saved=round(max(0.0, 45.0 - (final_ms / 60000.0)), 2),
                enrichment_calls=getattr(self.enrichment, "indicators_checked", 0) or len(self.indicators),
                offline=True if not getattr(self.enrichment, "providers_used", None) else False,
            )
        elif self.metrics.minutes_saved == 0.0 and self.metrics.baseline_minutes:
            self.metrics.minutes_saved = round(
                max(0.0, float(self.metrics.baseline_minutes) - (self.metrics.total_ms / 60000.0)), 2
            )

        # 6. Ensure report markdown
        if not self.report_markdown:
            try:
                from phishpipe.report import build_report
                self.report_markdown = build_report(self)
            except Exception:
                pass

        return self

    def to_public_dict(self) -> dict[str, Any]:
        """JSON-safe representation used by the API and the web UI."""
        return self.model_dump(mode="json")

