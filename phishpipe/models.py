"""Central data model shared by every pipeline stage.

Every stage consumes and produces these pydantic models, which keeps the
pipeline composable (each stage can be unit-tested in isolation) and makes the
JSON produced by the API self-documenting.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

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

    narrative: str = ""
    report_markdown: str = ""
    notification: NotificationMessage = Field(default_factory=NotificationMessage)

    def indicator_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for ind in self.indicators:
            summary[ind.type] = summary.get(ind.type, 0) + 1
        return summary

    def to_public_dict(self) -> dict[str, Any]:
        """JSON-safe representation used by the API and the web UI."""
        return self.model_dump(mode="json")
