"""Stage 5 - Reporting: structured incident report in Markdown.

The report is the deliverable an analyst hands to the business, so it follows the
same shape every time: summary -> message details -> timeline -> IOCs ->
findings -> ATT&CK -> verdict -> actions. Indicators are rendered defanged so the
report can be pasted into chat or a ticket without becoming a live link.
"""

from __future__ import annotations

import re
from datetime import datetime

from phishpipe.models import Case, EnrichmentResult

_CLS_LABEL = {
    "true_positive": "TRUE POSITIVE",
    "suspicious": "SUSPICIOUS - HUMAN REVIEW REQUIRED",
    "false_positive": "FALSE POSITIVE",
}

_SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "⚪",
}


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt.tzinfo else dt.strftime("%Y-%m-%d %H:%M:%S")


def _yes_no(value: bool) -> str:
    return "✅ pass" if value else "❌ fail"


def _escape(text: str) -> str:
    """Keep free text from breaking Markdown tables."""
    return (text or "").replace("|", "\\|").replace("\n", " ").strip()


def _defang(text: str | None, indicators=()) -> str:
    """Neutralise live URLs inside free-text such as evidence and context.

    The IOC column is rendered with :attr:`Indicator.defanged`, but the sentence
    around it is analyst-authored text that frequently quotes the same URL. If
    that were left live the report would be a click-away hazard despite the
    "indicators are defanged" promise in its own footer.
    """
    out = text or ""
    for indicator in indicators:
        out = out.replace(indicator.value, indicator.defanged)
    # Anything still carrying a scheme (e.g. quoted inside a longer sentence).
    out = re.sub(r"https?://", lambda m: m.group(0).replace("http", "hxxp"), out)
    return out


def build_report(case: Case, detections_version: str = "unknown") -> str:
    e = case.email
    v = case.verdict
    lines: list[str] = []

    # --- Header ------------------------------------------------------------
    lines.append(f"# Incident Report - {case.title}")
    lines.append("")
    lines.append(f"**Case ID:** `{case.id}`  ")
    lines.append(f"**Created:** {_fmt_ts(case.created_at)}  ")
    lines.append(f"**Status:** {case.status}  ")
    lines.append(f"**Detection logic version:** `{detections_version}`  ")
    lines.append(
        f"**Triage mode:** {'offline (local verdict cache)' if case.metrics.offline else 'live reputation lookups'}  "
    )
    lines.append(f"**Processing time:** {case.metrics.total_ms} ms")
    lines.append("")

    # --- Verdict -----------------------------------------------------------
    lines.append("## 1. Verdict")
    lines.append("")
    lines.append(
        f"| Classification | Severity | Confidence | Signals matched | Human review |"
    )
    lines.append("|---|---|---|---|---|")
    lines.append(
        f"| **{_CLS_LABEL[v.classification]}** | {_SEVERITY_ICON[v.severity]} {v.severity} "
        f"| **{v.confidence}/100** | {v.signals_matched}/{v.signals_total} "
        f"| {'⚠️ yes' if v.needs_human_review else 'no'} |"
    )
    lines.append("")
    lines.append(f"> {v.explanation}")
    lines.append("")
    lines.append("**Confidence explanation**")
    for step in v.reasoning:
        lines.append(f"- {step}")
    lines.append("")

    # --- Executive summary -------------------------------------------------
    lines.append("## 2. Investigation summary")
    lines.append("")
    lines.append(_defang(case.narrative, case.indicators) or "_Narrative not generated._")
    lines.append("")

    # --- Message details ---------------------------------------------------
    lines.append("## 3. Message details")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|---|---|")
    lines.append(f"| Subject | {_escape(e.subject) or '_none_'} |")
    lines.append(f"| From | {_escape(e.from_display_name)} `{_escape(e.from_address)}` |")
    lines.append(f"| To | {_escape(', '.join(e.to)) or '_none_'} |")
    if e.cc:
        lines.append(f"| Cc | {_escape(', '.join(e.cc))} |")
    lines.append(f"| Reply-To | `{_escape(e.reply_to) or '_none_'}` |")
    lines.append(f"| Return-Path | `{_escape(e.return_path) or '_none_'}` |")
    lines.append(f"| Date | {_escape(e.date_header or '') or '_none_'} |")
    lines.append(f"| Message-ID | `{_escape(e.message_id) or '_none_'}` |")
    lines.append(f"| Size | {e.raw_size_bytes} bytes |")
    lines.append(f"| Attachments | {len(e.attachments)} |")
    if case.detected_brands:
        lines.append(f"| Brands referenced | {', '.join(case.detected_brands)} |")
    lines.append(f"| Source | {_escape(e.source_name) or e.source} |")
    lines.append("")

    lines.append("### Authentication results")
    lines.append("")
    lines.append("| Check | Result |")
    lines.append("|---|---|")
    lines.append(f"| SPF | {e.auth.spf or '_not evaluated_'} |")
    lines.append(f"| DKIM | {e.auth.dkim or '_not evaluated_'} |")
    lines.append(f"| DMARC | {e.auth.dmarc or '_not evaluated_'}{f' ({e.auth.dmarc_domain})' if e.auth.dmarc_domain else ''} |")
    lines.append(f"| DMARC header.from | {e.auth.header_from or '_n/a_'} |")
    lines.append("")

    if e.received_hops:
        lines.append("### Received chain (oldest first)")
        lines.append("")
        lines.append("| # | From | By | With | IP | Timestamp |")
        lines.append("|---|---|---|---|---|---|")
        for i, hop in enumerate(e.received_hops, 1):
            lines.append(
                f"| {i} | {_defang(hop.from_host, case.indicators) or '-'} "
                f"| {_defang(hop.by_host, case.indicators) or '-'} "
                f"| {_escape(hop.with_protocol or '') or '-'} | {hop.ip or '-'} "
                f"| {_escape(hop.timestamp or '') or '-'} |"
            )
        lines.append("")

    # --- Timeline ----------------------------------------------------------
    lines.append("## 4. Investigation timeline")
    lines.append("")
    lines.append("| # | Stage | Started | Duration | Detail |")
    lines.append("|---|---|---|---|---|")
    for i, entry in enumerate(case.timeline, 1):
        lines.append(
            f"| {i} | {entry.stage} | {_fmt_ts(entry.started_at)} | {entry.duration_ms} ms "
            f"| {_escape(entry.detail)} |"
        )
    lines.append("")
    m = case.metrics
    lines.append(
        f"**Time saved vs. manual triage:** ~{m.minutes_saved:.0f} minutes "
        f"(automated {m.estimated_minutes:.2f} min vs. {m.baseline_minutes} min manual baseline)."
    )
    lines.append("")

    # --- IOC table ---------------------------------------------------------
    lines.append("## 5. Indicators of Compromise")
    lines.append("")
    if case.indicators:
        summary = case.indicator_summary()
        lines.append(
            "**Totals:** "
            + ", ".join(f"{count} {kind}" for kind, count in sorted(summary.items()))
        )
        lines.append("")
        lines.append("| Type | Indicator (defanged) | Source | Context |")
        lines.append("|---|---|---|---|")
        for ind in case.indicators:
            lines.append(
                f"| {ind.type} | `{_escape(ind.defanged)}` | {ind.source} "
                f"| {_escape(_defang(ind.context, case.indicators))[:120]} |"
            )
    else:
        lines.append("_No indicators extracted._")
    lines.append("")

    # --- Enrichment --------------------------------------------------------
    lines.append("## 6. Enrichment")
    lines.append("")
    lines.append(
        f"Providers used: **{', '.join(case.enrichment.providers_used) or 'none'}** | "
        f"{case.enrichment.indicators_checked} indicator(s) checked in {case.enrichment.duration_ms} ms"
    )
    lines.append("")
    if case.enrichment.providers_skipped:
        lines.append("Providers skipped:")
        for provider, reason in case.enrichment.providers_skipped.items():
            lines.append(f"- `{provider}` - {reason}")
        lines.append("")
    if case.enrichment.results:
        lines.append("| Provider | Indicator | Verdict | Score | Summary |")
        lines.append("|---|---|---|---|---|")
        for r in case.enrichment.results:
            lines.append(
                f"| {r.provider} | `{_escape(_defang(r.indicator, case.indicators))[:60]}` "
                f"| **{r.verdict.upper()}** "
                f"| {r.score if r.score is not None else '-'} | {_escape(r.summary)[:110]} |"
            )
    else:
        lines.append("_No enrichment performed._")
    lines.append("")

    # --- Findings ----------------------------------------------------------
    lines.append("## 7. Analysis findings")
    lines.append("")
    lines.append("| Signal | Matched | Weight | Severity | Evidence |")
    lines.append("|---|---|---|---|---|")
    for sig in case.signals:
        mark = "✅" if sig.matched else "—"
        evidence = _escape(_defang(sig.evidence, case.indicators))[:130] if sig.matched else "_not matched_"
        lines.append(
            f"| `{sig.id}` {sig.title} | {mark} | {sig.weight:+d} | {sig.severity} | {evidence} |"
        )
    lines.append("")

    # --- MITRE -------------------------------------------------------------
    lines.append("## 8. MITRE ATT&CK mapping")
    lines.append("")
    if v.mitre:
        lines.append("| Technique | Name | Tactic | Reference |")
        lines.append("|---|---|---|---|")
        for t in v.mitre:
            lines.append(f"| {t.id} | {t.name} | {t.tactic} | [ATT&CK]({t.url}) |")
    else:
        lines.append("_No technique mapped._")
    lines.append("")

    # --- Attachments -------------------------------------------------------
    if e.attachments:
        lines.append("## 9. Attachments")
        lines.append("")
        lines.append("| Filename | Type | Size | SHA-256 | Notes |")
        lines.append("|---|---|---|---|---|")
        for idx, att in enumerate(e.attachments):
            obs = case.attachment_flags[idx] if idx < len(case.attachment_flags) else {}
            notes = []
            if obs.get("dangerous_ext"):
                notes.append("dangerous extension")
            if obs.get("double_extension"):
                notes.append("double extension")
            if obs.get("macro_ext"):
                notes.append("macro-capable")
            if obs.get("content_type_mismatch"):
                notes.append("MIME/extension mismatch")
            lines.append(
                f"| {_escape(att.filename)} | {att.content_type} | {att.size_bytes} B "
                f"| `{att.sha256 or '-'}` | {', '.join(notes) or '-'} |"
            )
        lines.append("")

    # --- Actions -----------------------------------------------------------
    lines.append("## 10. Recommended actions")
    lines.append("")
    for i, action in enumerate(v.recommended_actions, 1):
        lines.append(f"{i}. {action}")
    lines.append("")

    # --- Notification ------------------------------------------------------
    lines.append("## 11. User notification (ready to send)")
    lines.append("")
    lines.append(f"**To:** {case.notification.to or '_recipient_'}  ")
    lines.append(f"**Subject:** {case.notification.subject}")
    lines.append("")
    lines.append("```text")
    lines.append(case.notification.body.rstrip())
    lines.append("```")
    lines.append("")

    lines.append("---")
    lines.append(
        f"_Generated automatically by PhishPipe. Detection logic `{detections_version}`. "
        "Indicators are defanged; verify against live reputation sources before blocking._"
    )
    return "\n".join(lines)
