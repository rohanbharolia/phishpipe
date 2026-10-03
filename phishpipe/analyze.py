"""Stage 4 - Automated reasoning: signal evaluation, scoring, ATT&CK mapping.

The scorer is deliberately *deterministic and additive* rather than a black-box
model: every point in the final confidence score can be traced to a named signal
in ``detections/signals.yaml`` with the evidence that triggered it. That is what
lets the pipeline print a "confidence explanation" the analyst can audit.
"""

from __future__ import annotations

from phishpipe.detections import Detections, SignalDefinition, load_detections
from phishpipe.extract import ContentProfile
from phishpipe.models import (
    EnrichmentBundle,
    Indicator,
    MitreTechnique,
    ParsedEmail,
    Signal,
    Verdict,
)

# X-Mailer values commonly emitted by bulk mailers and phishing kits.
SUSPICIOUS_MAILERS = (
    "phpmailer",
    "the bat!",
    "groupmail",
    "advanced emailer",
    "sendblaster",
    "email detective",
    "mail bomb",
    "gammadyne mailer",
    "sparkpost",
)

_FAIL_VALUES = {"fail", "softfail", "permerror", "temperror"}
_CRITICAL_SEVERITY = "critical"


def _signal(defn: SignalDefinition, matched: bool, evidence: str = "") -> Signal:
    return Signal(
        id=defn.id,
        title=defn.title,
        description=defn.description,
        weight=defn.weight,
        matched=matched,
        severity=defn.severity,  # type: ignore[arg-type]
        evidence=evidence,
        category=defn.category,
        mitre=list(defn.techniques),
    )


# ---------------------------------------------------------------------------
# Signal evaluation
# ---------------------------------------------------------------------------
def evaluate_signals(
    email: ParsedEmail,
    profile: ContentProfile,
    indicators: list[Indicator],
    enrichment: EnrichmentBundle,
    detections: Detections | None = None,
) -> list[Signal]:
    """Evaluate every detection rule against the evidence and return all of them.

    Non-matching signals are returned too (with ``matched=False``) so the report
    can show what was checked, not just what fired.
    """
    detections = detections or load_detections()
    s = detections.signals
    out: list[Signal] = []

    def emit(sig_id: str, matched: bool, evidence: str = "") -> None:
        defn = s.get(sig_id)
        if defn:
            out.append(_signal(defn, matched, evidence if matched else ""))

    # --- authentication ----------------------------------------------------
    auth = email.auth
    emit("auth.spf_fail", auth.spf in _FAIL_VALUES, f"SPF result: {auth.spf}")
    emit("auth.dkim_fail", auth.dkim in _FAIL_VALUES, f"DKIM result: {auth.dkim}")
    emit("auth.dmarc_fail", auth.dmarc in _FAIL_VALUES, f"DMARC result: {auth.dmarc}")
    emit("auth.dmarc_none", auth.dmarc == "none", "DMARC policy evaluated as 'none' (not enforced)")
    emit(
        "auth.missing_results",
        not any([auth.spf, auth.dkim, auth.dmarc]),
        "No SPF, DKIM or DMARC result found in Authentication-Results",
    )
    emit(
        "auth.alignment_fail",
        (auth.spf == "pass" or auth.dkim == "pass") and auth.dmarc != "pass",
        f"SPF={auth.spf}, DKIM={auth.dkim}, DMARC={auth.dmarc} - identifiers not aligned",
    )
    emit(
        "auth.all_pass_aligned",
        auth.aligned_pass,
        f"SPF={auth.spf}, DKIM={auth.dkim}, DMARC={auth.dmarc} - all checks passed and aligned",
    )

    # --- envelope / headers ------------------------------------------------
    emit(
        "header.return_path_mismatch",
        bool(profile.return_path_domain and profile.sender_domain and profile.return_path_domain != profile.sender_domain),
        f"Return-Path {profile.return_path_domain} vs From {profile.sender_domain}",
    )
    emit(
        "header.reply_to_mismatch",
        bool(profile.reply_to_domain and profile.sender_domain and profile.reply_to_domain != profile.sender_domain),
        f"Reply-To {profile.reply_to_domain} vs From {profile.sender_domain}",
    )
    emit(
        "header.foreign_origin",
        _foreign_origin(email, profile),
        f"Sender domain {profile.sender_domain} does not appear in the Received chain",
    )
    mailer = (email.headers.get("X-Mailer") or "").lower()
    suspicious_mailers = detections.wordlist("suspicious_mailers") or SUSPICIOUS_MAILERS
    emit(
        "header.suspicious_mailer",
        any(m in mailer for m in suspicious_mailers),
        f"X-Mailer: {email.headers.get('X-Mailer', '')}",
    )

    # --- identity ----------------------------------------------------------
    emit(
        "identity.display_name_spoof",
        profile.display_name_spoofed,
        f"Display name {profile.display_name!r} claims {profile.display_name_brand!r} "
        f"but sender domain is {profile.sender_domain}",
    )
    emit(
        "identity.brand_impersonation",
        profile.brand_impersonation,
        f"Body references {', '.join(profile.brands_mentioned)} while sender domain is {profile.sender_domain}",
    )
    emit("identity.allowlisted_sender", profile.sender_allowlisted, f"{profile.sender_domain} is on the allow-list")
    emit(
        "identity.unknown_sender",
        profile.unknown_sender and bool(profile.sender_domain),
        f"First-seen external domain: {profile.sender_domain}",
    )

    # --- content -----------------------------------------------------------
    emit("content.urgency", bool(profile.urgency_hits), "Urgency terms: " + ", ".join(profile.urgency_hits[:6]))
    emit("content.threat", bool(profile.threat_hits), "Threat terms: " + ", ".join(profile.threat_hits[:6]))
    emit(
        "content.sensitive_request",
        bool(profile.sensitive_request_hits),
        "Credential/data request terms: " + ", ".join(profile.sensitive_request_hits[:6]),
    )
    emit(
        "content.credential_harvest_url",
        bool(profile.credential_urls_found),
        "Bait tokens in URL path: " + "; ".join(profile.credential_urls_found[:3]),
    )
    emit(
        "content.mismatched_link",
        bool(profile.mismatched_links_found),
        "Anchor/destination mismatch: " + "; ".join(profile.mismatched_links_found[:3]),
    )
    emit("content.ip_based_link", bool(profile.ip_links_found), "Raw-IP links: " + ", ".join(profile.ip_links_found[:3]))
    emit("content.url_shortener", bool(profile.shorteners_found), "Redirectors: " + ", ".join(profile.shorteners_found[:3]))
    emit(
        "content.suspicious_tld",
        bool(profile.suspicious_tlds_found),
        "Suspicious TLD links: " + ", ".join(profile.suspicious_tlds_found[:3]),
    )
    emit("content.punycode", bool(profile.punycode_found), "Punycode links: " + ", ".join(profile.punycode_found[:3]))
    emit("content.generic_greeting", bool(profile.generic_greeting_hit), f"Greeting: {profile.generic_greeting_hit!r}")
    emit(
        "content.macro_instruction",
        bool(profile.macro_instruction_hits),
        "Macro instructions: " + ", ".join(profile.macro_instruction_hits[:4]),
    )
    emit(
        "content.no_suspicious_elements",
        profile.suspicious_element_count == 0,
        "No tracked phishing pattern present in headers, body or links",
    )

    # --- attachments -------------------------------------------------------
    dangerous = [a.filename for a in profile.attachments if a.dangerous_ext]
    emit("attach.suspicious_extension", bool(dangerous), "Dangerous attachments: " + ", ".join(dangerous[:5]))
    doubled = [a.filename for a in profile.attachments if a.double_extension]
    emit("attach.double_extension", bool(doubled), "Double-extension attachments: " + ", ".join(doubled[:5]))
    macros = [a.filename for a in profile.attachments if a.macro_ext]
    emit("attach.macro_enabled", bool(macros), "Macro-capable attachments: " + ", ".join(macros[:5]))
    emit(
        "attach.password_protected_hint",
        profile.password_protected_hint,
        "Message text supplies a password to open the attachment",
    )
    mismatched = [a.filename for a in profile.attachments if a.content_type_mismatch]
    emit(
        "attach.content_type_mismatch",
        bool(mismatched),
        "MIME/extension contradiction: " + ", ".join(mismatched[:5]),
    )
    emit(
        "attach.unexpected",
        bool(profile.attachments) and profile.unknown_sender,
        f"{len(profile.attachments)} attachment(s) from external unknown sender {profile.sender_domain}",
    )

    # --- enrichment --------------------------------------------------------
    verdicts = [r.verdict for r in enrichment.results]
    malicious = [r.indicator for r in enrichment.results if r.verdict == "malicious"]
    suspicious = [r.indicator for r in enrichment.results if r.verdict == "suspicious"]
    emit("enrich.malicious", bool(malicious), "Flagged malicious: " + ", ".join(malicious[:5]))
    emit("enrich.suspicious", bool(suspicious) and not malicious, "Flagged suspicious: " + ", ".join(suspicious[:5]))
    emit(
        "enrich.all_clean",
        bool(verdicts) and all(v == "clean" for v in verdicts),
        f"All {len(verdicts)} enriched indicators returned clean",
    )

    # --- guardrail ---------------------------------------------------------
    # Emitted last so it is visible in the report as an explicit escalation flag.
    emit("guard.needs_human_review", False, "")

    return out


def _foreign_origin(email: ParsedEmail, profile: ContentProfile) -> bool:
    """True when no Received hop originates from the claimed sender domain."""
    if not profile.sender_domain or not email.received_hops:
        return False
    hop_domains = [
        (hop.from_host or "").lower().split("@")[-1].split(":")[0]
        for hop in email.received_hops
        if hop.from_host
    ]
    if not hop_domains:
        return False
    sender = profile.sender_domain
    return not any(sender in hd or hd in sender or hd.endswith(sender) for hd in hop_domains)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------
def _clamp(value: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, value))


def score_signals(signals: list[Signal], detections: Detections | None = None) -> int:
    """Sum matched signal weights and clamp to 0-100."""
    detections = detections or load_detections()
    matched = [s for s in signals if s.matched]
    raw = sum(s.weight for s in matched)
    return _clamp(raw)


# Categories whose critical signals are direct, structural evidence in the
# message itself. A critical hit in one of these escalates severity even when
# mitigating factors drag the total score down (e.g. an .exe attachment inside
# an otherwise clean-looking message). Reputation-driven signals follow the
# confidence bands instead, so a single intel hit cannot overrule the analysis.
SELF_EVIDENCE_CATEGORIES = {"content", "attachment"}


def severity_for(confidence: int, signals: list[Signal], detections: Detections | None = None) -> str:
    detections = detections or load_detections()
    th = detections.thresholds
    if th.critical_signal_auto_escalate and any(
        s.matched and s.severity == _CRITICAL_SEVERITY and s.category in SELF_EVIDENCE_CATEGORIES
        for s in signals
    ):
        return "critical"
    if confidence >= th.critical:
        return "critical"
    if confidence >= th.high:
        return "high"
    if confidence >= th.medium:
        return "medium"
    if confidence >= th.low:
        return "low"
    return "info"


def classify(confidence: int, detections: Detections | None = None) -> str:
    detections = detections or load_detections()
    th = detections.thresholds
    if confidence >= th.true_positive:
        return "true_positive"
    if confidence >= th.suspicious:
        return "suspicious"
    return "false_positive"


def map_mitre(signals: list[Signal], detections: Detections | None = None) -> list[MitreTechnique]:
    """Union of ATT&CK techniques from every matched signal, de-duplicated."""
    detections = detections or load_detections()
    ids: list[str] = []
    for sig in signals:
        if not sig.matched:
            continue
        for tid in sig.mitre:
            if tid not in ids:
                ids.append(tid)

    # Keep catalogue order for stable, readable output.
    catalogue_order = list(detections.mitre.keys())
    ids.sort(key=lambda t: catalogue_order.index(t) if t in catalogue_order else len(catalogue_order))

    return [
        MitreTechnique(
            id=tid,
            name=detections.technique(tid)["name"],
            tactic=detections.technique(tid)["tactic"],
            url=format_attack_url(tid),
        )
        for tid in ids
    ]


def format_attack_url(technique_id: str) -> str:
    """Build an ATT&CK navigator permalink for a technique/sub-technique."""
    base = "https://attack.mitre.org/techniques"
    if "." in technique_id:
        parent, child = technique_id.split(".", 1)
        return f"{base}/{parent}/{child}/"
    return f"{base}/{technique_id}/"


# ---------------------------------------------------------------------------
# Recommended actions
# ---------------------------------------------------------------------------
def recommended_actions(
    classification: str,
    profile: ContentProfile,
    enrichment: EnrichmentBundle,
    signals: list[Signal],
) -> list[str]:
    matched_ids = {s.id for s in signals if s.matched}
    actions: list[str] = []

    if classification == "false_positive":
        actions.append("Record as a false positive and close the case with the evidence attached.")
        if profile.sender_allowlisted:
            actions.append("Sender is already allow-listed - confirm no mailbox rule was created by the message.")
        else:
            actions.append(
                "If this sender is expected business mail, add the domain to the gateway allow-list after verification."
            )
        actions.append("No user notification required unless the recipient reported it.")
        return actions

    actions.append("Quarantine the message from the recipient's mailbox and search for copies across the tenant.")

    if matched_ids & {"content.credential_harvest_url", "content.mismatched_link", "content.ip_based_link"}:
        actions.append("Block the listed URLs and domains at the secure web gateway / DNS proxy.")
    if matched_ids & {"attach.suspicious_extension", "attach.double_extension", "attach.macro_enabled"}:
        actions.append("Detonate the attachment in a sandbox and add its hashes to the EDR blocklist.")
    if matched_ids & {"content.sensitive_request", "content.credential_harvest_url"}:
        actions.append(
            "If the recipient submitted credentials, force a password reset, revoke active sessions and review sign-in logs."
        )
    if matched_ids & {"identity.display_name_spoof", "identity.brand_impersonation"}:
        actions.append("Add a strict DMARC policy (p=reject) for the impersonated domain and monitor lookalike registrations.")
    if matched_ids & {"header.return_path_mismatch", "header.reply_to_mismatch"}:
        actions.append("Tune the gateway to reject envelope/From domain mismatches for the impersonated brand.")
    if enrichment.results and all(r.offline for r in enrichment.results):
        actions.append(
            "Reputation checks used the offline dataset only - re-run with VT_API_KEY / URLSCAN_API_KEY for live confirmation."
        )

    actions.append("Publish the IOCs to MISP or the shared blocklist so downstream controls pick them up.")
    actions.append("Notify the recipient with the templated user warning generated with this case.")
    actions.append("Escalate to a Tier-2 analyst for confirmation if the score falls in the inconclusive band.")
    return actions


# ---------------------------------------------------------------------------
# Verdict assembly
# ---------------------------------------------------------------------------
def build_verdict(
    signals: list[Signal],
    profile: ContentProfile,
    enrichment: EnrichmentBundle,
    detections: Detections | None = None,
) -> Verdict:
    detections = detections or load_detections()
    matched = [s for s in signals if s.matched]

    confidence = score_signals(signals, detections)
    classification = classify(confidence, detections)
    severity = severity_for(confidence, signals, detections)

    critical_fired = [s for s in matched if s.severity == _CRITICAL_SEVERITY]
    inconclusive = detections.thresholds.suspicious <= confidence < detections.thresholds.true_positive
    needs_review = bool(critical_fired) or inconclusive

    if needs_review:
        for sig in signals:
            if sig.id == "guard.needs_human_review":
                sig.matched = True
                sig.evidence = _review_reason(critical_fired, confidence, detections)
                matched.append(sig)
                break

    reasoning = [
        f"{len(matched)}/{len(signals)} detection signals matched for a raw score of "
        f"{sum(s.weight for s in matched)} clamped to {confidence}/100.",
    ]
    top = sorted(matched, key=lambda s: -abs(s.weight))[:5]
    if top:
        reasoning.append(
            "Highest-impact signals: "
            + "; ".join(f"{s.title} ({s.weight:+d})" for s in top)
            + "."
        )
    if classification == "true_positive":
        reasoning.append(
            f"Confidence met the true-positive threshold of {detections.thresholds.true_positive}."
        )
    elif classification == "suspicious":
        reasoning.append(
            f"Score sits between {detections.thresholds.suspicious} and "
            f"{detections.thresholds.true_positive} - insufficient evidence for an automatic verdict."
        )
    else:
        reasoning.append(
            f"Score below the suspicious threshold of {detections.thresholds.suspicious}."
        )
    if any(s.matched and s.weight < 0 for s in signals):
        reasoning.append(
            "Mitigating factors reduced the score: "
            + "; ".join(s.title for s in matched if s.weight < 0)
            + "."
        )

    return Verdict(
        classification=classification,  # type: ignore[arg-type]
        confidence=confidence,
        severity=severity,  # type: ignore[arg-type]
        raw_score=sum(s.weight for s in matched),
        signals_matched=len(matched),
        signals_total=len(signals),
        explanation=_explanation(classification, confidence, matched, profile),
        reasoning=reasoning,
        mitre=map_mitre(signals, detections),
        recommended_actions=recommended_actions(classification, profile, enrichment, signals),
        needs_human_review=needs_review,
    )


def _review_reason(critical_fired: list[Signal], confidence: int, detections: Detections) -> str:
    if critical_fired:
        return "Critical signal fired: " + ", ".join(s.title for s in critical_fired)
    return (
        f"Confidence {confidence} is in the inconclusive band "
        f"({detections.thresholds.suspicious}-{detections.thresholds.true_positive})"
    )


def _explanation(classification: str, confidence: int, matched: list[Signal], profile: ContentProfile) -> str:
    if not matched:
        return "No detection signal matched; nothing in this message resembles a tracked phishing pattern."

    factors = ", ".join(s.title for s in sorted(matched, key=lambda s: -abs(s.weight))[:4])
    if classification == "true_positive":
        return (
            f"Assessed as a true positive with {confidence}% confidence. "
            f"The decisive evidence was: {factors}. "
            f"Authentication and/or content analysis show the message impersonates "
            f"{profile.display_name_brand or 'an unrelated brand'} from {profile.sender_domain or 'an unknown sender'}."
        )
    if classification == "suspicious":
        return (
            f"Assessed as suspicious with {confidence}% confidence. "
            f"Supporting evidence: {factors}. "
            "The evidence is real but not conclusive, so a human analyst must confirm before remediation."
        )
    return (
        f"Assessed as a likely false positive with {confidence}% confidence. "
        f"Only minor observations were made ({factors or 'none'}) and they are outweighed by "
        "passing authentication checks and the absence of phishing content."
    )
