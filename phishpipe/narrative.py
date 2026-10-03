"""Natural-language layer: investigation summary + user notification.

Two modes, selected automatically:

* **LLM mode** - when an ``OPENAI_API_KEY`` / ``LLM_API_KEY`` is present, the
  structured case is sent to an OpenAI-compatible endpoint and the model writes
  the narrative and the user notification.
* **Deterministic mode** - the default. A template writer assembles both texts
  from the scored signals, so a report is always produced, offline, in
  milliseconds, and with no external dependency.

Both modes are fed the *same* structured facts, so the LLM can never invent
indicators that were not extracted - it only rephrases what the pipeline found.
"""

from __future__ import annotations

from phishpipe.config import Settings, load_settings, llm_config
from phishpipe.models import Case, NotificationMessage

SYSTEM_PROMPT = (
    "You are a senior SOC analyst writing an incident summary for an internal "
    "case record. Use only the structured facts supplied by the user. Do not "
    "invent indicators, scores, or conclusions. Be concise, factual and "
    "jargon-light. Output plain text with short paragraphs, no markdown headers."
)

USER_PROMPT_TEMPLATE = """Write two sections, separated by a line containing only ---.

SECTION 1: INVESTIGATION SUMMARY (for analysts)
Cover: what the message claimed, why it is or is not malicious, the key
technical evidence, and the risk if the recipient had interacted.

SECTION 2: USER NOTIFICATION (for the recipient, non-technical)
Address the recipient directly, explain in simple words what happened, state
clearly whether they need to do anything, and give 3 short do/don't bullets.

FACTS:
{facts}
"""


def _case_facts(case: Case) -> str:
    """Flatten a case into the fact block shared by both modes."""
    lines: list[str] = [
        f"Verdict: {case.verdict.classification}",
        f"Confidence: {case.verdict.confidence}/100",
        f"Severity: {case.verdict.severity}",
        f"Assessment: {case.verdict.explanation}",
        f"Subject: {case.email.subject!r}",
        f"From: {case.email.from_display_name or case.email.from_address} <{case.email.from_address}>",
        f"To: {', '.join(case.email.to) or 'n/a'}",
        f"SPF={case.email.auth.spf} DKIM={case.email.auth.dkim} DMARC={case.email.auth.dmarc}",
        "",
        "Matched signals:",
    ]
    matched = [s for s in case.signals if s.matched]
    if matched:
        lines += [f"- {s.title} (weight {s.weight:+d}) evidence: {s.evidence}" for s in matched]
    else:
        lines.append("- none")

    lines.append("")
    lines.append("Indicators:")
    if case.indicators:
        lines += [f"- [{i.type}] {i.defanged}" for i in case.indicators[:25]]
    else:
        lines.append("- none")

    lines.append("")
    lines.append("MITRE ATT&CK: " + (", ".join(f"{t.id} {t.name}" for t in case.verdict.mitre) or "none"))
    lines.append("")
    lines.append("Recommended actions:")
    lines += [f"- {a}" for a in case.verdict.recommended_actions]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# LLM mode
# ---------------------------------------------------------------------------
def _call_llm(case: Case, cfg: dict) -> tuple[str, str] | None:
    """Call an OpenAI-compatible chat endpoint. Returns None on any failure."""
    import requests

    facts = _case_facts(case)
    url = cfg["base_url"].rstrip("/") + "/chat/completions"
    payload = {
        "model": cfg["model"],
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": USER_PROMPT_TEMPLATE.format(facts=facts)},
        ],
    }
    try:
        resp = requests.post(
            url,
            json=payload,
            headers={"Authorization": f"Bearer {cfg['api_key']}"},
            timeout=20,
        )
        if resp.status_code != 200:
            return None
        content = resp.json()["choices"][0]["message"]["content"]
    except Exception:  # noqa: BLE001 - narrative must never break the pipeline
        return None

    if "---" in content:
        summary, _, notification = content.partition("---")
        return summary.strip(), notification.strip()
    return content.strip(), ""


# ---------------------------------------------------------------------------
# Deterministic mode
# ---------------------------------------------------------------------------
def _template_summary(case: Case) -> str:
    v = case.verdict
    e = case.email
    matched = [s for s in case.signals if s.matched and s.weight > 0]

    subject_line = (
        f"A message with the subject {e.subject!r} was reported and analysed "
        f"automatically by PhishPipe."
        if e.subject
        else "A message was reported and analysed automatically by PhishPipe."
    )

    verdict_line = {
        "true_positive": f"It was classified as a **true positive phishing attempt** with {v.confidence}% confidence.",
        "suspicious": f"It was classified as **suspicious** with {v.confidence}% confidence - below the bar for an "
        "automatic verdict, so it requires analyst confirmation.",
        "false_positive": f"It was classified as a **likely false positive** with {v.confidence}% confidence.",
    }[v.classification]

    auth = e.auth
    auth_bits = f"SPF {auth.spf or 'not evaluated'}, DKIM {auth.dkim or 'not evaluated'}, DMARC {auth.dmarc or 'not evaluated'}"

    parts = [subject_line, "", verdict_line, ""]

    parts.append("**What the message claimed**")
    sender_repr = e.from_display_name or e.from_address
    parts.append(
        f"The message presented itself as coming from {sender_repr} "
        f"<{e.from_address}>, with the subject {e.subject!r}."
    )
    if case.email.attachments:
        names = ", ".join(a.filename for a in case.email.attachments[:5])
        parts.append(f"It carried {len(e.attachments)} attachment(s): {names}.")
    parts.append("")

    parts.append("**Why**")
    if matched:
        for s in matched[:8]:
            evidence = f" - {s.evidence}" if s.evidence else ""
            parts.append(f"- {s.title} (weight {s.weight:+d}){evidence}")
    else:
        parts.append("- No tracked phishing signal matched.")
    parts.append("")

    parts.append("**Authentication**")
    parts.append(f"{auth_bits}.")
    if e.received_hops:
        parts.append(
            f"The message traversed {len(e.received_hops)} hop(s); "
            f"first observed origin {e.received_hops[0].from_host or 'unknown'}."
        )
    parts.append("")

    if case.indicators:
        parts.append("**Indicators**")
        for ind in case.indicators[:15]:
            parts.append(f"- [{ind.type}] {ind.defanged}")
        if len(case.indicators) > 15:
            parts.append(f"- ...and {len(case.indicators) - 15} more (see IOC table)")
        parts.append("")

    if v.mitre:
        parts.append("**MITRE ATT&CK**")
        parts.append(", ".join(f"{t.id} {t.name} ({t.tactic})" for t in v.mitre))
        parts.append("")

    if v.needs_human_review:
        parts.append(
            "> This case was escalated for human review: "
            + next((s.evidence for s in case.signals if s.id == "guard.needs_human_review" and s.matched), "inconclusive score")
            + "."
        )
    return "\n".join(parts)


def _template_notification(case: Case) -> str:
    recipient = (case.email.to or ["there"])[0].split("@")[0]
    v = case.verdict
    first_name = recipient.replace(".", " ").replace("_", " ").split(" ")[0].title()

    if v.classification == "false_positive":
        return (
            f"Hi {first_name},\n\n"
            "Thanks for reporting the email you recently received. We investigated it and "
            "it appears to be legitimate - no action is needed on your part.\n\n"
            "We appreciate you checking. When in doubt, reporting is always the right call.\n\n"
            "- Security Operations\n"
        )

    urgency = "Please do this as soon as possible." if v.severity in {"high", "critical"} else "There is no immediate panic."

    return (
        f"Hi {first_name},\n\n"
        f"You recently reported an email with the subject \"{case.email.subject or 'no subject'}\". "
        "We have completed an automated investigation and confirmed it was a phishing attempt.\n\n"
        "What this means for you:\n"
        "- Do not click any links in that email or open its attachments.\n"
        "- If you already entered a password, tell us immediately so we can reset it.\n"
        "- If you opened an attachment, let us know which device you used.\n\n"
        "What happens next:\n"
        "- We are blocking the sender and the links it contained.\n"
        "- We are searching for copies of the message in other mailboxes.\n"
        "- Your account will be monitored for unusual sign-in activity.\n\n"
        f"{urgency}\n\n"
        "You did the right thing by reporting it. If you are ever unsure about a message, "
        "forward it to the Security Operations team before acting on it.\n\n"
        "- Security Operations\n"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def generate_narrative(case: Case, settings: Settings | None = None) -> tuple[str, str]:
    """Return ``(investigation_summary, user_notification)`` for a case."""
    settings = settings or load_settings()
    cfg = settings.llm or llm_config()

    if cfg.get("api_key"):
        result = _call_llm(case, cfg)
        if result:
            summary, notification = result
            if notification:
                return summary, notification
            return summary, _template_notification(case)

    return _template_summary(case), _template_notification(case)


def build_notification(case: Case, narrative: str) -> NotificationMessage:
    recipient = (case.email.to or [""])[0]
    subject = case.email.subject or "no subject"
    prefix = {
        "true_positive": "[Security Alert] Phishing attempt blocked - ",
        "suspicious": "[Security Review] Suspicious email reported - ",
        "false_positive": "[Security] Your report was checked - ",
    }[case.verdict.classification]

    body = narrative
    if not body.strip():
        body = _template_notification(case)

    return NotificationMessage(
        to=recipient,
        subject=prefix + subject[:100],
        body=body,
        channel="email",
    )


def llm_status() -> dict:
    """Report whether the LLM layer is active (used by /api/providers)."""
    cfg = llm_config()
    return {
        "enabled": bool(cfg.get("api_key")),
        "mode": "llm" if cfg.get("api_key") else "deterministic-template",
        "model": cfg.get("model"),
        "note": None if cfg.get("api_key") else "Set OPENAI_API_KEY to enable LLM-authored narratives.",
    }
