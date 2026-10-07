"""Webhook Notification Dispatcher for Slack, Microsoft Teams, and SIEMs.

Sends formatted incident alert cards when high-severity threats are confirmed.
"""

from __future__ import annotations

import os
from typing import Any
import requests

from phishpipe.models import Case

WEBHOOK_TIMEOUT = 5


def dispatch_webhook(case: Case, webhook_url: str | None = None) -> dict[str, Any]:
    """Send formatted alert to Slack, MS Teams, or a generic JSON receiver."""
    url = webhook_url or os.environ.get("PHISHPIPE_WEBHOOK_URL") or os.environ.get("SLACK_WEBHOOK_URL")
    if not url:
        return {"status": "skipped", "reason": "No webhook URL configured (set PHISHPIPE_WEBHOOK_URL)"}

    # Determine format (Slack vs Generic)
    is_slack = "hooks.slack.com" in url

    if is_slack:
        payload = _build_slack_payload(case)
    else:
        payload = _build_generic_payload(case)

    try:
        resp = requests.post(url, json=payload, timeout=WEBHOOK_TIMEOUT)
        return {
            "status": "dispatched" if resp.status_code in {200, 204} else "error",
            "http_code": resp.status_code,
            "response": resp.text[:200],
        }
    except Exception as exc:
        return {"status": "failed", "error": str(exc)}


def _build_slack_payload(case: Case) -> dict[str, Any]:
    v = case.verdict
    icon = "🚨" if v.classification == "true_positive" else "⚠️" if v.classification == "suspicious" else "🛡️"
    color = "#f43f5e" if v.classification == "true_positive" else "#eab308" if v.classification == "suspicious" else "#10b981"

    return {
        "text": f"{icon} PhishPipe Alert: {case.title} [{case.id}]",
        "attachments": [
            {
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"{icon} PhishPipe Threat Alert: {case.id}", "emoji": True},
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Verdict:*\n{v.classification.upper()}"},
                            {"type": "mrkdwn", "text": f"*Confidence:*\n{v.confidence}/100 ({v.severity.upper()})"},
                            {"type": "mrkdwn", "text": f"*Sender:*\n`{case.email.from_address}`"},
                            {"type": "mrkdwn", "text": f"*Signals Matched:*\n{v.signals_matched}/{v.signals_total}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": f"*Assessment:*\n{v.explanation}"},
                    },
                ],
            }
        ],
    }


def _build_generic_payload(case: Case) -> dict[str, Any]:
    return {
        "event": "phishing_investigation_completed",
        "case_id": case.id,
        "created_at": case.created_at.isoformat(),
        "title": case.title,
        "classification": case.verdict.classification,
        "confidence": case.verdict.confidence,
        "severity": case.verdict.severity,
        "sender": case.email.from_address,
        "subject": case.email.subject,
        "explanation": case.verdict.explanation,
        "indicators": [i.value for i in case.indicators[:15]],
        "mitre_techniques": [m.id for m in case.verdict.mitre],
    }
