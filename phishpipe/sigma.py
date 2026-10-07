"""Sigma Rule Generator for PhishPipe Cases.

Generates industry-standard Sigma rules (in YAML) from investigated cases,
enabling direct ingestion into SIEMs (Splunk, Elastic, Microsoft Sentinel, QRadar).
"""

from __future__ import annotations

import uuid
from typing import Any
import yaml

from phishpipe.models import Case


def generate_sigma_rule(case: Case) -> str:
    """Generate a multi-logsource Sigma detection rule for the case's IOCs."""
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"phishpipe-sigma-{case.id}"))
    date_str = case.created_at.strftime("%Y/%m/%d")

    # Collect indicators by type
    urls = [i.value for i in case.indicators if i.type == "url"][:10]
    domains = [i.value for i in case.indicators if i.type == "domain"][:10]
    ips = [i.value for i in case.indicators if i.type == "ip"][:10]
    hashes = [i.value for i in case.indicators if i.type == "hash"][:10]

    # Map MITRE ATT&CK tags
    tags = ["attack.initial_access", "attack.t1566"]
    for m in case.verdict.mitre:
        tag_id = m.id.lower().replace(".", "_")
        tags.append(f"attack.{tag_id}")

    # Build detection criteria
    detection: dict[str, Any] = {}
    conditions = []

    if domains:
        detection["selection_domains"] = {"dns.question.name|endswith": domains}
        conditions.append("selection_domains")
    if urls:
        detection["selection_urls"] = {"url.full|contains": urls}
        conditions.append("selection_urls")
    if ips:
        detection["selection_ips"] = {"destination.ip": ips}
        conditions.append("selection_ips")
    if hashes:
        detection["selection_hashes"] = {"file.hash.sha256": hashes}
        conditions.append("selection_hashes")

    if not conditions:
        detection["selection_sender"] = {"email.from": case.email.from_address or "unknown"}
        conditions.append("selection_sender")

    detection["condition"] = " or ".join(conditions)

    level = (
        "critical"
        if case.verdict.severity == "critical"
        else "high"
        if case.verdict.severity == "high"
        else "medium"
    )

    sigma_dict = {
        "title": f"Phishing Threat Activity - {case.title[:70]}",
        "id": rule_id,
        "status": "experimental",
        "description": f"Detects network proxy, DNS, or host activity associated with PhishPipe investigation {case.id}. Assessment: {case.verdict.explanation}",
        "references": [
            f"https://attack.mitre.org/techniques/{m.id.replace('.', '/')}/"
            for m in case.verdict.mitre[:3]
        ] or ["https://attack.mitre.org/techniques/T1566/"],
        "author": "PhishPipe Autonomous SOC Engine",
        "date": date_str,
        "modified": date_str,
        "tags": list(dict.fromkeys(tags)),
        "logsource": {
            "category": "network",
            "definition": "Network proxy, DNS queries, and firewall transit logs",
        },
        "detection": detection,
        "falsepositives": [
            "Legitimate internal user navigation if domain was misclassified",
            "Security testing / authorized red team simulations",
        ],
        "level": level,
    }

    return yaml.dump(sigma_dict, sort_keys=False, default_flow_style=False)
