"""STIX 2.1 Export for PhishPipe Cases.

Generates an OASIS-compliant STIX 2.1 JSON bundle representing the phishing
incident, threat indicators (URLs, domains, IPs, hashes), MITRE ATT&CK
techniques, and indicator relationships.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from phishpipe.models import Case, Indicator

STIX_NAMESPACE = uuid.UUID("f39b6b8b-7f3e-4b68-8092-2c6b4122d256")


def _deterministic_uuid(type_prefix: str, seed: str) -> str:
    """Generate a deterministic STIX UUIDv5 so repeated exports of the same case have stable IDs."""
    u = uuid.uuid5(STIX_NAMESPACE, seed)
    return f"{type_prefix}--{u}"


def _stix_pattern(indicator: Indicator) -> str | None:
    val = indicator.value.replace("'", "\\'")
    if indicator.type == "url":
        return f"[url:value = '{val}']"
    if indicator.type == "domain":
        return f"[domain-name:value = '{val}']"
    if indicator.type == "ip":
        return f"[ipv4-addr:value = '{val}']"
    if indicator.type == "email":
        return f"[email-addr:value = '{val}']"
    if indicator.type == "hash":
        if len(indicator.value) == 64:
            return f"[file:hashes.'SHA-256' = '{val}']"
        if len(indicator.value) == 32:
            return f"[file:hashes.'MD5' = '{val}']"
    return None


def export_stix_bundle(case: Case) -> dict[str, Any]:
    """Convert an investigated Case into a standard STIX 2.1 bundle."""
    created_str = case.created_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    objects: list[dict[str, Any]] = []
    object_refs: list[str] = []

    # 1. Identity (PhishPipe System)
    identity_id = _deterministic_uuid("identity", "phishpipe-soc-engine")
    identity_obj = {
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": "2026-01-01T00:00:00Z",
        "modified": "2026-01-01T00:00:00Z",
        "name": "PhishPipe Autonomous SOC Engine",
        "description": "Deterministic email forensic and threat investigation platform",
        "identity_class": "system",
    }
    objects.append(identity_obj)
    object_refs.append(identity_id)

    # 2. Attack Patterns (MITRE ATT&CK)
    attack_pattern_ids: list[str] = []
    for tech in case.verdict.mitre:
        ap_id = _deterministic_uuid("attack-pattern", f"mitre-{tech.id}")
        ap_obj = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_id,
            "created": created_str,
            "modified": created_str,
            "name": tech.name,
            "description": f"MITRE ATT&CK Tactic: {tech.tactic}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech.id,
                    "url": tech.url or f"https://attack.mitre.org/techniques/{tech.id.replace('.', '/')}/",
                }
            ],
            "created_by_ref": identity_id,
        }
        objects.append(ap_obj)
        object_refs.append(ap_id)
        attack_pattern_ids.append(ap_id)

    # 3. Indicators
    indicator_stix_ids: list[str] = []
    indicator_type_label = (
        "malicious-activity"
        if case.verdict.classification == "true_positive"
        else "anomalous-activity"
        if case.verdict.classification == "suspicious"
        else "benign"
    )

    for idx, ind in enumerate(case.indicators):
        pattern = _stix_pattern(ind)
        if not pattern:
            continue
        ind_id = _deterministic_uuid("indicator", f"{case.id}-{ind.type}-{ind.value}")
        ind_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": ind_id,
            "created": created_str,
            "modified": created_str,
            "name": f"Phishing observable: {ind.type} {ind.defanged}",
            "description": ind.context or f"Extracted from {ind.source}",
            "indicator_types": [indicator_type_label],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": created_str,
            "created_by_ref": identity_id,
            "confidence": case.verdict.confidence,
            "labels": [ind.type, case.verdict.severity],
        }
        objects.append(ind_obj)
        object_refs.append(ind_id)
        indicator_stix_ids.append(ind_id)

    # 4. Relationships: Indicator -> Attack Pattern (indicates)
    if attack_pattern_ids:
        primary_ap = attack_pattern_ids[0]
        for ind_id in indicator_stix_ids:
            rel_id = _deterministic_uuid("relationship", f"{ind_id}-indicates-{primary_ap}")
            rel_obj = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": rel_id,
                "created": created_str,
                "modified": created_str,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": primary_ap,
                "created_by_ref": identity_id,
            }
            objects.append(rel_obj)
            object_refs.append(rel_id)

    # 5. Incident Report
    report_id = _deterministic_uuid("report", f"report-{case.id}")
    report_obj = {
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": created_str,
        "modified": created_str,
        "name": case.title or f"Incident Report {case.id}",
        "description": case.verdict.explanation,
        "published": created_str,
        "report_types": ["threat-report", "phishing"],
        "object_refs": object_refs,
        "created_by_ref": identity_id,
        "labels": [
            f"classification:{case.verdict.classification}",
            f"severity:{case.verdict.severity}",
            f"score:{case.verdict.confidence}",
        ],
    }
    objects.append(report_obj)

    bundle_id = _deterministic_uuid("bundle", f"bundle-{case.id}")
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }
