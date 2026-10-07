"""Homoglyph, Typosquatting, and Quishing (QR Phishing) Forensic Analyzers.

Provides deterministic detection of brand lookalike domains, character substitutions,
and QR code lures without external dependencies.
"""

from __future__ import annotations

import re
from typing import Any

# High-value targeted brands
TARGET_BRANDS: dict[str, str] = {
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "google": "google.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "paypal": "paypal.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "netflix": "netflix.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.com",
    "adobe": "adobe.com",
}

# Common visual character substitutions
LEET_SUBS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "8": "b",
    "@": "a",
    "$": "s",
    "vv": "w",
    "rn": "m",
}


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def normalize_domain_homoglyphs(domain: str) -> str:
    """Convert common leetspeak substitutions back to standard letters."""
    norm = domain.lower()
    for sub, repl in LEET_SUBS.items():
        norm = norm.replace(sub, repl)
    return norm


def check_domain_typosquatting(domain: str) -> dict[str, Any] | None:
    """Analyze whether domain impersonates a known protected brand.

    Returns dict with match details if suspicious, else None.
    """
    if not domain:
        return None
    d = domain.lower().split(":")[0].strip(".")
    stem = d.split(".")[0]  # e.g., 'micros0ft' from 'micros0ft.xyz'
    normalized_stem = normalize_domain_homoglyphs(stem)

    for brand, legitimate_domain in TARGET_BRANDS.items():
        # Exact brand match on an unauthorized TLD
        if stem == brand and d != legitimate_domain and not d.endswith("." + legitimate_domain):
            return {
                "brand": brand,
                "type": "tld_impersonation",
                "detail": f"Exact brand '{brand}' registered under non-official domain '{d}'",
                "confidence": 95,
            }

        # Character substitution match (e.g. micros0ft or rnicros0ft)
        if normalized_stem == brand and stem != brand:
            return {
                "brand": brand,
                "type": "homoglyph_substitution",
                "detail": f"Lookalike substitution '{stem}' mimics protected brand '{brand}'",
                "confidence": 98,
            }

        # Subdomain / prefix bait (e.g., login-microsoft365 or account-verify-google)
        if brand in d and d != legitimate_domain and not d.endswith("." + legitimate_domain):
            return {
                "brand": brand,
                "type": "brand_in_domain",
                "detail": f"Brand name '{brand}' embedded in external domain '{d}'",
                "confidence": 90,
            }

        # Levenshtein distance 1 (1-char typo)
        if 4 <= len(brand) <= len(stem) <= len(brand) + 2:
            dist = _levenshtein(stem, brand)
            if dist == 1 and d != legitimate_domain:
                return {
                    "brand": brand,
                    "type": "typosquatting_distance_1",
                    "detail": f"Domain stem '{stem}' is a 1-character typo of '{brand}'",
                    "confidence": 85,
                }

    return None


def detect_quishing(
    subject: str,
    body_text: str,
    html: str,
    attachments: list[Any],
) -> dict[str, Any] | None:
    """Detect QR code phishing (Quishing) lures in body or attachments."""
    haystack = f"{subject} {body_text} {html}".lower()

    qr_terms = [
        "scan the qr code",
        "scan qr code",
        "qr code below",
        "scan this code",
        "scan with your phone",
        "scan with your mobile",
        "use your camera to scan",
        "authenticator qr",
        "scan the barcode",
        "authenticator app to scan",
        "2fa qr",
        "mfa qr",
    ]
    matched_term = next((t for t in qr_terms if t in haystack), None)

    # Check attachment filenames
    qr_attachment = None
    for att in attachments:
        fn = getattr(att, "filename", str(att)).lower()
        if any(tok in fn for tok in ["qr", "qrcode", "scan_me", "barcode", "auth_code"]):
            qr_attachment = fn
            break

    if matched_term or qr_attachment:
        evidence = []
        if matched_term:
            evidence.append(f"Prompt text: '{matched_term}'")
        if qr_attachment:
            evidence.append(f"Attachment name: '{qr_attachment}'")

        return {
            "quishing_detected": True,
            "evidence": "; ".join(evidence),
            "severity": "high",
            "summary": "QR code phishing (Quishing) lure detected: instructs recipient to bypass perimeter filters via mobile camera",
        }

    return None
