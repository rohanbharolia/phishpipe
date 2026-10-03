"""Stage 2 - extraction: indicators, brand logic, link analysis."""

from __future__ import annotations

from phishpipe.extract import (
    build_content_profile,
    extract_indicators,
    host_from_url,
    registrable_domain,
)
from phishpipe.ingest import parse_email_file, parse_raw_email
from tests.conftest import INVOICE_PHISH, LEGIT_MAIL, M365_PHISH, PLAIN_LEGIT


# --- helpers ---------------------------------------------------------------
def test_registrable_domain():
    assert registrable_domain("mail.google.com") == "google.com"
    assert registrable_domain("sub.example.co.uk") == "example.co.uk"
    assert registrable_domain("192.0.2.1") == "192.0.2.1"
    assert registrable_domain("EXAMPLE.COM.") == "example.com"
    assert registrable_domain("") == ""


def test_host_from_url_handles_malformed_input():
    assert host_from_url("https://Example.COM:8443/path") == "example.com"
    assert host_from_url("example.com/path") == "example.com"
    assert host_from_url("http://user:pass@[192.0.2.5]:80/a") == "192.0.2.5"


# --- indicators ------------------------------------------------------------
def test_phish_indicator_types(m365_case):
    kinds = {i.type for i in m365_case.indicators}
    assert {"url", "domain", "ip", "email"} <= kinds
    urls = [i.value for i in m365_case.indicators if i.type == "url"]
    assert any("microsoft365-secure-portal.xyz" in u for u in urls)
    # Sender IP from the Received chain is captured.
    assert any(i.value == "185.234.72.19" for i in m365_case.indicators if i.type == "ip")


def test_indicators_are_deduplicated(pipeline):
    email = parse_email_file(M365_PHISH)
    profile = build_content_profile(email)
    inds = extract_indicators(email, profile)
    values = [(i.type, i.value) for i in inds]
    assert len(values) == len(set(values))


def test_indicator_defanging():
    from phishpipe.models import Indicator

    url = Indicator(type="url", value="https://evil.example/x")
    assert url.defanged.startswith("hxxps://")
    dom = Indicator(type="domain", value="evil.example")
    assert dom.defanged == "evil[.]example"
    mail = Indicator(type="email", value="a@b.example")
    assert mail.defanged == "a[@]b.example"


def test_attachment_hash_indicators(pipeline):
    email = parse_email_file(INVOICE_PHISH)
    profile = build_content_profile(email)
    inds = extract_indicators(email, profile)
    hashes = [i.value for i in inds if i.type == "hash"]
    assert len(hashes) >= 2  # sha256 + md5 per attachment at minimum
    files = [i.value for i in inds if i.type == "attachment"]
    assert "backup_scan.pdf.exe" in files


# --- brand logic -----------------------------------------------------------
def test_typosquat_is_brand_impersonation(detections):
    email = parse_email_file(M365_PHISH)
    profile = build_content_profile(email, detections)
    assert profile.display_name_spoofed is True
    assert profile.brand_impersonation is True
    assert profile.display_name_brand == "microsoft"
    # The typosquat contains "microsoft" but is not an official Microsoft domain.
    assert profile.sender_domain == "secure-login-microsoft365.xyz"


def test_allowlisted_sender_is_not_brand_impersonation(detections):
    email = parse_email_file(LEGIT_MAIL)
    profile = build_content_profile(email, detections)
    assert profile.sender_allowlisted is True
    assert profile.display_name_spoofed is False
    assert profile.brand_impersonation is False


def test_official_brand_sender_is_not_flagged(detections):
    raw = (
        "From: Microsoft <noreply@microsoft.com>\n"
        "To: jane@yourcompany.com\n"
        "Subject: Microsoft account notice\n"
        "Content-Type: text/plain\n\n"
        "Your Microsoft account statement is ready.\n"
    )
    profile = build_content_profile(parse_raw_email(raw), detections)
    assert profile.display_name_spoofed is False
    assert profile.brand_impersonation is False


def test_externally_sent_brand_mail_from_unrelated_domain_is_flagged(detections):
    raw = (
        "From: Payroll <payroll@random-hosting.top>\n"
        "To: jane@yourcompany.com\n"
        "Subject: PayPal payout confirmation\n"
        "Content-Type: text/plain\n\n"
        "Your PayPal payout is ready to claim.\n"
    )
    profile = build_content_profile(parse_raw_email(raw), detections)
    assert profile.brand_impersonation is True


# --- link analysis ---------------------------------------------------------
def test_mismatched_anchor_is_detected(detections):
    email = parse_email_file(M365_PHISH)
    profile = build_content_profile(email, detections)
    assert profile.mismatched_links_found
    assert profile.credential_urls_found
    assert profile.suspicious_tlds_found


def test_matching_links_are_not_flagged(detections):
    email = parse_email_file(LEGIT_MAIL)
    profile = build_content_profile(email, detections)
    assert not profile.mismatched_links_found
    assert not profile.ip_links_found
    assert not profile.shorteners_found


def test_ip_based_link_flagged(detections):
    raw = (
        "From: a@b.example\nTo: c@d.example\nSubject: x\n"
        "Content-Type: text/plain\n\n"
        "Open http://198.51.100.77/login.php now\n"
    )
    profile = build_content_profile(parse_raw_email(raw), detections)
    assert profile.ip_links_found
    assert profile.credential_urls_found


# --- content signals -------------------------------------------------------
def test_wordlist_hits(detections):
    email = parse_email_file(M365_PHISH)
    profile = build_content_profile(email, detections)
    assert profile.urgency_hits
    assert profile.threat_hits
    assert profile.sensitive_request_hits
    assert profile.generic_greeting_hit


def test_attachment_risk_flags(pipeline, detections):
    email = parse_email_file(INVOICE_PHISH)
    profile = build_content_profile(email, detections)
    flags = {a.filename: a for a in profile.attachments}
    assert flags["backup_scan.pdf.exe"].dangerous_ext is True
    assert flags["backup_scan.pdf.exe"].double_extension is True
    assert flags["Q3_Invoice_Adjustment.docm"].macro_ext is True


def test_legit_message_has_no_suspicious_elements(legit_case, detections):
    from phishpipe.extract import build_content_profile

    profile = build_content_profile(legit_case.email, detections)
    assert profile.suspicious_element_count == 0
