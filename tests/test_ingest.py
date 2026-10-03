"""Stage 1 - ingestion: header parsing, authentication results, attachments."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from phishpipe.ingest import parse_email_file, parse_raw_email
from tests.conftest import DHL_PHISH, INVOICE_PHISH, LEGIT_MAIL, M365_PHISH, PLAIN_LEGIT


def test_parses_basic_headers():
    email = parse_raw_email(PLAIN_LEGIT)
    assert email.from_address == "awareness@yourcompany.com"
    assert email.subject == "October security awareness briefing"
    assert email.to == ["jane.doe@yourcompany.com"]
    assert email.message_id == "<20260929080000@yourcompany.com>"
    assert email.date_header is not None


def test_extracts_authentication_results():
    email = parse_email_file(M365_PHISH)
    assert email.auth.spf == "fail"
    assert email.auth.dkim == "fail"
    assert email.auth.dmarc == "fail"
    assert email.auth.header_from == "portal.office.com"
    assert email.auth.any_fail is True
    assert email.auth.aligned_pass is False


def test_passing_authentication_is_recognised():
    email = parse_email_file(LEGIT_MAIL)
    assert email.auth.spf == "pass"
    assert email.auth.dkim == "pass"
    assert email.auth.dmarc == "pass"
    assert email.auth.aligned_pass is True


def test_received_chain_is_ordered_oldest_first():
    email = parse_email_file(M365_PHISH)
    assert len(email.received_hops) == 3
    # Chronological order means the sending host appears before the receiver.
    assert email.received_hops[0].ip == "185.234.72.19"
    assert all(hop.raw for hop in email.received_hops)


def test_html_anchor_urls_are_extracted():
    email = parse_email_file(M365_PHISH)
    assert any("microsoft365-secure-portal.xyz" in u for u in email.urls)
    assert any("portal.office.com" in u for u in email.urls)


def test_plain_text_urls_are_extracted():
    email = parse_email_file(LEGIT_MAIL)
    assert email.urls == ["https://intranet.yourcompany.com/maintenance/2026-w40"]


def test_attachments_are_hashed():
    email = parse_email_file(INVOICE_PHISH)
    names = {a.filename for a in email.attachments}
    assert names == {"Q3_Invoice_Adjustment.docm", "backup_scan.pdf.exe"}
    for att in email.attachments:
        assert att.sha256 and len(att.sha256) == 64
        assert att.md5 and len(att.md5) == 32
        assert att.size_bytes > 0
    # Hashes must be stable across parses (they are IOCs).
    again = parse_email_file(INVOICE_PHISH)
    assert {a.sha256 for a in again.attachments} == {a.sha256 for a in email.attachments}


def test_html_only_message_gets_text_fallback():
    raw = (
        "From: a@b.example\nTo: c@d.example\nSubject: html only\n"
        "Content-Type: text/html\n\n"
        "<html><body><p>Hello <b>there</b></p></body></html>\n"
    )
    email = parse_raw_email(raw)
    assert "Hello" in email.body_text
    assert "there" in email.body_text


def test_rfc2047_encoded_subject_is_decoded():
    # Built from codepoints (and base64 computed here) so the test file itself
    # stays pure ASCII and immune to editor/encoding mangling.
    display_name = "J\u00fcrgen Verner"
    subject = "R\u00fcckung \u00d6ffolgien"
    enc_name = base64.b64encode(display_name.encode("utf-8")).decode()
    enc_subject = base64.b64encode(subject.encode("utf-8")).decode()

    raw = (
        f"From: =?utf-8?B?{enc_name}?= <jorgen@example.com>\n"
        f"To: a@b.example\n"
        f"Subject: =?utf-8?B?{enc_subject}?= \n"
        "MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "\nbody\n"
    )
    email = parse_raw_email(raw)
    assert email.from_display_name == display_name
    assert email.subject == subject
    assert email.from_address == "jorgen@example.com"


def test_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        parse_email_file(tmp_path / "nope.eml")


def test_dhl_sample_parses_with_single_link():
    email = parse_email_file(DHL_PHISH)
    assert len(email.urls) == 1
    assert "parcel-redelivery-dhl.click" in email.urls[0]
    assert email.auth.spf == "pass"


def test_oversized_message_is_truncated_not_rejected():
    from phishpipe.config import MAX_EMAIL_BYTES

    raw = b"From: a@b.example\nSubject: big\n\n" + b"X" * (MAX_EMAIL_BYTES + 1000)
    email = parse_raw_email(raw)
    assert email.raw_size_bytes <= MAX_EMAIL_BYTES
    assert email.parse_errors  # truncation is reported, not silently swallowed
