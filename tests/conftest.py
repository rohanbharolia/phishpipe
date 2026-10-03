"""Shared fixtures for the PhishPipe test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SAMPLES = ROOT / "samples"
M365_PHISH = SAMPLES / "phish_m365_credential_harvest.eml"
DHL_PHISH = SAMPLES / "phish_dhl_redelivery.eml"
INVOICE_PHISH = SAMPLES / "phish_invoice_attachment.eml"
LEGIT_MAIL = SAMPLES / "legit_it_maintenance_notice.eml"

# A second, independent legitimate message so false-positive suppression is not
# tuned to a single fixture.
PLAIN_LEGIT = """\
From: Security Awareness <awareness@yourcompany.com>
To: jane.doe@yourcompany.com
Subject: October security awareness briefing
Date: Tue, 29 Sep 2026 08:00:00 +0000
Message-ID: <20260929080000@yourcompany.com>
Authentication-Results: mx01.yourcompany.com;
 spf=pass smtp.mailfrom=yourcompany.com;
 dkim=pass header.d=yourcompany.com;
 dmarc=pass header.from=yourcompany.com
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello team,

This month's briefing covers how to spot unexpected file attachments.
The slides are on the intranet at https://intranet.yourcompany.com/briefing/oct

Thanks,
Security Awareness
"""


@pytest.fixture(scope="session")
def samples_dir() -> Path:
    return SAMPLES


@pytest.fixture(scope="session")
def detections():
    from phishpipe.detections import load_detections

    return load_detections()


@pytest.fixture()
def settings(tmp_path):
    """Settings with an isolated SQLite DB so tests never touch the real one."""
    from phishpipe.config import load_settings

    s = load_settings()
    s.cases_db_file = tmp_path / "cases.db"
    return s


@pytest.fixture()
def pipeline(settings, detections):
    from phishpipe.pipeline import InvestigationPipeline

    return InvestigationPipeline(settings=settings, detections=detections, persist=False)


@pytest.fixture()
def m365_case(pipeline):
    return pipeline.investigate_file(M365_PHISH)


@pytest.fixture()
def legit_case(pipeline):
    return pipeline.investigate_file(LEGIT_MAIL)
