"""Stage 2 - Extraction: turn a parsed message into indicators and a content profile.

Two outputs feed the scorer:

* ``extract_indicators`` - the atomic observables (URLs, domains, IPs, hashes)
  that get enriched and published to the IOC report.
* ``build_content_profile`` - the derived, human-meaningful observations such as
  "anchor text does not match href" or "display name impersonates Microsoft".
  These are what make the final score explainable.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urlparse

from phishpipe.detections import Detections, load_detections
from phishpipe.models import Indicator, ParsedEmail, ReceivedChain, ReceivedHop

# ---------------------------------------------------------------------------
# Domain helpers
# ---------------------------------------------------------------------------
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.za", "com.br", "com.mx", "co.in", "com.sg", "co.jp",
    "com.cn", "com.tw", "com.hk", "com.ar", "com.tr", "com.pl", "com.ua",
    "gov.in", "gov.uk", "net.cn", "org.cn", "edu.au", "co.kr", "or.kr",
}


def registrable_domain(host: str) -> str:
    """Approximate eTLD+1 without needing the public-suffix list.

    Good enough for comparing "does this link belong to the claimed sender",
    which is the only place we use it.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    if _is_ip(host):
        return host
    if host.startswith("*."):
        host = host[2:]
    labels = [l for l in host.split(".") if l]
    if len(labels) <= 2:
        return ".".join(labels)
    candidate = ".".join(labels[-2:])
    if candidate in _MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return candidate


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip("[]"))
        return True
    except ValueError:
        return False


def _is_official_brand_sender(brand: str, domain: str, detections) -> bool:
    """True when ``domain`` is one of the brand's own official sending domains.

    This is what separates "Microsoft wrote to you" from "someone claiming to be
    Microsoft wrote to you": a typosquat like ``secure-login-microsoft365.xyz``
    contains the brand name but is not in the brand's official domain list.
    Brands with no mapping fall back to plain substring containment.
    """
    official = detections.official_domains_for(brand)
    if not official:
        return brand.replace(" ", "") in domain.replace(" ", "")
    return any(domain == d or domain.endswith("." + d) for d in official)


def _manual_host(candidate: str) -> str:
    """Fallback host extraction when :func:`urlparse` rejects the URL.

    Python 3.12 raises ``ValueError`` for bracketed IPv4 (``http://[192.0.2.5]/``),
    which phishing kits do produce, so the authority is parsed by hand instead of
    losing the host entirely.
    """
    rest = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", candidate)
    rest = re.split(r"[/?#]", rest, 1)[0]
    rest = rest.rsplit("@", 1)[-1]  # drop userinfo
    if rest.startswith("["):
        end = rest.find("]")
        if end > 0:
            return rest[1:end].lower()
    if ":" in rest:
        head, _, tail = rest.rpartition(":")
        if tail.isdigit():
            rest = head
    return rest.strip("[]").lower()


def host_from_url(url: str) -> str:
    """Best-effort host extraction for malformed phishing URLs."""
    candidate = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
    except ValueError:
        return _manual_host(candidate)
    host = parsed.hostname or ""
    if not host:
        # Handles "example.com/path" style values fed in without a scheme.
        host = _manual_host(candidate)
    return host.lower()


def _anchor_hosts(html: str) -> list[tuple[str, str]]:
    """Return ``(anchor_text, href)`` pairs in document order."""
    pairs: list[tuple[str, str]] = []

    class _A(HTMLParser):
        def __init__(self) -> None:
            super().__init__(convert_charrefs=True)
            self._href: str | None = None
            self._text: list[str] = []

        def handle_starttag(self, tag, attrs):
            if tag.lower() == "a":
                self._href = dict(attrs).get("href")
                self._text = []

        def handle_data(self, data):
            if self._href is not None:
                self._text.append(data)

        def handle_endtag(self, tag):
            if tag.lower() == "a" and self._href is not None:
                pairs.append(("".join(self._text).strip(), self._href.strip()))
                self._href = None
                self._text = []

    parser = _A()
    try:
        parser.feed(html)
    except Exception:  # malformed HTML is common in phishing kits
        return pairs
    return pairs


# ---------------------------------------------------------------------------
# Content profile
# ---------------------------------------------------------------------------
@dataclass
class LinkObservation:
    url: str
    host: str
    is_ip_host: bool = False
    is_shortener: bool = False
    is_suspicious_tld: bool = False
    is_punycode: bool = False
    has_credential_token: bool = False
    anchor_text: str = ""
    mismatched: bool = False


@dataclass
class AttachmentObservation:
    filename: str
    content_type: str
    size_bytes: int
    dangerous_ext: bool = False
    macro_ext: bool = False
    double_extension: bool = False
    content_type_mismatch: bool = False
    sha256: str | None = None
    md5: str | None = None


@dataclass
class ContentProfile:
    """Everything the scorer needs to reason about the message."""

    subject: str = ""
    body_text: str = ""
    haystack: str = ""

    urgency_hits: list[str] = field(default_factory=list)
    threat_hits: list[str] = field(default_factory=list)
    sensitive_request_hits: list[str] = field(default_factory=list)
    macro_instruction_hits: list[str] = field(default_factory=list)
    generic_greeting_hit: str = ""
    brands_mentioned: list[str] = field(default_factory=list)

    links: list[LinkObservation] = field(default_factory=list)
    attachments: list[AttachmentObservation] = field(default_factory=list)

    sender_domain: str = ""
    reply_to_domain: str = ""
    return_path_domain: str = ""
    origin_domain: str = ""

    display_name: str = ""
    display_name_brand: str = ""
    display_name_spoofed: bool = False
    brand_impersonation: bool = False
    sender_allowlisted: bool = False
    sender_internal: bool = False
    unknown_sender: bool = True

    password_protected_hint: bool = False
    suspicious_tlds_found: list[str] = field(default_factory=list)
    shorteners_found: list[str] = field(default_factory=list)
    ip_links_found: list[str] = field(default_factory=list)
    mismatched_links_found: list[str] = field(default_factory=list)
    credential_urls_found: list[str] = field(default_factory=list)
    punycode_found: list[str] = field(default_factory=list)

    @property
    def mismatched_link_count(self) -> int:
        return len(self.mismatched_links_found)

    @property
    def suspicious_element_count(self) -> int:
        return sum(
            [
                bool(self.urgency_hits),
                bool(self.threat_hits),
                bool(self.sensitive_request_hits),
                bool(self.macro_instruction_hits),
                bool(self.mismatched_links_found),
                bool(self.ip_links_found),
                bool(self.shorteners_found),
                bool(self.suspicious_tlds_found),
                bool(self.punycode_found),
                bool(self.credential_urls_found),
                self.display_name_spoofed,
                self.brand_impersonation,
                self.password_protected_hint,
                any(a.dangerous_ext or a.double_extension or a.macro_ext for a in self.attachments),
            ]
        )


def _find_terms(haystack: str, terms: list[str]) -> list[str]:
    """Return the terms present in ``haystack``.

    Terms containing non-word characters are matched literally; plain words are
    matched on word boundaries so "act now" does not match "react nows".
    """
    hits: list[str] = []
    for term in terms:
        if not term:
            continue
        if re.search(r"\w", term):
            pattern = r"(?<!\w)" + re.escape(term) + r"(?!\w)"
            found = re.search(pattern, haystack, re.IGNORECASE)
        else:
            found = re.search(re.escape(term), haystack, re.IGNORECASE)
        if found:
            hits.append(term)
    return hits


def build_content_profile(
    email: ParsedEmail,
    detections: Detections | None = None,
) -> ContentProfile:
    detections = detections or load_detections()
    body = email.body_text or ""
    subject = email.subject or ""
    haystack = f"{subject}\n{body}"

    wl = detections.wordlist
    profile = ContentProfile(subject=subject, body_text=body, haystack=haystack)

    profile.urgency_hits = _find_terms(haystack, wl("urgency"))
    profile.threat_hits = _find_terms(haystack, wl("threats"))
    profile.sensitive_request_hits = _find_terms(haystack, wl("sensitive_requests"))
    profile.macro_instruction_hits = _find_terms(haystack, wl("macro_instructions"))
    profile.brands_mentioned = _find_terms(haystack, wl("brands"))

    for greeting in wl("generic_greetings"):
        if greeting in haystack.lower():
            profile.generic_greeting_hit = greeting
            break

    profile.password_protected_hint = bool(
        re.search(r"\bpassword\s+(?:for|to open|is|:)\b|\b(?:protected|encrypted)\s+(?:archive|file|attachment)\b", haystack, re.I)
        or re.search(r"\bpassword\s*:\s*\S+", haystack, re.I)
    )

    # --- domains -----------------------------------------------------------
    profile.sender_domain = registrable_domain(email.from_address.split("@")[-1]) if "@" in email.from_address else ""
    profile.reply_to_domain = registrable_domain(email.reply_to.split("@")[-1]) if "@" in email.reply_to else ""
    profile.return_path_domain = registrable_domain(email.return_path.split("@")[-1]) if "@" in email.return_path else ""

    allowlisted = set(wl("allowlist_domains"))
    internal = set(wl("internal_domains"))
    profile.sender_allowlisted = profile.sender_domain in allowlisted
    profile.sender_internal = profile.sender_domain in internal
    profile.unknown_sender = not (profile.sender_allowlisted or profile.sender_internal)

    profile.display_name = email.from_display_name or ""
    lower_display = profile.display_name.lower()
    for brand in wl("brands"):
        if brand in lower_display:
            profile.display_name_brand = brand
            break

    trusted_sender = profile.sender_allowlisted or profile.sender_internal

    # Display-name spoof: the friendly name claims a brand that the sending
    # domain is not one of that brand's official domains. Suppressed for
    # allow-listed/internal senders, which may legitimately reference brands.
    if profile.display_name_brand and profile.sender_domain and not trusted_sender:
        if not _is_official_brand_sender(profile.display_name_brand, profile.sender_domain, detections):
            profile.display_name_spoofed = True

    # Brand impersonation: the body invokes brands, but the sending domain is
    # not an official domain for any of them.
    if profile.brands_mentioned and profile.sender_domain and not trusted_sender:
        official = [
            b for b in profile.brands_mentioned if _is_official_brand_sender(b, profile.sender_domain, detections)
        ]
        if not official:
            profile.brand_impersonation = True

    # --- links -------------------------------------------------------------
    credential_tokens = set(wl("credential_url_tokens"))
    suspicious_tlds = set(wl("suspicious_tlds"))
    shorteners = set(wl("url_shorteners"))
    anchor_pairs = _anchor_hosts(email.body_html) if email.body_html else []

    anchor_by_href: dict[str, str] = {}
    for text, href in anchor_pairs:
        anchor_by_href.setdefault(href, text)

    for url in email.urls:
        host = host_from_url(url)
        if not host:
            continue
        ext = registrable_domain(host)
        obs = LinkObservation(url=url, host=host)
        obs.is_ip_host = _is_ip(host)
        obs.is_shortener = ext in shorteners or host in shorteners
        obs.is_suspicious_tld = any(host.endswith(tld) for tld in suspicious_tlds)
        obs.is_punycode = "xn--" in host

        path_tokens = set(re.split(r"[/?#&=._-]", url.lower()))
        obs.has_credential_token = bool(credential_tokens & path_tokens)

        anchor_text = anchor_by_href.get(url, "")
        obs.anchor_text = anchor_text
        if anchor_text:
            anchor_host = host_from_url(anchor_text) if re.search(r"https?://|www\.|\.", anchor_text) else ""
            if anchor_host:
                obs.mismatched = registrable_domain(anchor_host) != ext
            elif re.search(r"https?://|www\.", anchor_text):
                obs.mismatched = True
            else:
                # Plain-text anchor: flag when it names a brand the host does not own.
                for brand in wl("brands"):
                    if brand in anchor_text.lower() and brand.replace(" ", "") not in host.replace(" ", ""):
                        obs.mismatched = True
                        break

        if obs.is_ip_host:
            profile.ip_links_found.append(url)
        if obs.is_shortener:
            profile.shorteners_found.append(url)
        if obs.is_suspicious_tld:
            profile.suspicious_tlds_found.append(url)
        if obs.is_punycode:
            profile.punycode_found.append(url)
        # A credential-bait path only matters when something else about the link
        # is also wrong: it advertises a different destination, impersonates a
        # brand the sender does not own, or resolves to suspicious infrastructure.
        brand_or_host_risk = (
            obs.mismatched
            or profile.brand_impersonation
            or obs.is_ip_host
            or obs.is_suspicious_tld
            or obs.is_punycode
        )
        if obs.has_credential_token and brand_or_host_risk:
            profile.credential_urls_found.append(url)
        if obs.mismatched:
            profile.mismatched_links_found.append(f"{anchor_text[:60]!r} -> {url}")
        profile.links.append(obs)

    # --- attachments -------------------------------------------------------
    dangerous = set(wl("dangerous_extensions"))
    macro = set(wl("macro_extensions"))
    benign = set(wl("benign_extensions"))

    for att in email.attachments:
        name = (att.filename or "").lower()
        obs = AttachmentObservation(
            filename=att.filename,
            content_type=att.content_type,
            size_bytes=att.size_bytes,
            sha256=att.sha256,
            md5=att.md5,
        )
        obs.dangerous_ext = any(name.endswith(ext) for ext in dangerous)
        obs.macro_ext = any(name.endswith(ext) for ext in macro)

        # invoice.pdf.exe -> a dangerous terminal extension preceded by another
        # extension. This is the classic file-name disguise technique.
        stem, _, terminal_ext = name.rpartition(".")
        if terminal_ext and any(name.endswith(e) for e in dangerous) and "." in stem:
            obs.double_extension = True

        if terminal_ext and benign and not any(name.endswith(e) for e in dangerous | macro):
            declared = (att.content_type or "").lower()
            expected = _expected_mime(terminal_ext)
            if expected and declared and declared.split(";")[0].strip() != expected:
                # Only flag clear contradictions (e.g. .pdf served as application/x-msdownload)
                if expected in {"application/pdf", "image/png", "image/jpeg"} and "octet-stream" in declared:
                    obs.content_type_mismatch = True
                elif declared in {"application/x-msdownload", "application/x-msdos-program", "text/plain"} and expected != "text/plain":
                    obs.content_type_mismatch = True

        profile.attachments.append(obs)

    return profile


_MIME_BY_EXT = {
    "pdf": "application/pdf",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "gif": "image/gif",
    "txt": "text/plain",
    "csv": "text/csv",
    "html": "text/html",
    "htm": "text/html",
    "zip": "application/zip",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}


def _expected_mime(ext: str) -> str:
    return _MIME_BY_EXT.get(ext, "")


# ---------------------------------------------------------------------------
# Indicator extraction
# ---------------------------------------------------------------------------
def _context_snippet(text: str, needle: str, radius: int = 70) -> str:
    idx = text.lower().find(needle.lower())
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(needle) + radius)
    snippet = " ".join(text[start:end].split())
    return ("..." if start > 0 else "") + snippet + ("..." if end < len(text) else "")


def extract_indicators(
    email: ParsedEmail,
    profile: ContentProfile | None = None,
    detections: Detections | None = None,
) -> list[Indicator]:
    """Collect every observable, de-duplicated, with provenance for the report."""
    detections = detections or load_detections()
    profile = profile or build_content_profile(email, detections)

    indicators: list[Indicator] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str, source: str, context: str = "") -> None:
        value = value.strip()
        if not value or (kind, value) in seen:
            return
        seen.add((kind, value))
        indicators.append(
            Indicator(type=kind, value=value, source=source, context=context, first_seen_in=source)
        )

    # URLs
    for url in email.urls:
        if url.lower().startswith(("mailto:", "cid:", "data:", "#")):
            continue
        add("url", url, "body", _context_snippet(profile.haystack, url))

    # Domains (from links, sender, envelope)
    for obs in profile.links:
        if obs.host:
            add("domain", registrable_domain(obs.host) or obs.host, "body", f"link host in {obs.url[:80]}")
    if profile.sender_domain:
        add("domain", profile.sender_domain, "header", f"From: {email.from_address}")
    if profile.reply_to_domain and profile.reply_to_domain != profile.sender_domain:
        add("domain", profile.reply_to_domain, "header", f"Reply-To: {email.reply_to}")
    if profile.return_path_domain and profile.return_path_domain != profile.sender_domain:
        add("domain", profile.return_path_domain, "header", f"Return-Path: {email.return_path}")

    # IPs (links + Received chain)
    for url in profile.ip_links_found:
        host = host_from_url(url)
        if host:
            add("ip", host.strip("[]"), "body", f"raw IP embedded in URL {url[:80]}")
    for hop in email.received_hops:
        if hop.ip:
            add("ip", hop.ip, "header", f"Received: {hop.raw[:120]}")
    origin_ip = _originating_ip(email.received_hops)
    if origin_ip:
        add("ip", origin_ip, "header", "first external Received hop")

    # Email addresses
    if email.from_address:
        add("email", email.from_address, "header", "From")
    if email.reply_to and email.reply_to != email.from_address:
        add("email", email.reply_to, "header", "Reply-To")
    if email.return_path and email.return_path != email.from_address:
        add("email", email.return_path, "header", "Return-Path")

    # Attachment hashes + names
    for att in email.attachments:
        if att.sha256:
            add("hash", att.sha256, "attachment", f"SHA-256 of {att.filename}")
        if att.md5:
            add("hash", att.md5, "attachment", f"MD5 of {att.filename}")
        add("attachment", att.filename, "attachment", f"{att.content_type}, {att.size_bytes} bytes")

    return indicators


def _originating_ip(hops: list[ReceivedHop]) -> str | None:
    """IP of the first hop that left the sending organisation, if determinable."""
    for hop in hops:
        if hop.ip:
            return hop.ip
    return None


def build_received_chain(hops: list[ReceivedHop]) -> ReceivedChain:
    if not hops:
        return ReceivedChain()
    origin = next((h for h in hops if h.ip), None)
    return ReceivedChain(
        hops=hops,
        origin_ip=origin.ip if origin else None,
        origin_helo=origin.from_host if origin else None,
        first_received=hops[0].timestamp,
        hop_count=len(hops),
    )
