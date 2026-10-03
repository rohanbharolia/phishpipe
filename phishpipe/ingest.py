"""Stage 1 - Ingestion: parse raw EML / MSG / forwarded text into :class:`ParsedEmail`.

Uses only the standard library ``email`` package for EML so the pipeline has no
hard dependency beyond the web stack. ``extract_msg`` is imported lazily and
only when an Outlook ``.msg`` file is actually supplied.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
from email.message import Message
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Iterable

from phishpipe.config import MAX_ATTACHMENTS, MAX_BODY_CHARS, MAX_EMAIL_BYTES
from phishpipe.models import (
    AuthResults,
    ParsedAttachment,
    ParsedEmail,
    ReceivedHop,
)

# Headers we preserve verbatim for the report / analyst drill-down.
INTERESTING_HEADERS = (
    "From",
    "To",
    "Cc",
    "Subject",
    "Date",
    "Message-ID",
    "Return-Path",
    "Reply-To",
    "Sender",
    "Authentication-Results",
    "Received-SPF",
    "DKIM-Signature",
    "ARC-Authentication-Results",
    "X-Originating-IP",
    "X-Mailer",
    "X-Priority",
    "List-Unsubscribe",
    "Content-Type",
)


# ---------------------------------------------------------------------------
# Header helpers
# ---------------------------------------------------------------------------
def _decode_header(value: str | None) -> str:
    """Flatten an RFC 2047 encoded header into printable text."""
    if not value:
        return ""
    try:
        parts = email.header.decode_header(value)
    except Exception:  # pragma: no cover - malformed header, degrade gracefully
        return value
    out: list[str] = []
    for chunk, charset in parts:
        if isinstance(chunk, bytes):
            for enc in (charset, "utf-8", "latin-1"):
                if not enc:
                    continue
                try:
                    out.append(chunk.decode(enc, errors="replace"))
                    break
                except LookupError:
                    continue
            else:  # pragma: no cover
                out.append(chunk.decode("utf-8", errors="replace"))
        else:
            out.append(chunk)
    return "".join(out).strip()


def _auth_results(msg: Message) -> AuthResults:
    """Extract SPF/DKIM/DMARC results from the authentication headers.

    Real-world headers vary wildly (``Authentication-Results``,
    ``ARC-Authentication-Results``, ``Received-SPF``), so we scan every candidate
    and take the last evaluated result, which is the one added by the final
    receiving MTA.
    """
    raw_headers = [
        _decode_header(msg.get("Authentication-Results")),
        _decode_header(msg.get("ARC-Authentication-Results")),
    ]
    raw_headers = [h for h in raw_headers if h]
    raw = raw_headers[-1] if raw_headers else None

    auth = AuthResults(raw=raw)

    # ``Received-SPF: pass (google.com: ...)`` is a common fallback for SPF.
    received_spf = _decode_header(msg.get("Received-SPF"))
    if received_spf:
        auth.spf = received_spf.split()[0].lower() if received_spf.split() else None
        if not auth.raw:
            auth.raw = f"Received-SPF: {received_spf}"

    if not raw:
        return auth

    lowered = raw.lower()

    # domain=...; header.from=...; smtp.mailfrom=...
    dm = re.search(r"dmarc\s*=\s*([a-z]+)", lowered)
    if dm:
        auth.dmarc = dm.group(1)
    dm_dom = re.search(
        r"dmarc(?:\([^)]*\))?\s*=\s*[a-z]+\s*(?:;|\s)\s*(?:domain|header\.from)\s*=\s*([^\s;]+)",
        lowered,
    )
    if dm_dom:
        auth.dmarc_domain = dm_dom.group(1).strip()

    # SPF may appear as ``spf=pass``, ``spf=none (domain ...)`` or smtp.mailfrom
    sp = re.search(r"\bspf\s*=\s*([a-z]+)", lowered)
    if sp and not auth.spf:
        auth.spf = sp.group(1)
    elif sp and auth.spf in (None, "unknown"):
        auth.spf = sp.group(1)

    dk = re.search(r"\bdkim\s*=\s*([a-z]+)", lowered)
    if dk:
        auth.dkim = dk.group(1)

    hf = re.search(r"header\.from\s*=\s*([^\s;]+)", lowered)
    if hf:
        auth.header_from = hf.group(1).strip()

    return auth


def _parse_received_chain(msg: Message) -> list[ReceivedHop]:
    """Return the ``Received:`` chain ordered oldest -> newest (bottom-up)."""
    raw_values = msg.get_all("Received") or []
    hops: list[ReceivedHop] = []
    for raw in raw_values:
        text = _decode_header(raw)
        if not text:
            continue
        one_line = " ".join(text.split())

        ip = None
        ip_match = re.search(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]|(\d{1,3}(?:\.\d{1,3}){3})", one_line)
        if ip_match:
            ip = ip_match.group(1) or ip_match.group(2)

        from_match = re.search(r"\bfrom\s+([^\s;]+)", one_line, re.IGNORECASE)
        by_match = re.search(r"\bby\s+([^\s;]+)", one_line, re.IGNORECASE)
        with_match = re.search(r"\bwith\s+([^\s;]+)", one_line, re.IGNORECASE)

        # ``by`` is followed by a timestamp on most MTAs, e.g. "...; Tue, 3 Mar ..."
        timestamp = None
        tail = one_line.rsplit(";", 1)
        if len(tail) == 2:
            candidate = tail[1].strip()
            try:
                timestamp = parsedate_to_datetime(candidate).isoformat()
            except Exception:
                timestamp = candidate or None

        hops.append(
            ReceivedHop(
                raw=one_line,
                from_host=from_match.group(1) if from_match else None,
                by_host=by_match.group(1) if by_match else None,
                with_protocol=with_match.group(1) if with_match else None,
                ip=ip,
                timestamp=timestamp,
            )
        )
    hops.reverse()  # header order is newest-first; the report wants chronological
    return hops


# ---------------------------------------------------------------------------
# Body / attachment helpers
# ---------------------------------------------------------------------------
def _walk_parts(msg: Message) -> Iterable[Message]:
    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            yield part
    else:
        yield msg


def _decode_part(part: Message) -> bytes:
    payload = part.get_payload(decode=True)
    if payload is not None:
        return payload
    raw = part.get_payload()
    if isinstance(raw, str):
        return raw.encode("utf-8", errors="replace")
    return b""


def _attachment_from_part(part: Message, filename: str) -> ParsedAttachment:
    data = _decode_part(part)
    disposition = (part.get_content_disposition() or "").lower()
    return ParsedAttachment(
        filename=filename,
        content_type=part.get_content_type(),
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest() if data else None,
        md5=hashlib.md5(data).hexdigest() if data else None,  # noqa: S324 - IOC parity with AV tools
        content_id=part.get("Content-ID"),
        is_inline=disposition == "inline",
    )


def _extract_urls(text_html: str, text_plain: str) -> list[str]:
    """Collect candidate URLs from HTML ``href``/``src`` plus plain text."""
    found: list[str] = []
    if text_html:
        for match in re.findall(r"""(?:href|src)\s*=\s*["']([^"']+)["']""", text_html, re.IGNORECASE):
            found.append(match.strip())
    if text_plain:
        found.extend(re.findall(r"https?://[^\s<>\"')\]]+", text_plain, re.IGNORECASE))
        # Bare domains that look like links, e.g. "visit secure-login.example now"
        found.extend(re.findall(r"\b(?:www\.)[a-z0-9.-]+\.[a-z]{2,}[^\s<>\"')\]]*", text_plain, re.IGNORECASE))

    cleaned: list[str] = []
    seen: set[str] = set()
    for url in found:
        url = url.rstrip(".,;:!?)")
        if not url or url.lower().startswith(("mailto:", "cid:", "data:", "#")):
            continue
        if url not in seen:
            seen.add(url)
            cleaned.append(url)
    return cleaned


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def parse_raw_email(raw: bytes | str, source: str = "upload", source_name: str = "") -> ParsedEmail:
    """Parse a raw RFC 5322 message into a :class:`ParsedEmail`."""
    if isinstance(raw, str):
        raw_bytes = raw.encode("utf-8", errors="replace")
    else:
        raw_bytes = raw

    errors: list[str] = []
    if len(raw_bytes) > MAX_EMAIL_BYTES:
        errors.append(f"message truncated for parsing: {len(raw_bytes)} bytes exceeds {MAX_EMAIL_BYTES}")
        raw_bytes = raw_bytes[:MAX_EMAIL_BYTES]

    msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)

    from_name, from_addr = parseaddr(msg.get("From", ""))
    _, reply_to = parseaddr(msg.get("Reply-To", "")) if msg.get("Reply-To") else ("", "")
    _, return_path = parseaddr(msg.get("Return-Path", "")) if msg.get("Return-Path") else ("", "")
    _, sender_header = parseaddr(msg.get("Sender", "")) if msg.get("Sender") else ("", "")

    to_addresses = [a for _, a in getaddresses(msg.get_all("To", [])) if a]
    cc_addresses = [a for _, a in getaddresses(msg.get_all("Cc", [])) if a]

    headers: dict[str, str] = {}
    for name in INTERESTING_HEADERS:
        value = msg.get(name)
        if value:
            headers[name] = _decode_header(value)

    body_text, body_html = "", ""
    attachments: list[ParsedAttachment] = []
    urls: list[str] = []
    inline_text: list[str] = []

    for part in _walk_parts(msg):
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        content_type = part.get_content_type()

        if disposition == "attachment" or (filename and disposition != "inline"):
            if len(attachments) >= MAX_ATTACHMENTS:
                errors.append(f"attachment limit of {MAX_ATTACHMENTS} reached; remaining parts ignored")
                break
            attachments.append(_attachment_from_part(part, _decode_header(filename) or "unnamed"))
            continue

        if content_type == "text/plain":
            text = _decode_part(part).decode("utf-8", errors="replace")
            body_text += text
            inline_text.append(text)
        elif content_type == "text/html":
            body_html += _decode_part(part).decode("utf-8", errors="replace")
        elif filename:
            # Inline image or embedded object.
            if len(attachments) < MAX_ATTACHMENTS:
                attachments.append(_attachment_from_part(part, _decode_header(filename)))

    if not body_text and body_html:
        body_text = _html_to_text(body_html)

    body_text = body_text[:MAX_BODY_CHARS]
    body_html = body_html[:MAX_BODY_CHARS]
    urls = _extract_urls(body_html, body_text)

    date_header = _decode_header(msg.get("Date"))
    parsed_date: str | None = date_header
    if date_header:
        try:
            parsed_date = parsedate_to_datetime(date_header).isoformat()
        except Exception:
            parsed_date = date_header

    return ParsedEmail(
        source=source,
        source_name=source_name or "raw-message",
        raw_size_bytes=len(raw_bytes),
        from_address=from_addr,
        from_display_name=_decode_header(from_name),
        reply_to=reply_to,
        return_path=return_path,
        sender_header=sender_header,
        to=to_addresses,
        cc=cc_addresses,
        subject=_decode_header(msg.get("Subject")),
        date_header=parsed_date,
        message_id=_decode_header(msg.get("Message-ID")),
        auth=_auth_results(msg),
        received_hops=_parse_received_chain(msg),
        body_text=body_text,
        body_html=body_html,
        urls=urls,
        attachments=attachments,
        headers=headers,
        parse_errors=errors,
    )


def parse_email_file(path: str | Path) -> ParsedEmail:
    """Parse an ``.eml`` or ``.msg`` file from disk."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"email file not found: {p}")

    if p.suffix.lower() == ".msg":
        return _parse_msg(p)
    return parse_raw_email(p.read_bytes(), source="file", source_name=p.name)


def parse_email_upload(filename: str, content: bytes) -> ParsedEmail:
    """Parse an uploaded file (``.eml``/``.msg``) or raw text pasted by a user."""
    suffix = Path(filename or "").suffix.lower()
    if suffix == ".msg":
        tmp_dir = Path.cwd() / ".phishpipe_uploads"
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp = tmp_dir / (hashlib.sha256(content).hexdigest()[:16] + ".msg")
        tmp.write_bytes(content)
        try:
            return _parse_msg(tmp)
        finally:
            tmp.unlink(missing_ok=True)
    if suffix in {".eml", ".txt", ""}:
        return parse_raw_email(content, source="upload", source_name=filename or "pasted-message")
    # Unknown extension: try EML first, fall back to MSG.
    try:
        return parse_raw_email(content, source="upload", source_name=filename or "pasted-message")
    except Exception:
        return _parse_msg_bytes(filename, content)


def _parse_msg(path: Path) -> ParsedEmail:
    return _parse_msg_bytes(path.name, path.read_bytes())


def _parse_msg_bytes(name: str, content: bytes) -> ParsedEmail:
    """Parse an Outlook ``.msg`` file via the optional ``extract_msg`` package."""
    try:
        import extract_msg  # type: ignore
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "Outlook .msg support requires the optional dependency 'extract_msg'. "
            "Install it with: pip install extract_msg"
        ) from exc

    tmp_dir = Path.cwd() / ".phishpipe_uploads"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    tmp = tmp_dir / (hashlib.sha256(content).hexdigest()[:16] + ".msg")
    tmp.write_bytes(content)
    try:
        with extract_msg.openMsg(str(tmp)) as msg:  # type: ignore[attr-defined]
            body_text = msg.body or ""
            body_html = msg.htmlBody or ""
            if isinstance(body_html, bytes):
                body_html = body_html.decode("utf-8", errors="replace")
            attachments = [
                ParsedAttachment(
                    filename=getattr(a, "longFilename", None) or getattr(a, "name", "unnamed"),
                    content_type=getattr(a, "type", "") or "application/octet-stream",
                    size_bytes=len(getattr(a, "data", b"") or b""),
                    sha256=hashlib.sha256(a.data).hexdigest() if getattr(a, "data", None) else None,
                    md5=hashlib.md5(a.data).hexdigest() if getattr(a, "data", None) else None,  # noqa: S324
                )
                for a in getattr(msg, "attachments", [])
            ]
            return ParsedEmail(
                source="file",
                source_name=name,
                raw_size_bytes=len(content),
                from_address=getattr(msg, "sender", "") or "",
                from_display_name="",
                to=[getattr(msg, "to", "") or ""] if getattr(msg, "to", "") else [],
                cc=[getattr(msg, "cc", "") or ""] if getattr(msg, "cc", "") else [],
                subject=getattr(msg, "subject", "") or "",
                date_header=str(getattr(msg, "date", "") or "") or None,
                message_id="",
                body_text=body_text,
                body_html=body_html,
                urls=_extract_urls(body_html, body_text),
                attachments=attachments,
                parse_errors=[],
            )
    finally:
        tmp.unlink(missing_ok=True)


_TAG_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
_BLOCK_TAGS = re.compile(r"</?(p|div|br|tr|td|li|h[1-6]|table|section)[^>]*>", re.IGNORECASE)
_ANY_TAG = re.compile(r"<[^>]+>")


def _html_to_text(html: str) -> str:
    """Best-effort HTML -> text conversion for messages with no text/plain part."""
    text = _TAG_RE.sub(" ", html)
    text = re.sub(r"""<a[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>""", r"\2 (\1)", text, flags=re.I | re.S)
    text = _BLOCK_TAGS.sub("\n", text)
    text = _ANY_TAG.sub("", text)
    text = re.sub(r"&nbsp;", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&#\d+;", "", text)
    text = re.sub(r"[ \t]{2,}", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()
