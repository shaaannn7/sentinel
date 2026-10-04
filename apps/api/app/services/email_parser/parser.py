"""Main email parsing entry point."""

import email
import ipaddress
import re
from email import policy
from email.message import Message

from app.services.email_parser.models import (
    ParsedEmail,
    EmailHeader,
    Indicator,
)
from app.services.email_parser.headers import (
    parse_received_hops,
    parse_authentication_results,
    extract_addresses,
    first_address,
    get_header,
)
from app.services.email_parser.body import extract_bodies, sanitize_html, strip_html
from app.services.email_parser.urls import extract_urls
from app.services.email_parser.attachments import extract_attachments

_IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F:.]+(?![\w:])")
_DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b")


def _is_private_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_reserved or address.is_link_local


def parse_email(raw_bytes: bytes) -> ParsedEmail:
    """Perform deterministic parsing of an .eml payload.

    Delegates to sub-modules for headers, body, URLs, and attachments.
    Ensures safe handling of untrusted input.
    """
    msg: Message = email.message_from_bytes(raw_bytes, policy=policy.default)

    # 1. Extract all headers
    headers = [
        EmailHeader(name=name, value=str(value))
        for name, value in msg.items()
    ]

    # 2. Extract bodies
    plain_body, html_body = extract_bodies(msg)
    html_body = sanitize_html(html_body) if html_body else None

    # 3. Extract indicators from bodies
    header_text = "\n".join(header.value for header in headers)
    combined_text = (plain_body or "") + "\n" + strip_html(html_body or "") + "\n" + header_text
    urls = extract_urls(combined_text)

    indicators = []
    for url in urls:
        indicators.append(Indicator(type="URL", raw_value=url, normalized_value=url))

    seen_values = {indicator.normalized_value for indicator in indicators}
    for value in _IP_RE.findall(combined_text):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        if value not in seen_values:
            indicators.append(
                Indicator(type="IP", raw_value=value, normalized_value=value, is_private=_is_private_ip(value))
            )
            seen_values.add(value)
    for value in _IPV6_RE.findall(combined_text):
        try:
            ipaddress.ip_address(value)
        except ValueError:
            continue
        if value not in seen_values:
            indicators.append(Indicator(type="IP", raw_value=value, normalized_value=value,
                                        is_private=_is_private_ip(value)))
            seen_values.add(value)
    for value in _DOMAIN_RE.findall(combined_text):
        normalized = value.lower().rstrip(".")
        if normalized not in seen_values and normalized != "localhost":
            indicators.append(Indicator(type="DOMAIN", raw_value=value, normalized_value=normalized))
            seen_values.add(normalized)

    # 4. Extract attachments
    attachments = extract_attachments(msg)
    for att in attachments:
        indicators.append(Indicator(
            type="HASH",
            raw_value=att.filename,
            normalized_value=att.sha256
        ))

    # 5. Parse structured header data
    hops = parse_received_hops(headers)
    auth_results = []
    auth_header = get_header(headers, "Authentication-Results")
    if auth_header:
        auth_results = parse_authentication_results(auth_header)

    # 6. Build final result
    return ParsedEmail(
        from_addr=first_address(get_header(headers, "From") or ""),
        to_addrs=extract_addresses(get_header(headers, "To") or ""),
        cc_addrs=extract_addresses(get_header(headers, "Cc") or ""),
        reply_to=first_address(get_header(headers, "Reply-To") or ""),
        return_path=first_address(get_header(headers, "Return-Path") or ""),
        subject=get_header(headers, "Subject"),
        date=get_header(headers, "Date"),
        message_id=get_header(headers, "Message-ID"),
        headers=headers,
        plain_body=plain_body,
        html_body=html_body,
        attachments=attachments,
        indicators=indicators,
        auth_results=auth_results,
        hops=hops,
    )
