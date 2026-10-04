"""Email body extraction helpers."""

import re
from html import escape
from html import unescape
from html.parser import HTMLParser
from typing import Optional
from email.message import Message

# Maximum body size to load (5 MB)
_MAX_BODY_SIZE = 5 * 1024 * 1024


def _is_safe_payload(part: Message) -> bool:
    """Return True if part is text/* content type."""
    ctype = part.get_content_type()
    return ctype in ("text/plain", "text/html")


def _decode_part(part: Message) -> str:
    """Decode a text part payload safely."""
    payload = part.get_payload(decode=True)
    if not payload:
        return ""
    if isinstance(payload, bytes):
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, UnicodeDecodeError):
            return payload.decode("utf-8", errors="replace")
    return str(payload)


def extract_bodies(msg: Message) -> tuple[Optional[str], Optional[str]]:
    """Walk the email tree and extract text/plain and text/html bodies.

    Returns (plain_body, html_body). Either may be None if absent.
    """
    plain: Optional[str] = None
    html: Optional[str] = None

    if msg.is_multipart():
        part_count = 0
        for part in msg.walk():
            part_count += 1
            if part_count > 500:
                break
            if part.is_multipart():
                continue
            if not _is_safe_payload(part):
                continue
            content = _decode_part(part)
            if len(content.encode("utf-8", errors="ignore")) > _MAX_BODY_SIZE:
                content = content[: _MAX_BODY_SIZE]
            ctype = part.get_content_type()
            if ctype == "text/plain":
                plain = content
            elif ctype == "text/html":
                html = content
    else:
        if _is_safe_payload(msg):
            content = _decode_part(msg)
            if len(content.encode("utf-8", errors="ignore")) > _MAX_BODY_SIZE:
                content = content[: _MAX_BODY_SIZE]
            ctype = msg.get_content_type()
            if ctype == "text/plain":
                plain = content
            elif ctype == "text/html":
                html = content

    return plain, html


def strip_html(html: str) -> str:
    """Lightweight HTML-to-text conversion for analysis (not for display)."""
    if not html:
        return ""
    # Remove script/style blocks
    cleaned = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", html, flags=re.DOTALL | re.IGNORECASE)
    # Remove tags
    cleaned = re.sub(r"<[^>]+>", " ", cleaned)
    # Decode HTML entities (minimal)
    cleaned = unescape(cleaned)
    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


class _SafeHTMLParser(HTMLParser):
    _allowed_tags = {
        "a", "b", "br", "code", "div", "em", "i", "li", "ol", "p", "pre",
        "span", "strong", "table", "tbody", "td", "th", "thead", "tr", "ul",
    }
    _void_tags = {"br"}
    _blocked_tags = {"iframe", "object", "embed", "script", "style", "form", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.output: list[str] = []
        self._blocked_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self._blocked_tags:
            self._blocked_depth += 1
            return
        if self._blocked_depth or tag not in self._allowed_tags:
            return
        safe_attrs = []
        for name, value in attrs:
            name = name.lower()
            if name.startswith("on") or name in {"style", "src", "srcdoc"}:
                continue
            if name == "href":
                href = (value or "").strip()
                if not href.lower().startswith(("http://", "https://", "mailto:")):
                    continue
                safe_attrs.append(f' href="{escape(href, quote=True)}"')
            elif name == "title":
                safe_attrs.append(f' title="{escape(value or "", quote=True)}"')
        self.output.append(f"<{tag}{''.join(safe_attrs)}>")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._blocked_tags:
            self._blocked_depth = max(0, self._blocked_depth - 1)
        elif not self._blocked_depth and tag in self._allowed_tags and tag not in self._void_tags:
            self.output.append(f"</{tag}>")

    def handle_data(self, data: str) -> None:
        if not self._blocked_depth:
            self.output.append(escape(data))


def sanitize_html(html: str) -> str:
    """Return a restricted HTML fragment safe for isolated UI rendering."""
    if not html:
        return ""
    parser = _SafeHTMLParser()
    parser.feed(html)
    parser.close()
    return "".join(parser.output)
