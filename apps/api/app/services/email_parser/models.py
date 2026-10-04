"""Pydantic models for email parsing output."""

from typing import Optional
from pydantic import BaseModel, Field


class EmailHeader(BaseModel):
    name: str
    value: str


class Attachment(BaseModel):
    filename: str
    mime_type: str
    size: int
    sha256: str
    extension: Optional[str] = None
    is_suspicious: bool = False
    magic_bytes: Optional[str] = None


class Indicator(BaseModel):
    type: str  # IP, DOMAIN, URL, EMAIL, HASH, ATTACHMENT
    raw_value: str
    normalized_value: str
    is_private: bool = False


class AuthenticationResult(BaseModel):
    protocol: str  # SPF, DKIM, DMARC
    result: str    # pass, fail, neutral, none, softfail
    details: dict = Field(default_factory=dict)


class ReceivedHop(BaseModel):
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: Optional[str] = None


class ParsedEmail(BaseModel):
    """Result of deterministic email parsing."""
    from_addr: Optional[str] = None
    to_addrs: list[str] = Field(default_factory=list)
    cc_addrs: list[str] = Field(default_factory=list)
    reply_to: Optional[str] = None
    return_path: Optional[str] = None
    subject: Optional[str] = None
    date: Optional[str] = None
    message_id: Optional[str] = None
    headers: list[EmailHeader] = Field(default_factory=list)
    plain_body: Optional[str] = None
    html_body: Optional[str] = None
    attachments: list[Attachment] = Field(default_factory=list)
    indicators: list[Indicator] = Field(default_factory=list)
    auth_results: list[AuthenticationResult] = Field(default_factory=list)
    hops: list[ReceivedHop] = Field(default_factory=list)
