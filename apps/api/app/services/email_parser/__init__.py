"""Email parser package."""

from app.services.email_parser.parser import parse_email
from app.services.email_parser.models import ParsedEmail

__all__ = ["parse_email", "ParsedEmail"]
