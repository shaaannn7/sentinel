"""SPF, DKIM, DMARC and sender alignment analysis."""

from email.utils import parseaddr
from app.services.email_parser.models import ParsedEmail
from app.services.analysis.models import AnalyzerResult, EvidenceItem, FindingDraft
from app.services.analysis.evidence import evidence

VALID = {"PASS", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "TEMPERROR", "PERMERROR", "UNKNOWN"}
FAILURE_POINTS = {"FAIL": 10, "PERMERROR": 8, "SOFTFAIL": 6, "TEMPERROR": 4}


def _domain(address: str | None) -> str | None:
    value = parseaddr(address or "")[1]
    return value.rsplit("@", 1)[1].lower().rstrip(".") if "@" in value else None


def analyze(parsed: ParsedEmail) -> AnalyzerResult:
    result = AnalyzerResult(stage="AUTHENTICATION_ANALYSIS")
    observed: dict[str, dict] = {protocol: {"result": "NOT_OBSERVED"} for protocol in ("SPF", "DKIM", "DMARC")}
    for auth in parsed.auth_results:
        protocol = auth.protocol.upper()
        state = auth.result.upper().replace("SOFTFAIL", "SOFTFAIL")
        if protocol not in {"SPF", "DKIM", "DMARC"}:
            continue
        state = state if state in VALID else "UNKNOWN"
        details = auth.details or {}
        ev = evidence(EvidenceItem("AUTHENTICATION", "Authentication-Results", f"{protocol}={state.lower()}",
                                   f"{protocol} authentication result observed as {state}.", details))
        result.evidence.append(ev)
        observed[protocol] = {"result": state, **details}
        if state in FAILURE_POINTS:
            points = FAILURE_POINTS[state] + (5 if protocol == "DMARC" and state == "FAIL" else 0)
            severity = "HIGH" if protocol == "DMARC" and state == "FAIL" else "MEDIUM"
            label = "failed" if state == "FAIL" else state.lower()
            result.findings.append(FindingDraft(severity, "AUTHENTICATION", f"{protocol} authentication {label}",
                f"The message's observed {protocol} authentication result was {state}.",
                [ev], "authentication", points))
    for protocol in ("SPF", "DKIM", "DMARC"):
        if observed[protocol]["result"] == "NOT_OBSERVED":
            result.warnings.append(f"{protocol} result not observed")

    from_domain = _domain(parsed.from_addr)
    return_domain = _domain(parsed.return_path)
    dkim_domain = (observed.get("DKIM", {}).get("d")
                   or observed.get("DKIM", {}).get("header.d")
                   or observed.get("DKIM", {}).get("domain"))
    spf_identity = observed.get("SPF", {}).get("smtp.mailfrom") or observed.get("SPF", {}).get("smtp.helo")
    sending_ip = observed.get("SPF", {}).get("client-ip")
    alignment = {}
    if from_domain and return_domain:
        alignment["return_path"] = from_domain == return_domain
        ev_from = evidence(EvidenceItem("AUTHENTICATION", "From", from_domain, f"Displayed From domain: {from_domain}."))
        ev_return = evidence(EvidenceItem("AUTHENTICATION", "Return-Path", return_domain, f"Return-Path domain: {return_domain}."))
        result.evidence.extend([ev_from, ev_return])
        if from_domain != return_domain:
            result.findings.append(FindingDraft("MEDIUM", "SENDER", "Sender domain alignment mismatch",
                "The observed Return-Path domain differs from the displayed From domain; this can be legitimate but warrants review.",
                [ev_from, ev_return], "authentication", 10))
    reply_domain = _domain(parsed.reply_to)
    if from_domain and reply_domain and from_domain != reply_domain:
        ev_from = evidence(EvidenceItem("AUTHENTICATION", "From", from_domain, f"Displayed From domain: {from_domain}."))
        ev_reply = evidence(EvidenceItem("AUTHENTICATION", "Reply-To", reply_domain, f"Reply-To domain: {reply_domain}."))
        result.evidence.extend([ev_from, ev_reply])
        result.findings.append(FindingDraft("MEDIUM", "SENDER", "Reply-To domain mismatch",
            "The observed Reply-To domain differs from the displayed From domain; this can be legitimate but warrants review.",
            [ev_from, ev_reply], "authentication", 10))
    if from_domain and dkim_domain:
        alignment["dkim"] = from_domain == str(dkim_domain).lower().rstrip(".")
    result.data = {"observed": observed, "from_domain": from_domain, "return_path_domain": return_domain,
                   "reply_to_domain": reply_domain,
                   "dkim_domain": dkim_domain, "spf_identity": spf_identity,
                   "sending_ip": sending_ip, "alignment": alignment}
    return result
