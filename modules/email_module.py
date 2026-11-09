"""
Stage 3: Email Module
Parses .eml files, checks SPF/DKIM/DMARC authentication-results
headers, and flags sender/display-name spoofing patterns.
"""

import email
import re

SPOOF_DISPLAY_RE = re.compile(r'"?([^"<]+)"?\s*<([^>]+)>')


def run_email_module(file_path):
    findings = []
    headers = {}

    try:
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f)
    except Exception as e:
        return {"findings": [{
            "module": "email", "severity": "INFO",
            "title": "Could not parse as an email message", "detail": str(e),
        }]}

    for h in ("From", "To", "Subject", "Return-Path", "Reply-To",
              "Authentication-Results", "Received-SPF"):
        if msg.get(h):
            headers[h] = msg.get(h)

    auth = (msg.get("Authentication-Results") or "") + " " + (msg.get("Received-SPF") or "")
    auth_lower = auth.lower()

    if auth:
        if "spf=fail" in auth_lower or "spf=softfail" in auth_lower:
            findings.append({
                "module": "email", "severity": "HIGH",
                "title": "SPF authentication failed",
                "detail": "Sender's SPF check did not pass — spoofing indicator.",
            })
        if "dkim=fail" in auth_lower:
            findings.append({
                "module": "email", "severity": "HIGH",
                "title": "DKIM signature failed",
                "detail": "Message signature did not validate.",
            })
        if "dmarc=fail" in auth_lower:
            findings.append({
                "module": "email", "severity": "HIGH",
                "title": "DMARC check failed",
                "detail": "Message failed domain alignment policy.",
            })
    else:
        findings.append({
            "module": "email", "severity": "LOW",
            "title": "No authentication-results header present",
            "detail": "Could not verify SPF/DKIM/DMARC status from available headers.",
        })

    from_header = msg.get("From", "")
    reply_to = msg.get("Reply-To", "")
    match = SPOOF_DISPLAY_RE.search(from_header)
    if match and reply_to and reply_to.strip() and reply_to.strip() not in from_header:
        findings.append({
            "module": "email", "severity": "MEDIUM",
            "title": "Reply-To differs from From address",
            "detail": f"From: {from_header} | Reply-To: {reply_to}",
        })

    return {"headers": headers, "findings": findings}
