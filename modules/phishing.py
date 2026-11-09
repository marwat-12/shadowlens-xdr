"""
Stage 5: Phishing and Social Engineering Detection
Scans extracted text for urgency language, brand impersonation,
credential-harvesting phrases, and Unicode homograph characters.
"""

import re

URGENCY_PHRASES = [
    "verify your account immediately", "your account has been suspended",
    "urgent action required", "act now", "confirm your identity",
    "unusual login activity", "your password will expire",
    "click here immediately", "limited time", "final notice",
]

CREDENTIAL_PHRASES = [
    "enter your password", "login to verify", "update your billing",
    "confirm your card details", "ssn", "social security number",
    "one-time passcode", "otp code",
]

# Common Latin lookalike characters used in homograph / IDN spoofing attacks
HOMOGRAPH_CHARS = set("а е о р с у х і ј ѕ ԁ ѵ".split())  # Cyrillic lookalikes


def run_phishing_module(text_blob):
    findings = []
    lower = text_blob.lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in lower]
    cred_hits = [p for p in CREDENTIAL_PHRASES if p in lower]
    homograph_hits = [c for c in HOMOGRAPH_CHARS if c in text_blob]

    if urgency_hits:
        findings.append({
            "module": "phishing",
            "severity": "MEDIUM" if len(urgency_hits) == 1 else "HIGH",
            "title": f"{len(urgency_hits)} urgency/social-engineering phrase(s) found",
            "detail": "; ".join(urgency_hits),
        })

    if cred_hits:
        findings.append({
            "module": "phishing",
            "severity": "HIGH",
            "title": f"{len(cred_hits)} credential-harvesting phrase(s) found",
            "detail": "; ".join(cred_hits),
        })

    if homograph_hits:
        findings.append({
            "module": "phishing",
            "severity": "HIGH",
            "title": "Unicode homograph character(s) detected",
            "detail": "Lookalike characters can disguise spoofed domains/text: "
                      + ", ".join(homograph_hits),
        })

    return {"findings": findings}
