"""
Stage 2 (Universal): String Extraction Module
Pulls every readable ASCII/Unicode string out of the raw bytes, then
parses those strings for URLs, IP addresses, email addresses, and
known threat-related keywords.
"""

import re

MIN_STRING_LEN = 4

ASCII_STRING_RE = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING_LEN)
UTF16_STRING_RE = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING_LEN)

URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>\\]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

THREAT_KEYWORDS = [
    "ncat", "netcat", "wget", "curl", "c2", "powershell", "mimikatz",
    "reverse shell", "bind shell", "shellcode", "meterpreter",
    "cmd.exe", "/bin/sh", "/bin/bash", "base64 -d", "iex(",
    "invoke-expression", "certutil -urlcache", "rundll32",
]


def extract_strings(data):
    ascii_strings = [m.group().decode("latin-1") for m in ASCII_STRING_RE.finditer(data)]
    utf16_strings = [
        m.group().decode("utf-16-le", errors="ignore")
        for m in UTF16_STRING_RE.finditer(data)
    ]
    return ascii_strings + utf16_strings


def run_string_module(data):
    findings = []
    strings = extract_strings(data)
    blob = "\n".join(strings)

    urls = sorted(set(URL_RE.findall(blob)))
    ips = sorted(set(IP_RE.findall(blob)))
    emails = sorted(set(EMAIL_RE.findall(blob)))

    hits = []
    lower_blob = blob.lower()
    for kw in THREAT_KEYWORDS:
        if kw in lower_blob:
            hits.append(kw)

    if hits:
        severity = "CRITICAL" if len(hits) >= 3 else ("HIGH" if len(hits) >= 2 else "MEDIUM")
        findings.append({
            "module": "strings",
            "severity": severity,
            "title": f"{len(hits)} threat-related keyword(s) found in extracted strings",
            "detail": ", ".join(hits),
        })

    if urls:
        findings.append({
            "module": "strings",
            "severity": "INFO",
            "title": f"{len(urls)} URL(s) extracted",
            "detail": ", ".join(urls[:10]) + (" ..." if len(urls) > 10 else ""),
        })

    return {
        "strings_count": len(strings),
        "urls": urls,
        "ips": ips,
        "emails": emails,
        "keyword_hits": hits,
        "findings": findings,
    }
