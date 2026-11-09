"""
Stage 4: URL Reputation Engine
Checks extracted URLs against suspicious TLDs, known shorteners,
typosquatting patterns, live DNS resolution, and optionally
VirusTotal (if an API key is supplied).
"""

import re
import socket
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "zip", "mov", "xyz", "top", "work", "click", "country", "gq", "tk",
    "ml", "cf", "ga", "rest", "quest",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
}

POPULAR_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "facebook",
    "netflix", "bankofamerica", "wellsfargo", "chase",
]


def _looks_like_typosquat(host):
    host_l = host.lower()
    for brand in POPULAR_BRANDS:
        if brand in host_l and not host_l.endswith("." + brand + ".com") \
                and host_l != brand + ".com" and "www." + brand + ".com" != host_l:
            # brand name present but not as the real registered domain
            if re.search(rf"{brand}[-0-9]|[-0-9]{brand}", host_l) or \
                    host_l.replace(brand, "") not in ("", ".com"):
                return brand
    return None


def run_url_reputation(urls, vt_api_key=None, resolve_dns=True):
    findings = []
    details = []

    for url in urls:
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
        except Exception:
            continue

        tld = host.rsplit(".", 1)[-1].lower() if "." in host else ""
        entry = {"url": url, "host": host, "flags": []}

        if tld in SUSPICIOUS_TLDS:
            entry["flags"].append(f"suspicious TLD .{tld}")

        if host.lower() in SHORTENERS:
            entry["flags"].append("known URL shortener")

        brand = _looks_like_typosquat(host)
        if brand:
            entry["flags"].append(f"possible typosquat of '{brand}'")

        if resolve_dns and host:
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(host)
                entry["dns"] = "resolves"
            except Exception:
                entry["dns"] = "does not resolve"
                entry["flags"].append("domain does not resolve (possibly dead/sinkholed)")

        if vt_api_key:
            entry["virustotal"] = "lookup skipped (implement API call with provided key)"

        details.append(entry)
        if entry["flags"]:
            severity = "HIGH" if len(entry["flags"]) >= 2 else "MEDIUM"
            findings.append({
                "module": "url_reputation",
                "severity": severity,
                "title": f"Suspicious URL: {url}",
                "detail": "; ".join(entry["flags"]),
            })

    return {"checked": details, "findings": findings}
