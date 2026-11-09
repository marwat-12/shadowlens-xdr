"""
Stage 2 (Universal): Metadata Module
Extracts author/software/date metadata and flags anomalies such as
future-dated timestamps or known malicious-tool signatures.
"""

import subprocess
import json
import datetime
import shutil

SUSPICIOUS_SOFTWARE_HINTS = [
    "cobalt strike", "metasploit", "empire", "msfvenom",
    "havoc", "sliver", "brute ratel",
]


def run_metadata_module(file_path):
    findings = []
    fields = {}

    exiftool_path = shutil.which("exiftool")
    if exiftool_path:
        try:
            out = subprocess.run(
                [exiftool_path, "-j", "-a", "-G", file_path],
                capture_output=True, text=True, timeout=20,
            )
            if out.returncode == 0 and out.stdout.strip():
                data = json.loads(out.stdout)
                if data:
                    fields = data[0]
        except Exception:
            pass
    else:
        findings.append({
            "module": "metadata",
            "severity": "INFO",
            "title": "exiftool not installed",
            "detail": "Install libimage-exiftool-perl for full metadata extraction.",
        })

    # Anomaly: future-dated timestamps
    now = datetime.datetime.now()
    for key, value in fields.items():
        if "Date" in key and isinstance(value, str):
            parsed = _try_parse_date(value)
            if parsed and parsed > now + datetime.timedelta(days=1):
                findings.append({
                    "module": "metadata",
                    "severity": "MEDIUM",
                    "title": f"Future-dated timestamp in {key}",
                    "detail": f"{key} = {value}",
                })

    # Anomaly: known malicious-tool signatures in Software/Producer/Creator fields
    for key in ("Software", "Producer", "Creator", "CreatorTool", "Application"):
        value = str(fields.get(key, "")).lower()
        for hint in SUSPICIOUS_SOFTWARE_HINTS:
            if hint in value:
                findings.append({
                    "module": "metadata",
                    "severity": "HIGH",
                    "title": f"Suspicious authoring tool signature in {key}",
                    "detail": f"{key} = {fields.get(key)}",
                })

    return {"fields": fields, "findings": findings}


def _try_parse_date(value):
    fmts = [
        "%Y:%m:%d %H:%M:%S", "%Y:%m:%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S",
    ]
    cleaned = value.strip()
    for fmt in fmts:
        try:
            return datetime.datetime.strptime(cleaned[:len(fmt.replace("%z", "+0000"))], fmt)
        except Exception:
            continue
    return None
