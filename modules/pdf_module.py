"""
Stage 3: PDF Module
Looks for dangerous objects: JavaScript, OpenAction, embedded files, launch actions.
"""

import re

DANGEROUS_KEYS = {
    rb"/JavaScript": ("Embedded JavaScript object", 22),
    rb"/JS": ("Embedded JavaScript object", 22),
    rb"/OpenAction": ("Auto-run OpenAction trigger", 20),
    rb"/Launch": ("Launch action (can run external programs)", 30),
    rb"/EmbeddedFile": ("Embedded file object", 25),
    rb"/AA": ("Additional-Actions auto-trigger", 18),
    rb"/RichMedia": ("Embedded rich media (e.g. Flash)", 15),
}

COLOR_FILTER_RE = re.compile(rb"/Colors\s*\d+")


def run_pdf_module(data):
    findings = []
    for key, (title, weight) in DANGEROUS_KEYS.items():
        count = len(re.findall(re.escape(key), data))
        if count:
            severity = "HIGH" if weight >= 25 else "MEDIUM"
            findings.append({
                "module": "pdf",
                "severity": severity,
                "title": title,
                "detail": f"Found {count} occurrence(s) of {key.decode()}",
                "weight": weight,
            })

    color_filters = len(COLOR_FILTER_RE.findall(data))

    return {
        "dangerous_object_count": sum(1 for f in findings),
        "color_filter_objects": color_filters,
        "findings": findings,
    }
