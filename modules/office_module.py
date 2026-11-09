"""
Stage 3: Office Module
Checks OOXML files (docx/xlsx/pptx) for VBA macros, DDE injection,
and suspicious external relationships.
"""

import zipfile
import re

DDE_PATTERNS = [rb"DDEAUTO", rb"DDE\s", rb"\\x13DDE"]


def run_office_module(file_path):
    findings = []
    macro_found = False
    external_rels = []

    try:
        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()

            if any(n.lower().endswith("vbaproject.bin") for n in names):
                macro_found = True
                findings.append({
                    "module": "office",
                    "severity": "HIGH",
                    "title": "VBA macro project present",
                    "detail": "vbaProject.bin found inside the document package.",
                })

            for n in names:
                if n.endswith(".xml") or n.endswith(".rels"):
                    try:
                        content = z.read(n)
                    except Exception:
                        continue
                    for pattern in DDE_PATTERNS:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                "module": "office",
                                "severity": "HIGH",
                                "title": "Possible DDE injection field code",
                                "detail": f"DDE pattern found in {n}",
                            })
                            break
                    if n.endswith(".rels") and b"TargetMode=\"External\"" in content:
                        urls = re.findall(rb'Target="([^"]+)"\s+TargetMode="External"', content)
                        for u in urls:
                            external_rels.append(u.decode(errors="ignore"))

            if external_rels:
                findings.append({
                    "module": "office",
                    "severity": "MEDIUM",
                    "title": f"{len(external_rels)} external relationship(s) found",
                    "detail": ", ".join(external_rels[:5]),
                })

    except Exception as e:
        findings.append({
            "module": "office",
            "severity": "INFO",
            "title": "Could not fully parse OOXML package",
            "detail": str(e),
        })

    return {
        "macro_found": macro_found,
        "external_relationships": external_rels,
        "findings": findings,
    }
