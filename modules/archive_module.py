"""
Stage 3: Archive Module
Checks for password protection, path traversal filenames, and
zip-bomb style extreme compression ratios.
"""

import zipfile
import os

ZIP_BOMB_RATIO_THRESHOLD = 100  # uncompressed/compressed


def run_archive_module(file_path):
    findings = []
    entries = []
    password_protected = False
    traversal_names = []
    max_ratio = 0

    try:
        with zipfile.ZipFile(file_path) as z:
            for info in z.infolist():
                entries.append(info.filename)

                if info.flag_bits & 0x1:
                    password_protected = True

                norm = os.path.normpath(info.filename)
                if norm.startswith("..") or os.path.isabs(info.filename):
                    traversal_names.append(info.filename)

                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    max_ratio = max(max_ratio, ratio)

    except zipfile.BadZipFile:
        findings.append({
            "module": "archive",
            "severity": "INFO",
            "title": "Not a standard ZIP archive (or uses RAR/7Z format)",
            "detail": "Only ZIP-based archives are inspected in detail by this module.",
        })
        return {"entries": [], "findings": findings}
    except Exception as e:
        findings.append({
            "module": "archive",
            "severity": "INFO",
            "title": "Could not open archive",
            "detail": str(e),
        })
        return {"entries": [], "findings": findings}

    if password_protected:
        findings.append({
            "module": "archive",
            "severity": "MEDIUM",
            "title": "Archive is password-protected",
            "detail": "Password-protected archives are commonly used to evade "
                      "antivirus scanning of the contained payload.",
        })

    if traversal_names:
        findings.append({
            "module": "archive",
            "severity": "CRITICAL",
            "title": "Path-traversal filename(s) detected",
            "detail": ", ".join(traversal_names[:5]),
        })

    if max_ratio >= ZIP_BOMB_RATIO_THRESHOLD:
        findings.append({
            "module": "archive",
            "severity": "HIGH",
            "title": "Extreme compression ratio detected (possible zip bomb)",
            "detail": f"Max observed ratio: {round(max_ratio, 1)}:1",
        })

    return {
        "entries": entries,
        "password_protected": password_protected,
        "findings": findings,
    }
