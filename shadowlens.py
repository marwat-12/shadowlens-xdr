#!/usr/bin/env python3
"""
ShadowLens XDR
A lightweight, modular forensic file-analysis / threat-triage tool.

Usage:
    python3 shadowlens.py <file_path> [--save-report] [--format json|txt] [--vt-key KEY] [--no-dns]
"""

import argparse
import hashlib
import datetime
import sys
import os

from modules.filetype import detect_file_type
from modules.metadata import run_metadata_module
from modules.entropy import run_entropy_module
from modules.string_extractor import run_string_module, extract_strings
from modules.pdf_module import run_pdf_module
from modules.office_module import run_office_module
from modules.archive_module import run_archive_module
from modules.image_module import run_image_module
from modules.email_module import run_email_module
from modules.url_reputation import run_url_reputation
from modules.phishing import run_phishing_module
from modules.obfuscation import run_obfuscation_module
from modules.scoring import calculate_risk_score
from modules.report import print_terminal_report, save_report

MAX_READ_BYTES = 50 * 1024 * 1024  # 50 MB safety cap for in-memory analysis


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def analyze(file_path, vt_api_key=None, resolve_dns=True):
    if not os.path.isfile(file_path):
        print(f"[!] File not found: {file_path}")
        sys.exit(1)

    file_size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        data = f.read(MAX_READ_BYTES)

    file_type = detect_file_type(file_path, data[:64])
    digest = sha256_of(file_path)

    all_findings = []

    # --- Universal modules (run on every file) ---
    meta_result = run_metadata_module(file_path)
    all_findings += meta_result["findings"]

    entropy_result = run_entropy_module(data)
    all_findings += entropy_result["findings"]

    string_result = run_string_module(data)
    all_findings += string_result["findings"]

    strings_list = extract_strings(data)
    text_blob = "\n".join(strings_list)

    # --- Format-specific modules ---
    format_result = {}
    if file_type == "PDF":
        format_result = run_pdf_module(data)
        all_findings += format_result["findings"]
    elif file_type in ("DOCX", "XLSX", "PPTX"):
        format_result = run_office_module(file_path)
        all_findings += format_result["findings"]
    elif file_type in ("ZIP", "RAR", "7Z", "GZIP"):
        format_result = run_archive_module(file_path)
        all_findings += format_result["findings"]
    elif file_type in ("JPEG", "PNG", "GIF", "BMP"):
        format_result = run_image_module(data)
        all_findings += format_result["findings"]
    elif file_type == "EML":
        format_result = run_email_module(file_path)
        all_findings += format_result["findings"]

    # --- URL reputation ---
    url_result = run_url_reputation(string_result["urls"], vt_api_key=vt_api_key,
                                     resolve_dns=resolve_dns)
    all_findings += url_result["findings"]

    # --- Phishing / social engineering ---
    phishing_result = run_phishing_module(text_blob)
    all_findings += phishing_result["findings"]

    # --- Obfuscation detection ---
    obfuscation_result = run_obfuscation_module(strings_list)
    all_findings += obfuscation_result["findings"]

    # --- Risk scoring ---
    risk = calculate_risk_score(all_findings)

    result = {
        "file_path": file_path,
        "file_type": file_type,
        "file_size": file_size,
        "sha256": digest,
        "scanned_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "metadata": meta_result["fields"],
        "entropy": {
            "overall": entropy_result["overall_entropy"],
            "high_entropy_regions": entropy_result["regions"],
        },
        "iocs": {
            "urls": string_result["urls"],
            "ips": string_result["ips"],
            "emails": string_result["emails"],
        },
        "format_specific": format_result,
        "url_reputation": url_result["checked"],
        "risk": risk,
        "all_findings": all_findings,
    }
    return result


def main():
    parser = argparse.ArgumentParser(
        prog="shadowlens",
        description="ShadowLens XDR - modular forensic file analysis tool",
    )
    parser.add_argument("file_path", help="Path to the file to analyze")
    parser.add_argument("--save-report", action="store_true",
                         help="Save the full report to the reports/ directory")
    parser.add_argument("--format", choices=["json", "txt"], default="json",
                         help="Report format when --save-report is used (default: json)")
    parser.add_argument("--vt-key", default=None,
                         help="Optional VirusTotal API key for URL reputation lookups")
    parser.add_argument("--no-dns", action="store_true",
                         help="Skip live DNS resolution checks for extracted URLs")
    args = parser.parse_args()

    result = analyze(args.file_path, vt_api_key=args.vt_key, resolve_dns=not args.no_dns)
    print_terminal_report(result)

    if args.save_report:
        reports_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        out_path = save_report(result, reports_dir, fmt=args.format)
        print(f"[+] Report saved to: {out_path}")


if __name__ == "__main__":
    main()
