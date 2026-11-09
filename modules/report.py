"""
Stage 8: Report Generation
Prints a color-coded terminal report (risk gauge, findings grouped
by severity, per-module score breakdown, and a complete IOC list),
with an option to save the full report as .txt or .json.
"""

import json
import os
import datetime

RESET = "\033[0m"
BOLD = "\033[1m"
COLORS = {
    "CRITICAL": "\033[41m\033[97m",  # white on red
    "HIGH": "\033[91m",              # red
    "MEDIUM": "\033[93m",            # yellow
    "LOW": "\033[94m",               # blue
    "INFO": "\033[90m",              # grey
}
LABEL_COLORS = {
    "Critical": "\033[41m\033[97m",
    "High": "\033[91m",
    "Medium": "\033[93m",
    "Low": "\033[94m",
    "Clean": "\033[92m",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def print_terminal_report(result):
    c = lambda s, code: f"{code}{s}{RESET}"

    print()
    print(BOLD + "=" * 60 + RESET)
    print(BOLD + f"  ShadowLens XDR — Forensic Report" + RESET)
    print(BOLD + "=" * 60 + RESET)
    print(f"  File:        {result['file_path']}")
    print(f"  Type:        {result['file_type']}")
    print(f"  Size:        {result['file_size']} bytes")
    print(f"  SHA-256:     {result['sha256']}")
    print(f"  Scanned at:  {result['scanned_at']}")
    print()

    score = result["risk"]["score"]
    label = result["risk"]["label"]
    label_color = LABEL_COLORS.get(label, "")
    gauge_len = 40
    filled = int(gauge_len * score / 100)
    gauge = "#" * filled + "-" * (gauge_len - filled)
    print(f"  Risk Score:  {c(score, label_color)}/100   Verdict: {c(label.upper(), label_color)}")
    print(f"  [{gauge}]")
    print()

    print(BOLD + "-- Findings by severity " + "-" * 35 + RESET)
    findings = result["all_findings"]
    if not findings:
        print("  No findings.")
    else:
        for sev in SEVERITY_ORDER:
            group = [f for f in findings if f.get("severity", "INFO").upper() == sev]
            if not group:
                continue
            color = COLORS.get(sev, "")
            for f in group:
                print(f"  {c('[' + sev + ']', color):<22} {f['title']}")
                if f.get("detail"):
                    print(f"      {f['detail']}")
    print()

    print(BOLD + "-- Per-module score contribution " + "-" * 25 + RESET)
    for mod, contrib in sorted(result["risk"]["per_module_contribution"].items(),
                                key=lambda kv: -kv[1]):
        print(f"  {mod:<18} {contrib}")
    print()

    print(BOLD + "-- Indicators of Compromise (IOCs) " + "-" * 24 + RESET)
    iocs = result["iocs"]
    print(f"  URLs   ({len(iocs['urls'])}): " + (", ".join(iocs["urls"]) or "none"))
    print(f"  IPs    ({len(iocs['ips'])}): " + (", ".join(iocs["ips"]) or "none"))
    print(f"  Emails ({len(iocs['emails'])}): " + (", ".join(iocs["emails"]) or "none"))
    print()

    if label in ("High", "Critical"):
        print(c(f"  VERDICT: Do not open/execute this file. "
                f"Handle only in an isolated environment.", LABEL_COLORS[label]))
    elif label == "Clean":
        print(c("  VERDICT: No significant threat indicators found.", LABEL_COLORS[label]))
    else:
        print(c(f"  VERDICT: {label} risk — review findings above before proceeding.",
                 LABEL_COLORS.get(label, "")))
    print(BOLD + "=" * 60 + RESET)
    print()


def save_report(result, out_dir, fmt="json"):
    os.makedirs(out_dir, exist_ok=True)
    base_name = os.path.splitext(os.path.basename(result["file_path"]))[0]
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        out_path = os.path.join(out_dir, f"{base_name}_{timestamp}.json")
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2, default=str)
    else:
        out_path = os.path.join(out_dir, f"{base_name}_{timestamp}.txt")
        with open(out_path, "w") as f:
            f.write(f"ShadowLens XDR Report\n")
            f.write(f"File: {result['file_path']}\n")
            f.write(f"Type: {result['file_type']}\n")
            f.write(f"SHA-256: {result['sha256']}\n")
            f.write(f"Risk score: {result['risk']['score']}/100 ({result['risk']['label']})\n\n")
            f.write("Findings:\n")
            for finding in result["all_findings"]:
                f.write(f"  [{finding.get('severity')}] {finding.get('title')}\n")
                if finding.get("detail"):
                    f.write(f"      {finding.get('detail')}\n")
            f.write("\nIOCs:\n")
            f.write(f"  URLs: {', '.join(result['iocs']['urls'])}\n")
            f.write(f"  IPs: {', '.join(result['iocs']['ips'])}\n")
            f.write(f"  Emails: {', '.join(result['iocs']['emails'])}\n")

    return out_path
