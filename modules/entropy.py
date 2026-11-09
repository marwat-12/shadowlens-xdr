"""
Stage 2 (Universal): Entropy Module
Calculates Shannon entropy across the file in chunks, flagging
unusually random-looking regions that may indicate hidden
encrypted or compressed payloads.
"""

import math
from collections import Counter

CHUNK_SIZE = 4096
HIGH_ENTROPY_THRESHOLD = 7.5   # bits/byte, out of a max of 8.0


def shannon_entropy(data):
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def run_entropy_module(data):
    findings = []
    regions = []

    for offset in range(0, len(data), CHUNK_SIZE):
        chunk = data[offset:offset + CHUNK_SIZE]
        if len(chunk) < 256:
            continue
        ent = shannon_entropy(chunk)
        if ent >= HIGH_ENTROPY_THRESHOLD:
            regions.append({"offset": offset, "size": len(chunk), "entropy": round(ent, 2)})

    overall = shannon_entropy(data)

    if regions:
        # Don't let a handful of normal (e.g. compressed-image) high-entropy
        # chunks dominate the score; severity scales with how much of the
        # file is high-entropy.
        ratio = len(regions) * CHUNK_SIZE / max(len(data), 1)
        severity = "LOW"
        if ratio > 0.6:
            severity = "HIGH"
        elif ratio > 0.25:
            severity = "MEDIUM"

        findings.append({
            "module": "entropy",
            "severity": severity,
            "title": f"{len(regions)} high-entropy region(s) detected",
            "detail": f"Overall file entropy: {round(overall, 2)} bits/byte. "
                      f"Example region at offset {regions[0]['offset']} "
                      f"({regions[0]['entropy']} bits/byte).",
        })

    return {"overall_entropy": round(overall, 2), "regions": regions, "findings": findings}
