"""
Stage 3: Image Module
Checks for data hidden after the image's end marker and basic
steganography indicators.
"""

from .entropy import shannon_entropy

JPEG_EOI = b"\xff\xd9"
PNG_IEND = b"IEND\xae\x42\x60\x82"


def run_image_module(data):
    findings = []
    trailing = b""

    if data.startswith(b"\xff\xd8\xff"):
        idx = data.rfind(JPEG_EOI)
        if idx != -1 and idx + 2 < len(data):
            trailing = data[idx + 2:]
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        idx = data.rfind(PNG_IEND)
        if idx != -1 and idx + len(PNG_IEND) < len(data):
            trailing = data[idx + len(PNG_IEND):]

    if trailing and len(trailing) > 16:
        ent = shannon_entropy(trailing)
        severity = "HIGH" if ent >= 7.0 else "MEDIUM"
        findings.append({
            "module": "image",
            "severity": severity,
            "title": f"{len(trailing)} byte(s) found appended after the image end marker",
            "detail": f"Trailing-data entropy: {round(ent, 2)} bits/byte. "
                      f"This can indicate an embedded payload (steganography-style hiding).",
        })

    return {"trailing_bytes": len(trailing), "findings": findings}
