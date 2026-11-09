"""
Stage 6: Obfuscation Detection
Scans extracted strings for Base64/hex-encoded blocks, decodes and
inspects them for embedded executable signatures (e.g. the Windows
"MZ" header), and for PowerShell -EncodedCommand patterns.
"""

import re
import base64
import binascii

BASE64_RE = re.compile(r"(?:[A-Za-z0-9+/]{40,}={0,2})")
HEX_BLOCK_RE = re.compile(r"(?:[0-9A-Fa-f]{2}){20,}")
POWERSHELL_ENCODED_RE = re.compile(
    r"-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{20,})", re.IGNORECASE
)

EXECUTABLE_SIGNATURES = {
    b"MZ": "Windows PE executable (MZ header)",
    b"\x7fELF": "Linux ELF executable",
    b"#!/": "Shebang script header",
}


def _check_decoded_for_executable(decoded_bytes):
    for sig, label in EXECUTABLE_SIGNATURES.items():
        if decoded_bytes.startswith(sig):
            return label
    return None


def run_obfuscation_module(strings_list):
    findings = []
    decoded_hits = []
    ps_hits = []

    blob = "\n".join(strings_list)

    # PowerShell -EncodedCommand (UTF-16LE base64)
    for match in POWERSHELL_ENCODED_RE.finditer(blob):
        candidate = match.group(1)
        try:
            raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4))
            decoded_text = raw.decode("utf-16-le", errors="ignore")
            ps_hits.append(decoded_text[:200])
        except Exception:
            ps_hits.append("(decode failed)")

    if ps_hits:
        findings.append({
            "module": "obfuscation",
            "severity": "CRITICAL",
            "title": f"{len(ps_hits)} PowerShell -EncodedCommand block(s) found",
            "detail": "Decoded preview: " + " | ".join(ps_hits[:2]),
        })

    # Generic Base64 blocks -> check if they decode to an executable
    for match in set(BASE64_RE.findall(blob)):
        try:
            raw = base64.b64decode(match + "=" * (-len(match) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        label = _check_decoded_for_executable(raw)
        if label:
            decoded_hits.append(label)

    if decoded_hits:
        findings.append({
            "module": "obfuscation",
            "severity": "CRITICAL",
            "title": f"Base64-encoded executable payload detected ({len(decoded_hits)})",
            "detail": "; ".join(set(decoded_hits)),
        })

    # Large hex-encoded blocks (shellcode style)
    hex_blocks = HEX_BLOCK_RE.findall(blob)
    long_hex_blocks = [b for b in hex_blocks if len(b) >= 200]
    if long_hex_blocks:
        findings.append({
            "module": "obfuscation",
            "severity": "MEDIUM",
            "title": f"{len(long_hex_blocks)} large hex-encoded block(s) found",
            "detail": "Can indicate shellcode or encoded configuration data.",
        })

    return {"findings": findings}
