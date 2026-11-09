#!/usr/bin/env bash
# ShadowLens XDR - installer
# Installs optional system dependency (exiftool) for full metadata
# extraction. The tool runs fine without it, with reduced metadata.

set -e

echo "=== ShadowLens XDR installer ==="

PYTHON_BIN=$(command -v python3 || true)
if [ -z "$PYTHON_BIN" ]; then
    echo "[!] python3 not found. Please install Python 3.8+ first."
    exit 1
fi
echo "[+] Found python3: $($PYTHON_BIN --version)"

if command -v exiftool >/dev/null 2>&1; then
    echo "[+] exiftool already installed."
else
    echo "[*] exiftool not found. Attempting install..."
    if command -v apt-get >/dev/null 2>&1; then
        sudo apt-get update && sudo apt-get install -y libimage-exiftool-perl
    elif command -v brew >/dev/null 2>&1; then
        brew install exiftool
    elif command -v yum >/dev/null 2>&1; then
        sudo yum install -y perl-Image-ExifTool
    else
        echo "[!] Could not detect a supported package manager."
        echo "    Please install 'exiftool' manually for full metadata extraction."
    fi
fi

mkdir -p reports
chmod +x shadowlens.py

echo "[+] Setup complete."
echo "Run it with:"
echo "    python3 shadowlens.py <path-to-file>"
