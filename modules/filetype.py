"""
Stage 1: File Ingestion and Type Detection
Identifies true file type from magic bytes, regardless of file extension.
"""

MAGIC_SIGNATURES = [
    (b"%PDF-", "PDF"),
    (b"PK\x03\x04", "ZIP"),           # also covers DOCX/XLSX/PPTX/JAR (OOXML)
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE"),  # legacy DOC/XLS/PPT
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE-EXE"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"From ", "EML"),
]

OOXML_INNER_HINTS = {
    "word/": "DOCX",
    "xl/": "XLSX",
    "ppt/": "PPTX",
}


def detect_file_type(file_path, head_bytes):
    """Return a short type label based on magic bytes, with OOXML sub-typing."""
    for sig, label in MAGIC_SIGNATURES:
        if head_bytes.startswith(sig):
            if label == "ZIP":
                return _refine_ooxml(file_path) or "ZIP"
            return label

    # Fallback: plain-text email headers without leading "From "
    sample = head_bytes[:4000].decode("latin-1", errors="ignore")
    if "Received:" in sample and ("From:" in sample or "Subject:" in sample):
        return "EML"

    return "UNKNOWN"


def _refine_ooxml(file_path):
    import zipfile
    try:
        with zipfile.ZipFile(file_path) as z:
            names = z.namelist()
            for prefix, label in OOXML_INNER_HINTS.items():
                if any(n.startswith(prefix) for n in names):
                    return label
    except Exception:
        pass
    return None
