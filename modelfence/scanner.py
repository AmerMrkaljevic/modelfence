"""Format detection and dispatch.

Detection is by magic bytes first, extension second — a file named `model.bin`
can be a raw pickle, a torch zip, a GGUF, or a safetensors, and the magic tells
us which. Anything we can open as a zip is treated as a zip model (torch .pt,
numpy .npz, keras .keras all are zips). A bare pickle is scanned directly.
"""
from __future__ import annotations

import os
import struct
import zipfile

from .findings import Finding, Severity
from .pickle_scan import scan_pickle_bytes
from .zip_scan import scan_zip
from .gguf_scan import scan_gguf
from .safetensors_scan import scan_safetensors

_PICKLE_EXT = {".pkl", ".pickle"}
_ZIP_EXT = {".pt", ".pth", ".ckpt", ".zip", ".npz", ".keras", ".model"}
_GGUF_EXT = {".gguf"}
_ST_EXT = {".safetensors"}
_SKIP_EXT = {".h5", ".hdf5", ".onnx", ".json", ".txt", ".md", ".bin"}  # bin re-sniffed below

MODEL_EXT = _PICKLE_EXT | _ZIP_EXT | _GGUF_EXT | _ST_EXT | {".bin", ".pb"}


def _sniff(path: str) -> str:
    """Return a format tag from magic bytes; '' if undetermined."""
    try:
        with open(path, "rb") as f:
            head = f.read(8)
    except OSError:
        return ""
    if head[:4] == b"PK\x03\x04":
        return "zip"
    if head[:4] == b"GGUF":
        return "gguf"
    if head[:2] == b"\x80" and len(head) >= 2 and head[1] in range(0, 6):
        return "pickle"           # PROTO opcode + protocol number 0..5
    # safetensors has no magic; a plausible u64 header length that fits the file
    # and begins a JSON object ('{') is the tell.
    try:
        size = os.path.getsize(path)
        if size >= 9:
            (hlen,) = struct.unpack("<Q", head)
            if 2 <= hlen <= size - 8:
                with open(path, "rb") as f:
                    f.seek(8)
                    if f.read(1) == b"{":
                        return "safetensors"
    except (OSError, struct.error):
        pass
    return ""


def scan_file(path: str) -> list[Finding]:
    tag = _sniff(path)
    ext = os.path.splitext(path)[1].lower()

    if tag == "zip" or (tag == "" and ext in _ZIP_EXT and zipfile.is_zipfile(path)):
        return scan_zip(path)
    if tag == "gguf" or (tag == "" and ext in _GGUF_EXT):
        return scan_gguf(path)
    if tag == "safetensors" or (tag == "" and ext in _ST_EXT):
        return scan_safetensors(path)
    if tag == "pickle" or ext in _PICKLE_EXT:
        try:
            with open(path, "rb") as f:
                return scan_pickle_bytes(f.read(), path)
        except OSError as exc:
            return [Finding(Severity.MEDIUM, "io.unreadable", str(exc), path)]

    # a .bin / unknown with no magic: best-effort pickle sniff, else skip
    if ext in (".bin", ".model", ""):
        try:
            with open(path, "rb") as f:
                raw = f.read()
            if raw[:1] == b"\x80":
                return scan_pickle_bytes(raw, path)
        except OSError:
            pass
    return [Finding(Severity.INFO, "scan.skipped",
                    f"unrecognized format for {ext or 'extensionless file'}; not a "
                    f"known model container", path)]


def scan_path(target: str) -> list[Finding]:
    """Scan a file or walk a directory, returning all findings."""
    if os.path.isfile(target):
        return scan_file(target)
    findings: list[Finding] = []
    for root, _dirs, files in os.walk(target):
        for name in files:
            if os.path.splitext(name)[1].lower() in MODEL_EXT:
                findings.extend(scan_file(os.path.join(root, name)))
    return findings
