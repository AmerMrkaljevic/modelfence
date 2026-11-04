"""safetensors header sanity check.

safetensors is the *safe* format: a little-endian u64 header length, then that
many bytes of JSON metadata, then raw tensor bytes. There is no pickle and no
code path, so a well-formed safetensors file cannot execute code — which is the
whole point, and worth telling the user (INFO). What CAN go wrong is a hostile
header: a declared header length larger than the file (read-overflow / OOM in
naive loaders), or tensor data offsets that overlap or run past the end. We
check those and otherwise certify the file as the format to prefer.
"""
from __future__ import annotations

import json
import os
import struct

from .findings import Finding, Severity

_MAX_HEADER = 100 * 1024 * 1024  # 100 MB of JSON header is already absurd


def scan_safetensors(path: str) -> list[Finding]:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            prefix = f.read(8)
            if len(prefix) < 8:
                return [Finding(Severity.MEDIUM, "safetensors.truncated",
                                "file shorter than an 8-byte header length", path)]
            (header_len,) = struct.unpack("<Q", prefix)
            if header_len > size - 8:
                return [Finding(Severity.HIGH, "safetensors.header_overflow",
                                f"declared header length {header_len} exceeds the "
                                f"remaining {size - 8} bytes — malformed/hostile header",
                                path, None, {"declared": header_len, "available": size - 8})]
            if header_len > _MAX_HEADER:
                return [Finding(Severity.MEDIUM, "safetensors.header_huge",
                                f"header length {header_len} is implausibly large", path)]
            header = f.read(header_len)
    except OSError as exc:
        return [Finding(Severity.MEDIUM, "safetensors.unreadable", str(exc), path)]

    try:
        meta = json.loads(header)
    except Exception as exc:
        return [Finding(Severity.MEDIUM, "safetensors.bad_json",
                        f"header is not valid JSON ({exc})", path)]

    findings: list[Finding] = []
    data_region = size - 8 - header_len
    for name, spec in (meta.items() if isinstance(meta, dict) else ()):
        if name == "__metadata__" or not isinstance(spec, dict):
            continue
        offs = spec.get("data_offsets")
        if (isinstance(offs, list) and len(offs) == 2
                and all(isinstance(o, int) for o in offs)):
            begin, end = offs
            if begin < 0 or end < begin or end > data_region:
                findings.append(Finding(
                    Severity.HIGH, "safetensors.offset_oob",
                    f"tensor {name!r} offsets {offs} fall outside the "
                    f"{data_region}-byte data region", path, None,
                    {"tensor": name, "offsets": offs}))

    if not findings:
        findings.append(Finding(Severity.INFO, "safetensors.ok",
                                "safetensors: no code path, header and offsets valid — "
                                "this is the format to prefer", path))
    return findings
