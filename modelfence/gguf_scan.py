"""GGUF header sanity check — catches the load-time DoS class.

GGUF files declare, right in the header, a tensor count and a metadata-KV count
as unsigned 64-bit integers. Several loaders trust those counts and allocate /
loop on them before validating against the actual file size — an attacker-set
count of 2**63 turns a model load into an OOM or a multiplication overflow (the
GGUF div-zero / unguarded-index DoS class). We do NOT parse the body (that is
where the crash lives); we only read the fixed header and bound the counts
against the file size, which is enough to flag a hostile header safely.

Header layout (little-endian): magic "GGUF" (4), version u32, tensor_count u64,
metadata_kv_count u64.
"""
from __future__ import annotations

import os
import struct

from .findings import Finding, Severity

_MAGIC = b"GGUF"
# smallest plausible on-disk footprint for one declared tensor or KV entry.
# Even an empty KV needs a length-prefixed key + type tag; a tensor needs a
# name + dims + type + offset. 16 bytes is a deliberate floor, not exact: any
# count that would require more bytes than the file holds is impossible.
_MIN_BYTES_PER_ENTRY = 16


def scan_gguf(path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = f.read(24)
    except OSError as exc:
        return [Finding(Severity.MEDIUM, "gguf.unreadable", str(exc), path)]

    if len(head) < 24 or head[:4] != _MAGIC:
        return [Finding(Severity.MEDIUM, "gguf.bad_magic",
                        "file does not start with a valid GGUF header", path)]

    version, n_tensors, n_kv = struct.unpack("<IQQ", head[4:24])

    if version == 0 or version > 100:
        findings.append(Finding(Severity.MEDIUM, "gguf.bad_version",
                                f"implausible GGUF version {version}", path))

    for label, count, code in (("tensor", n_tensors, "gguf.tensor_count_overflow"),
                               ("metadata-KV", n_kv, "gguf.kv_count_overflow")):
        # a count that cannot physically fit in the remaining bytes is a header
        # lie — the class of input that DoSes count-trusting loaders.
        max_possible = max(0, (size - 24)) // _MIN_BYTES_PER_ENTRY
        if count > max_possible:
            findings.append(Finding(
                Severity.HIGH, code,
                f"declared {label} count {count} cannot fit in a {size}-byte file "
                f"(max ~{max_possible}) — malformed header, loaders that trust this "
                f"count before validating can OOM or index out of bounds on load",
                path, None, {"declared": count, "max_possible": max_possible}))

    if not findings:
        findings.append(Finding(Severity.INFO, "gguf.ok",
                                f"GGUF v{version}: {n_tensors} tensors, {n_kv} KV — "
                                f"header counts within file bounds", path))
    return findings
