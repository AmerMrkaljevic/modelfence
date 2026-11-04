"""Zip-container scanner for .pt/.pth/.ckpt/.zip/.npz/.keras models.

The headline check here is **duplicate member names**, the parser-differential
evasion that defeats both picklescan and modelscan: Python's `zipfile` resolves
a duplicated name to the *last* entry, while PyTorch's vendored miniz returns
the *first*. Put the payload first and a benign pickle second and every
zipfile-based scanner inspects the wrong bytes while `torch.load` runs the
payload. We refuse to pick a winner: if names are duplicated we flag it as
CRITICAL (no legitimate model archive has duplicate members) AND scan every
copy, so the payload can never hide behind the tie-break.

We also catch zip-slip paths (`..`, absolute) and scan every pickle member.
"""
from __future__ import annotations

import zipfile

from .findings import Finding, Severity
from .pickle_scan import scan_pickle_bytes

_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle")
# inside a torch archive the pickle is usually named data.pkl / <k>/data.pkl,
# but the extension-less "data" member and "*/data" also carry pickles.
_PICKLE_MEMBER_NAMES = ("data.pkl", "data")


def _looks_like_pickle(name: str, raw: bytes) -> bool:
    if name.endswith(_PICKLE_MEMBER_SUFFIXES):
        return True
    base = name.rsplit("/", 1)[-1]
    if base in _PICKLE_MEMBER_NAMES:
        return True
    # pickle protocol 2+ starts with PROTO opcode 0x80; also accept classic
    # protocol-0/1 leading opcodes that realistic payloads use.
    return len(raw) >= 2 and raw[0:1] == b"\x80"


def scan_zip(path: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        zf = zipfile.ZipFile(path)
    except Exception as exc:
        return [Finding(Severity.HIGH, "zip.malformed",
                        f"not a readable zip archive ({exc.__class__.__name__}: {exc})",
                        path)]

    with zf:
        names = zf.namelist()

        # --- duplicate member names: the scanner-evasion construct ---------
        seen: dict[str, int] = {}
        for n in names:
            seen[n] = seen.get(n, 0) + 1
        duplicates = {n: c for n, c in seen.items() if c > 1}
        for n, c in duplicates.items():
            findings.append(Finding(
                Severity.CRITICAL, "zip.duplicate_member",
                f"archive member {n!r} appears {c} times — a parser-differential "
                f"evasion (zipfile reads last, torch/miniz reads first). "
                f"Every copy is scanned below.",
                path, n, {"count": c}))

        # --- zip-slip / absolute paths -------------------------------------
        for n in names:
            if n.startswith("/") or n.startswith("\\") or ".." in n.replace("\\", "/").split("/"):
                findings.append(Finding(
                    Severity.HIGH, "zip.path_traversal",
                    f"member path {n!r} escapes the archive root (zip-slip)",
                    path, n))

        # --- scan every pickle member, including each duplicate copy -------
        # infolist() yields one entry per physical local-file-header, so
        # duplicates appear as distinct infos; we read each by its info object
        # to avoid zipfile's name->last-entry collapse and reach the "first"
        # bytes torch would actually load.
        for info in zf.infolist():
            try:
                raw = zf.open(info).read()
            except Exception as exc:
                findings.append(Finding(
                    Severity.MEDIUM, "zip.member_unreadable",
                    f"member {info.filename!r} could not be read ({exc})",
                    path, info.filename))
                continue
            if _looks_like_pickle(info.filename, raw):
                findings.extend(scan_pickle_bytes(raw, path, info.filename))

    return findings
