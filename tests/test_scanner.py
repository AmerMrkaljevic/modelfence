#!/usr/bin/env python3
"""Standalone test suite — runnable with `python3 tests/test_scanner.py` or pytest.

Generates the exact attack shapes from the research reports (os.system REDUCE,
the logging.config.dictConfig data gadget, multiprocessing.util.spawnv_passfds,
and the duplicate-member zip differential) plus benign controls, and asserts the
scanner's verdict on each. The control files prove we don't just flag everything.
"""
import os
import pickle
import struct
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modelfence import Severity
from modelfence.scanner import scan_file


def _worst(findings):
    return max((f.severity for f in findings), default=Severity.INFO)


def _codes(findings):
    return {f.code for f in findings}


# ----------------------------------------------------------------- payloads
class _EvilOS:
    def __reduce__(self):
        return (os.system, ("echo pwned",))


class _EvilLogging:
    def __reduce__(self):
        import logging.config
        return (logging.config.dictConfig, ({
            "version": 1,
            "handlers": {"h": {"()": "subprocess.call",
                               "args": "echo pwned", "shell": True}},
        },))


class _EvilSpawn:
    def __reduce__(self):
        import multiprocessing.util as mu
        return (mu.spawnv_passfds,
                (b"/bin/sh", [b"sh", b"-c", b"echo pwned"], []))


def _write(d, name, obj):
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        pickle.dump(obj, f, protocol=2)
    return p


# ------------------------------------------------------------------- tests
def test_benign_pickle_clean():
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "benign.pkl", {"weights": [1, 2, 3], "name": "ok"})
        f = scan_file(p)
        assert _worst(f) < Severity.MEDIUM, [x.to_dict() for x in f]


def test_os_system_critical():
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "evil_os.pkl", _EvilOS())
        f = scan_file(p)
        assert _worst(f) == Severity.CRITICAL
        assert "pickle.reduce_exec" in _codes(f)


def test_logging_config_data_gadget():
    # the opcode-invisible gadget: caught by submodule blocklist AND data scan
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "evil_logging.pkl", _EvilLogging())
        f = scan_file(p)
        codes = _codes(f)
        assert _worst(f) >= Severity.MEDIUM, [x.to_dict() for x in f]
        assert "pickle.exec_name_in_data" in codes or "pickle.reduce_exec" in codes
        assert "pickle.factory_dict" in codes


def test_spawnv_passfds_critical():
    with tempfile.TemporaryDirectory() as d:
        p = _write(d, "evil_spawn.pkl", _EvilSpawn())
        f = scan_file(p)
        assert _worst(f) == Severity.CRITICAL, [x.to_dict() for x in f]


def test_zip_control_payload_alone():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "control.pt")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("archive/data.pkl", pickle.dumps(_EvilOS(), protocol=2))
            z.writestr("archive/version", "3\n")
        f = scan_file(p)
        assert _worst(f) == Severity.CRITICAL
        assert "pickle.reduce_exec" in _codes(f)


def test_zip_duplicate_member_evasion():
    # THE headline case: payload first, benign second — defeats picklescan+modelscan
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "model_dup.pt")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("archive/data.pkl", pickle.dumps(_EvilOS(), protocol=2))
            z.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))
            z.writestr("archive/version", "3\n")
        f = scan_file(p)
        assert "zip.duplicate_member" in _codes(f)
        assert "pickle.reduce_exec" in _codes(f)   # we scanned the hidden first copy
        assert _worst(f) == Severity.CRITICAL


def test_zip_benign_clean():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "benign.pt")
        with zipfile.ZipFile(p, "w") as z:
            z.writestr("archive/data.pkl", pickle.dumps({"w": [1, 2]}, protocol=2))
            z.writestr("archive/version", "3\n")
        f = scan_file(p)
        assert _worst(f) < Severity.MEDIUM, [x.to_dict() for x in f]


def test_gguf_overflow_header():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "boom.gguf")
        with open(p, "wb") as fh:
            # magic, version=3, tensor_count=2**60 (impossible), kv=0
            fh.write(b"GGUF" + struct.pack("<IQQ", 3, 1 << 60, 0))
            fh.write(b"\x00" * 64)
        f = scan_file(p)
        assert "gguf.tensor_count_overflow" in _codes(f)
        assert _worst(f) >= Severity.HIGH


def test_gguf_ok():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "ok.gguf")
        with open(p, "wb") as fh:
            fh.write(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
            fh.write(b"\x00" * 256)
        f = scan_file(p)
        assert _worst(f) == Severity.INFO


def test_safetensors_ok():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "model.safetensors")
        header = b'{"t":{"dtype":"F32","shape":[2],"data_offsets":[0,8]},"__metadata__":{}}'
        with open(p, "wb") as fh:
            fh.write(struct.pack("<Q", len(header)) + header + b"\x00" * 8)
        f = scan_file(p)
        assert "safetensors.ok" in _codes(f)
        assert _worst(f) == Severity.INFO


def test_safetensors_header_overflow():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "evil.safetensors")
        with open(p, "wb") as fh:
            fh.write(struct.pack("<Q", 1 << 40))  # header claims 1TB
            fh.write(b"{}")
        f = scan_file(p)
        assert "safetensors.header_overflow" in _codes(f)


def _run():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {t.__name__}: {e.__class__.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
    return 0 if passed == len(tests) else 1


if __name__ == "__main__":
    sys.exit(_run())
