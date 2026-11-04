"""ModelFence — scan AI model files for code-execution payloads.

A dependency-free scanner for pickle-based and binary model formats that catches
the scanner-evasion constructs picklescan and ModelScan miss: duplicate-member
zip differentials, submodule-blocklist bypasses, and code-execution names hidden
in string data.
"""
from .findings import Finding, Severity
from .scanner import scan_file, scan_path

__version__ = "0.1.0"
__all__ = ["Finding", "Severity", "scan_file", "scan_path", "__version__"]
