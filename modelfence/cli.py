"""modelfence command-line interface.

    modelfence scan <path> [--json] [--fail-on LEVEL] [--quiet]

Exit code is 0 when nothing at or above the --fail-on threshold is found, and 1
otherwise, so it drops straight into a CI gate. Default threshold is MEDIUM.
"""
from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .findings import Severity
from .scanner import scan_path

_COLOR = {
    Severity.CRITICAL: "\033[1;31m", Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m", Severity.LOW: "\033[36m", Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"


def _fmt(sev: Severity, use_color: bool) -> str:
    return f"{_COLOR[sev]}{sev.name:<8}{_RESET}" if use_color else f"{sev.name:<8}"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="modelfence",
        description="Scan AI model files for code-execution payloads, including "
                    "the evasions picklescan and ModelScan miss.")
    ap.add_argument("--version", action="version", version=f"modelfence {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="scan a file or directory")
    sc.add_argument("path", help="model file or directory to scan")
    sc.add_argument("--json", action="store_true", help="machine-readable output")
    sc.add_argument("--fail-on", default="medium",
                    help="minimum severity that sets exit code 1 "
                         "(info/low/medium/high/critical; default: medium)")
    sc.add_argument("--quiet", action="store_true",
                    help="suppress INFO lines in text output")
    sc.add_argument("--no-color", action="store_true", help="disable ANSI color")

    args = ap.parse_args(argv)
    if args.cmd != "scan":
        ap.print_help()
        return 2

    try:
        threshold = Severity.parse(args.fail_on)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = scan_path(args.path)
    findings.sort(key=lambda f: (-int(f.severity), f.location(), f.code))

    if args.json:
        gate = max((f.severity for f in findings), default=Severity.INFO)
        print(json.dumps({
            "path": args.path,
            "findings": [f.to_dict() for f in findings],
            "summary": {s.name: sum(1 for f in findings if f.severity == s)
                        for s in Severity},
            "passed": gate < threshold,
        }, indent=2))
    else:
        use_color = sys.stdout.isatty() and not args.no_color
        shown = [f for f in findings if not (args.quiet and f.severity == Severity.INFO)]
        for f in shown:
            loc = f.location()
            print(f"{_fmt(f.severity, use_color)} {f.code:<28} {loc}")
            print(f"         {f.message}")
        worst = max((f.severity for f in findings), default=Severity.INFO)
        counts = ", ".join(f"{sum(1 for f in findings if f.severity == s)} {s.name.lower()}"
                           for s in reversed(Severity)
                           if any(f.severity == s for f in findings))
        print(f"\n{'─' * 60}")
        print(f"scanned {args.path}: {counts or 'no findings'}")
        verdict = "FAIL" if worst >= threshold else "PASS"
        print(f"verdict: {verdict} (gate: >= {threshold.name})")

    gate = max((f.severity for f in findings), default=Severity.INFO)
    return 1 if gate >= threshold else 0


if __name__ == "__main__":
    sys.exit(main())
