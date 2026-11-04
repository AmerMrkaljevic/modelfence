# ModelFence

**Scan AI model files for code-execution payloads — including the evasions `picklescan` and `ModelScan` miss. Zero dependencies.**

Downloading a model from Hugging Face or a teammate runs code the moment you
`torch.load` it. The existing scanners that are supposed to gate that — `picklescan`
and Protect AI's `ModelScan` — can be bypassed by constructs that are trivial to
build. ModelFence was written by someone who reported those bypasses upstream, and
it catches them.

## The 409-byte file both incumbents pass

A `.pt` file with a duplicate archive member — malicious pickle first, benign
pickle second. Python's `zipfile` (what every scanner uses) reads the **last**
entry; PyTorch's loader reads the **first**. The scanner inspects the wrong bytes.

```
$ modelscan -p model.pt
--- Summary ---
 No issues found! 🎉                         exit 0

$ modelfence scan model.pt
CRITICAL pickle.reduce_exec       model.pt::archive/data.pkl
         imports posix.system and the pickle contains a call opcode — arbitrary code execution on load
CRITICAL zip.duplicate_member     model.pt::archive/data.pkl
         archive member appears 2 times — a parser-differential evasion. Every copy is scanned.
verdict: FAIL (gate: >= MEDIUM)            exit 1
```

Reproduce it yourself: `python3 examples/evasion_demo.py`.

## Install

```bash
pip install modelfence
```

No dependencies — a security tool should not drag a supply chain of its own into
your build. Pure Python standard library, Python 3.9+.

## Use

```bash
modelfence scan path/to/model.pt           # one file
modelfence scan ./models/                   # walk a directory
modelfence scan model.pt --json             # machine-readable, for pipelines
modelfence scan model.pt --fail-on high     # only fail CI on HIGH+ (default: medium)
```

Exit code is `1` when anything at or above the `--fail-on` threshold is found, so
it drops straight into a CI gate:

```yaml
# .github/workflows/model-scan.yml
- run: pip install modelfence && modelfence scan ./models
```

## What it catches that opcode-only / `zipfile`-based scanners don't

| Evasion / payload | picklescan | ModelScan | ModelFence |
|---|:--:|:--:|:--:|
| `os.system` / `subprocess` REDUCE | ✅ | ✅ | ✅ |
| **Duplicate-member zip differential** (`.pt`) | ❌ | ❌ | ✅ |
| **`logging.config.dictConfig` data gadget** (name hidden as string data) | ❌ | ❌ | ✅ |
| **Submodule blocklist bypass** (`multiprocessing.util.spawnv_passfds`) | ❌ | ❌ | ✅ |
| Malformed GGUF header (load-time DoS) | — | — | ✅ |
| safetensors header / offset overflow | — | — | ✅ |
| Truncated / garbage-after-payload pickle | partial | partial | ✅ |

The three bold rows are documented, reproducible bypasses of the current tools.

## How it works

- **Pickle**: static opcode walk via `pickletools.genops` — nothing is ever
  executed. Reconstructs `GLOBAL`/`STACK_GLOBAL` imports, flags dangerous
  callables **with submodule propagation** (the inheritance rule picklescan gets
  wrong), and separately scans string *data* for code-execution names that never
  appear as an opcode at all — the `dictConfig` gadget class.
- **Zip models** (`.pt`, `.pth`, `.ckpt`, `.npz`, `.keras`): refuses to pick a
  tie-break winner on duplicate members — flags the construct and scans **every**
  copy, so a payload can't hide behind the differential. Also catches zip-slip paths.
- **GGUF**: reads only the fixed header and bounds the declared tensor / KV counts
  against the real file size — catches the count-trusting load-time DoS class
  without parsing the hostile body.
- **safetensors**: certifies the safe format, and flags a hostile header length
  or out-of-bounds tensor offsets.

## Supported formats

`.pkl` `.pickle` · `.pt` `.pth` `.ckpt` · `.npz` `.keras` · `.gguf` · `.safetensors`
· raw pickles in `.bin`. Format is detected by magic bytes, not just extension.

## Library use

```python
from modelfence import scan_file, Severity

findings = scan_file("model.pt")
if any(f.severity >= Severity.HIGH for f in findings):
    raise SystemExit("unsafe model")
```

## ModelFence Cloud (coming)

The CLI is free and always will be. **ModelFence Cloud** adds the things teams
need around it: org-wide policy, a signed allow/deny registry so an approved
model stays approved, PR-blocking GitHub/GitLab checks, Hugging Face pull-time
scanning, and an audit trail for compliance. [Join the waitlist →](#) *(link set at launch)*

## License

MIT. Built on security research into picklescan, ModelScan, PyTorch, GGUF and
coremltools — see the advisories for the underlying findings.
