"""Pickle scanner — static opcode analysis, no execution, ever.

`pickletools.genops` walks a pickle's opcode stream without running a single
reduction, so this is safe to point at hostile input. We reconstruct the two
things that matter for code execution:

  1. The GLOBAL / STACK_GLOBAL targets (module, name) the pickle imports, and
     whether a REDUCE/INST/OBJ/NEWOBJ opcode actually *calls* one. A dangerous
     callable that is imported and then called is the classic pickle-RCE shape.

  2. Dangerous dotted names that appear as STRING DATA rather than as a GLOBAL
     opcode. This is the gap behind the `logging.config.dictConfig` gadget: the
     payload's `subprocess.call` never appears as an opcode at all — it is a
     plain string inside a config dict that `dictConfig` resolves at runtime.
     As the picklescan write-up put it, "no opcode-level scanner can observe it."
     We scan the string constants for that shape and flag it (as MEDIUM, since
     it is a heuristic and can false-positive on legitimate config blobs).

The blocklist below is intentionally broader than picklescan's and is applied
*with submodule propagation*: a dangerous module taints every submodule, which
is precisely the inheritance rule picklescan got wrong (its `logging` entry with
a name-set left `logging.config` completely unguarded).
"""
from __future__ import annotations

import pickletools
from io import BytesIO

from .findings import Finding, Severity

# --- modules/callables that reach code execution directly -------------------
# value "*" taints the whole module tree; a set names specific callables but the
# module prefix is ALSO treated as dangerous for submodules (see _classify).
_DANGEROUS: dict[str, object] = {
    "os": {"system", "popen", "execl", "execle", "execlp", "execv", "execve",
           "execvp", "execvpe", "spawnl", "spawnle", "spawnv", "spawnve", "fork"},
    "posix": {"system", "popen", "execv", "execve", "fork", "spawnv"},
    "nt": {"system", "popen", "spawnv"},
    "subprocess": "*",          # Popen, call, run, check_output, getoutput, ...
    "multiprocessing": "*",     # multiprocessing.util.spawnv_passfds reaches fork_exec
    "logging.config": "*",      # dictConfig/fileConfig resolve dotted names from data
    "pty": {"spawn"},
    "commands": "*",            # py2 getoutput/getstatusoutput
    "popen2": "*",
    "runpy": {"run_path", "run_module", "_run_code", "_run_module_code"},
    "code": {"interact", "InteractiveInterpreter", "InteractiveConsole"},
    "codeop": "*",
    "bdb": {"Bdb"},
    "pdb": {"run", "runeval", "runcall", "Pdb"},
    "importlib": {"import_module"},
    "imp": {"load_source", "load_module", "load_compiled", "load_dynamic"},
    "ctypes": "*",              # CDLL/cast/memmove -> native code
    "builtins": {"eval", "exec", "compile", "__import__", "getattr", "open",
                 "globals", "vars", "memoryview", "breakpoint", "input"},
    "__builtin__": {"eval", "exec", "compile", "__import__", "getattr", "open"},
    "webbrowser": {"open", "open_new", "get"},
    "asyncio": {"run", "get_event_loop"},
    "timeit": {"timeit", "repeat"},
    "sys": {"modules", "exit"},
}

# --- gadget-enabling callables: not RCE alone, but the glue in real chains ----
_SUSPICIOUS: dict[str, object] = {
    "functools": {"partial", "reduce"},
    "operator": {"methodcaller", "attrgetter", "itemgetter", "call"},
    "socket": "*",
    "shutil": {"rmtree", "move", "copy", "copyfileobj", "make_archive"},
    "tempfile": {"mktemp", "NamedTemporaryFile"},
    "pickle": {"loads", "load", "Unpickler"},
    "base64": {"b64decode", "decodebytes"},
    "codecs": {"decode", "encode"},
    "zlib": {"decompress"},
    "marshal": {"loads"},
    "pathlib": {"Path"},
}

# dotted callables, as a regex, hunted inside STRING DATA (the dictConfig class)
_DATA_PATTERNS = (
    r"\bos\.system\b", r"\bos\.popen\b", r"\bposix\.system\b", r"\bnt\.system\b",
    r"\bsubprocess\.(?:Popen|call|run|check_output|check_call|getoutput|getstatusoutput)\b",
    r"\bpty\.spawn\b", r"\bbuiltins\.(?:eval|exec|__import__|compile)\b",
    r"\b(?:eval|exec|compile)\s*\(", r"\b__import__\s*\(",
    r"\bspawnv_passfds\b", r"\bfork_exec\b",
)

import re as _re
_DATA_RX = _re.compile("|".join(_DATA_PATTERNS))
# the logging.config custom-factory key: inside a pickle the dict key is the
# bare two-character string "()", not the quoted source form, so match it exact.
_FACTORY_KEY = "()"

# opcodes that turn an imported object into an actual call / instance
_CALL_OPS = {"REDUCE", "INST", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"}
# opcodes that push a string we might later need to resolve a STACK_GLOBAL
_STR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE",
            "SHORT_BINSTRING", "BINSTRING", "STRING"}


def _classify(module: str, name: str) -> Severity | None:
    """Return a severity for a (module, name) global, or None if not flagged.

    Submodule propagation: `logging.config` is caught by the `logging.config`
    entry, but `logging.config.handlers` is caught too because we test every
    dotted prefix of the module against the table.
    """
    def check(table: dict[str, object], sev: Severity) -> Severity | None:
        parts = module.split(".")
        for i in range(len(parts), 0, -1):
            prefix = ".".join(parts[:i])
            if prefix in table:
                rule = table[prefix]
                # exact-module match with a name-set: name must be listed;
                # but a *prefix* match (submodule) taints regardless of name.
                if rule == "*" or i < len(parts):
                    return sev
                if isinstance(rule, (set, frozenset)) and name in rule:
                    return sev
        return None

    return check(_DANGEROUS, Severity.HIGH) or check(_SUSPICIOUS, Severity.MEDIUM)


def scan_pickle_bytes(data: bytes, path: str, member: str | None = None) -> list[Finding]:
    findings: list[Finding] = []
    globals_found: list[tuple[str, str]] = []
    string_consts: list[str] = []
    has_call_op = False
    recent_strings: list[str] = []

    try:
        for opcode, arg, _pos in pickletools.genops(BytesIO(data)):
            opname = opcode.name
            if opname == "GLOBAL":
                # arg is "module name" (space-joined by pickletools)
                mod, _, nm = str(arg).partition(" ")
                globals_found.append((mod, nm))
            elif opname == "STACK_GLOBAL":
                # module and name were pushed as the two most recent strings
                if len(recent_strings) >= 2:
                    globals_found.append((recent_strings[-2], recent_strings[-1]))
                else:
                    findings.append(Finding(
                        Severity.MEDIUM, "pickle.stack_global_unresolved",
                        "STACK_GLOBAL with operands not statically resolvable "
                        "(memoized or computed) — import target hidden",
                        path, member))
            elif opname in _STR_OPS and isinstance(arg, str):
                recent_strings.append(arg)
                string_consts.append(arg)
            if opname in _CALL_OPS:
                has_call_op = True
    except Exception as exc:  # malformed / truncated / adversarial pickle
        findings.append(Finding(
            Severity.HIGH, "pickle.malformed",
            f"pickle opcode stream failed to parse cleanly ({exc.__class__.__name__}: "
            f"{exc}) — truncation/garbage after a payload is a known evasion",
            path, member))

    # --- flag dangerous/suspicious imports --------------------------------
    for mod, nm in globals_found:
        sev = _classify(mod, nm)
        if sev is None:
            continue
        if sev >= Severity.HIGH and has_call_op:
            findings.append(Finding(
                Severity.CRITICAL, "pickle.reduce_exec",
                f"imports {mod}.{nm} and the pickle contains a call opcode "
                f"(REDUCE/NEWOBJ/BUILD) — arbitrary code execution on load",
                path, member, {"module": mod, "name": nm}))
        else:
            findings.append(Finding(
                sev, "pickle.dangerous_global" if sev >= Severity.HIGH
                else "pickle.suspicious_global",
                f"imports {mod}.{nm}", path, member,
                {"module": mod, "name": nm}))

    # --- opcode-invisible payloads hidden in string data ------------------
    # the logging.config.dictConfig class: a dotted callable sits in a config
    # dict as plain data, so it never appears as a GLOBAL. Catch the shape.
    for s in string_consts:
        if _DATA_RX.search(s):
            findings.append(Finding(
                Severity.MEDIUM, "pickle.exec_name_in_data",
                "a code-execution dotted name appears as string DATA, not as an "
                "opcode (the logging.config/dictConfig gadget shape) — invisible "
                "to opcode-only scanners",
                path, member, {"snippet": s[:120]}))
            break
    if any(s == _FACTORY_KEY for s in string_consts):
        findings.append(Finding(
            Severity.MEDIUM, "pickle.factory_dict",
            'a "()"-factory config key is present; logging.config resolves these '
            "to arbitrary callables from data at runtime",
            path, member))

    return findings
