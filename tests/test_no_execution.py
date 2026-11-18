"""Proof that scanning never runs package code.

Every way Python could start a process or execute code is replaced with a
tripwire (fittingly) that raises. Then the full malicious corpus is scanned
through the real extraction path. ``compile`` is allowed only in AST-only
mode, which is what ``ast.parse`` uses and which cannot produce runnable code.
"""

import ast
import builtins
import importlib
import importlib.util
import os
import pickle
import runpy
import subprocess
import sys
from pathlib import Path

import pytest

from tripwire.bench.corpus import FIXTURES, MALICIOUS
from tripwire.bench.run import run_corpus, scan_fixture
from tripwire.cli import main as cli_main

FORBIDDEN_MODULE_ATTRS = [
    (subprocess, "Popen"), (subprocess, "run"), (subprocess, "call"), (subprocess, "check_call"),
    (subprocess, "check_output"), (subprocess, "getoutput"), (os, "system"), (os, "popen"),
    (os, "execv"), (os, "execve"), (os, "execvp"), (os, "execvpe"), (os, "execl"), (os, "execle"),
    (os, "execlp"), (os, "execlpe"), (os, "spawnv"), (os, "spawnve"), (os, "spawnl"), (os, "spawnle"),
    (os, "startfile"), (os, "posix_spawn"), (os, "posix_spawnp"), (os, "fork"),
    (importlib, "import_module"), (importlib, "__import__"), (importlib.util, "spec_from_file_location"),
    (importlib.util, "module_from_spec"), (runpy, "run_path"), (runpy, "run_module"),
    (pickle, "load"), (pickle, "loads"),  # marshal is left alone: the import system loads .pyc files with it
]


class ExecutionAttempt(AssertionError):
    pass


@pytest.fixture
def tripwired(monkeypatch):
    """Arm every execution path. Yields the list of attempts (must stay empty)."""
    attempts: list[str] = []

    def trap(label):
        def _trap(*a, **k):
            attempts.append(label)
            raise ExecutionAttempt(f"scan tried to call {label}")
        return _trap

    for mod, attr in FORBIDDEN_MODULE_ATTRS:
        if hasattr(mod, attr):
            monkeypatch.setattr(mod, attr, trap(f"{mod.__name__}.{attr}"))
    monkeypatch.setattr(builtins, "exec", trap("exec"))
    monkeypatch.setattr(builtins, "eval", trap("eval"))

    real_compile = builtins.compile

    def ast_only_compile(source, filename, mode, flags=0, *a, **k):
        if not flags & ast.PyCF_ONLY_AST:
            attempts.append(f"compile({filename!r}) to bytecode")
            raise ExecutionAttempt("compile() to bytecode during a scan")
        return real_compile(source, filename, mode, flags, *a, **k)

    monkeypatch.setattr(builtins, "compile", ast_only_compile)

    fixture_modules = {f.name.replace("-", "_") for f in FIXTURES} | {"_build_helper", "twfx_pth_exec_env"}
    real_import = builtins.__import__

    def guarded_import(name, *a, **k):
        if name.split(".")[0] in fixture_modules:
            attempts.append(f"import {name}")
            raise ExecutionAttempt(f"scan tried to import package module {name}")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    yield attempts


@pytest.fixture(scope="module", autouse=True)
def warm_caches():
    # Load lazily-imported stdlib pieces (codecs such as cp437 for zip names) and
    # the popular-name lists before arming: one fixture of every archive kind.
    # Without this the test only passed when earlier test files had warmed them.
    one_per_kind = list({f.kind: f for f in FIXTURES}.values())
    run_corpus(FIXTURES[:3] + one_per_kind)


def test_scanning_the_malicious_corpus_executes_nothing(tmp_path, tripwired):  # tmp_path first: pytest imports getpass for it
    path_before = list(sys.path)
    modules_before = set(sys.modules)
    malicious = [f for f in FIXTURES if f.label == MALICIOUS]
    results = [scan_fixture(f, tmp_path) for f in malicious]
    assert tripwired == []
    assert sum(o.result.flagged for o in results) > len(malicious) // 2  # it did real work
    assert sys.path == path_before
    new = set(sys.modules) - modules_before
    assert not any(m.startswith(("twfx", "reqeusts", "crossenv", "_build_helper")) for m in new)


def test_cli_scan_executes_nothing(tmp_path, capsys, tripwired):
    from tripwire.bench.archive import build
    from tripwire.bench.corpus import by_id
    name, data = build(by_id("setup-env-post"))
    p = tmp_path / name
    p.write_bytes(data)
    assert cli_main(["scan", str(p), "--quarantine", str(tmp_path / "q")]) == 1
    assert tripwired == []


def test_the_traps_actually_fire(tripwired):
    # Guard against a silently broken fixture: the traps must catch real calls.
    with pytest.raises(ExecutionAttempt):
        subprocess.run(["echo", "hi"])
    with pytest.raises(ExecutionAttempt):
        builtins.exec("x = 1")
    with pytest.raises(ExecutionAttempt):
        builtins.compile("x = 1", "<t>", "exec")
    assert ast.parse("x = 1")  # AST-only compile is still allowed
    assert tripwired == ["subprocess.run", "exec", "compile('<t>') to bytecode"]


# The traps above replace module attributes, so they would miss a function bound
# at import time (``from subprocess import run``). This static check closes that
# gap: the tool's own source must not import or call anything that can run code.

SRC = Path(__file__).resolve().parents[1] / "src" / "tripwire"
FORBIDDEN_IMPORTS = {"subprocess", "runpy", "pickle", "marshal", "ctypes", "pty", "multiprocessing", "shelve",
                     "yaml", "code", "codeop", "pip", "setuptools", "distutils"}
# Called by bare name (``exec(...)``) or as an attribute (``os.system(...)``). ``re.compile`` is not
# in the second set, and ``ast.parse`` is the only sanctioned way to compile package text.
FORBIDDEN_NAME_CALLS = {"exec", "eval", "compile", "__import__", "execfile", "breakpoint"}
FORBIDDEN_ATTR_CALLS = {"system", "popen", "startfile", "import_module", "run_path", "run_module",
                        "spec_from_file_location", "module_from_spec", "exec_module", "load_module",
                        "execv", "execve", "execvp", "execvpe", "execl", "execle", "execlp", "execlpe",
                        "spawnv", "spawnve", "spawnl", "spawnle", "posix_spawn", "posix_spawnp", "fork"}


def _source_files():
    files = sorted(SRC.rglob("*.py"))
    assert len(files) > 20
    return files


def test_tool_source_never_imports_execution_modules():
    bad = []
    for path in _source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
            for n in names:
                top = n.split(".")[0]
                if top in FORBIDDEN_IMPORTS or (top == "importlib" and n not in ("importlib", "importlib.resources")
                                                and not n.startswith("importlib.resources")):
                    bad.append(f"{path.relative_to(SRC)}: import {n}")
    assert bad == []


def test_tool_source_never_calls_execution_functions():
    bad = []
    for path in _source_files():
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Call):
                fn = node.func
                if (isinstance(fn, ast.Name) and fn.id in FORBIDDEN_NAME_CALLS) or                         (isinstance(fn, ast.Attribute) and fn.attr in FORBIDDEN_ATTR_CALLS):
                    bad.append(f"{path.relative_to(SRC)}:{node.lineno} {ast.unparse(fn)}()")
    assert bad == []
