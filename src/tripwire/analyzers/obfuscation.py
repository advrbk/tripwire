"""Hidden code: encoded blobs that get executed, packer output, noise strings.

Legitimate packages almost never decode a blob and pass it straight to
``exec``/``eval``/``Function``. They do ship minified bundles and base64
images, so those only count when they sit in install-time code.
"""

from __future__ import annotations

import ast
import re

from ..models import Evidence, Package, PackageFile
from .base import ImportMap, ev, fold, has_any, is_js, is_python, line_of, parse_python, shannon_entropy, snippet_at

NAME = "obfuscation"

PY_DECODERS = {"b64decode", "b32decode", "b85decode", "a85decode", "decodebytes", "a2b_base64",
               "decompress", "loads", "fromhex", "unhexlify", "decode", "urlsafe_b64decode"}
PY_EXEC = {"exec", "eval", "builtins.exec", "builtins.eval", "compile"}

JS_DECODE_EXEC = re.compile(
    r"""(?:\beval|\bFunction|new\s+Function)\s*\((?:[^()]|\([^()]*\)){0,200}?"""
    r"""(?:atob\s*\(|Buffer\.from\s*\([^)]*['"](?:base64|hex)['"]|fromCharCode|unescape\s*\(|decodeURIComponent\s*\()""",
)
JS_EVAL_VAR = re.compile(r"""\beval\s*\(\s*(?!['"`])[\w$.\[\]]+\s*\)""")
JS_OBF_IDS = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
B64_BLOB = re.compile(r"""['"]([A-Za-z0-9+/]{300,}={0,2})['"]""")
HEX_BLOB = re.compile(r"""['"]((?:[0-9a-fA-F]{2}){150,})['"]""")
ESCAPE_RUN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){40,}")
LONG_STRING = re.compile(r"""['"]([^'"\s]{120,})['"]""")
# JS_DECODE_EXEC needs one of these decoders (lower case), so most files skip it.
JS_DECODER_KEYS = ("atob", "buffer.from", "fromcharcode", "unescape", "decodeuricomponent")
REGEX_EXEC_FALLBACK = re.compile(
    r"\b(?:exec|eval)\s*\(\s*(?:[\w.]+\.)?(?:b64decode|decompress|loads|fromhex|unhexlify|decode)\s*\(")


class ObfuscationAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        out: list[Evidence] = []
        for f in pkg.code_files():
            install = f.path in pkg.install_files
            if is_python(f) or f.suffix == ".pth":
                out += self._python(f, install)
            if is_js(f) or (install and f.path == "package.json"):
                out += self._js(f, install)
            out += self._blobs(f, install)
        return out

    def _python(self, f: PackageFile, install: bool) -> list[Evidence]:
        out = []
        tree = parse_python(f) if f.suffix != ".pth" else None
        if tree is None:
            for m in REGEX_EXEC_FALLBACK.finditer(f.text):
                ln = line_of(f.text, m.start())
                out.append(ev(NAME, "exec_decoded_blob", 0.8,
                              f"{f.path} decodes data and executes it immediately.", f, ln))
                break
            return out
        imports = ImportMap(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = imports.dotted(node.func)
            if target == "getattr" and len(node.args) >= 2 and _is_built_string(node.args[1]):
                out.append(ev(NAME, "hidden_attribute", 0.45,
                              f"{f.path} builds a function name from pieces at runtime (getattr with a joined "
                              "string), a way to hide calls like exec.", f, node.lineno))
            if target not in PY_EXEC:
                continue
            decoders = [n for n in ast.walk(node) if isinstance(n, ast.Call) and n is not node
                        and _call_name(n) in PY_DECODERS]
            if decoders:
                kinds = sorted({_call_name(d) for d in decoders})
                out.append(ev(NAME, "exec_decoded_blob", 0.85,
                              f"{f.path} decodes data ({', '.join(kinds)}) and runs it with {target}().",
                              f, node.lineno))
            elif any(isinstance(n, ast.Subscript) and isinstance(n.slice, ast.Slice) and n.slice.step is not None
                     for n in ast.walk(node)):
                out.append(ev(NAME, "exec_reversed_string", 0.7,
                              f"{f.path} reverses or slices a string and runs it with {target}().", f, node.lineno))
        return out

    def _js(self, f: PackageFile, install: bool) -> list[Evidence]:
        out = []
        m = JS_DECODE_EXEC.search(f.text) if has_any(fold(f.text), JS_DECODER_KEYS) else None
        if m:
            ln = line_of(f.text, m.start())
            out.append(ev(NAME, "exec_decoded_blob", 0.85 if install else 0.75,
                          f"{f.path} decodes data and runs it with eval/Function.", f, ln))
        ids = JS_OBF_IDS.findall(f.text)
        if len(set(ids)) >= 8:
            m2 = JS_OBF_IDS.search(f.text)
            ln = line_of(f.text, m2.start()) if m2 else 1
            out.append(ev(NAME, "packer_identifiers", 0.6,
                          f"{f.path} has {len(set(ids))} '_0x...' names, the fingerprint of an obfuscation tool.",
                          f, ln))
        if install:
            m3 = JS_EVAL_VAR.search(f.text)
            if m3:
                ln = line_of(f.text, m3.start())
                out.append(ev(NAME, "eval_variable", 0.4,
                              f"{f.path} runs a variable with eval() in install-time code.", f, ln))
        return out

    def _blobs(self, f: PackageFile, install: bool) -> list[Evidence]:
        out = []
        text = f.text
        m = B64_BLOB.search(text)
        if m and "data:" not in text[max(0, m.start() - 60):m.start()] and shannon_entropy(m.group(1)[:4000]) > 5.0:
            ln = line_of(text, m.start())
            out.append(ev(NAME, "base64_blob", 0.45 if install else 0.2,
                          f"{f.path} contains a {len(m.group(1))}-character base64 blob"
                          + (" in install-time code." if install else "."), f, ln, _short(snippet_at(text, ln))))
        m = HEX_BLOB.search(text)
        if m:
            ln = line_of(text, m.start())
            out.append(ev(NAME, "hex_blob", 0.45 if install else 0.2,
                          f"{f.path} contains a {len(m.group(1)) // 2}-byte hex-encoded blob.", f, ln,
                          _short(snippet_at(text, ln))))
        m = ESCAPE_RUN.search(text) if "\\x" in text else None
        if m:
            ln = line_of(text, m.start())
            out.append(ev(NAME, "escaped_bytes", 0.4,
                          f"{f.path} hides a long string as \\x escape sequences.", f, ln, _short(snippet_at(text, ln))))
        if not out:
            for m in LONG_STRING.finditer(text):
                s = m.group(1)
                if s.startswith(("http", "data:", "sha", "/")) or "data:" in text[max(0, m.start() - 60):m.start()]:
                    continue
                h = shannon_entropy(s[:2000])
                if h >= 5.2:
                    ln = line_of(text, m.start())
                    out.append(ev(NAME, "high_entropy_string", 0.4 if install else 0.15,
                                  f"{f.path} has a random-looking {len(s)}-character string (entropy {h:.1f} bits/char).",
                                  f, ln, _short(snippet_at(text, ln))))
                    break
        if install and f.path != "package.json":
            for i, line in enumerate(text.splitlines(), 1):
                if len(line) > 1000:
                    out.append(ev(NAME, "minified_install_code", 0.5,
                                  f"{f.path} runs at install time and has a {len(line)}-character single line "
                                  "(minified or packed code).", f, i, _short(line)))
                    break
        return out


def _short(s: str) -> str:
    return s if len(s) <= 120 else s[:117] + "..."


def _call_name(call: ast.Call) -> str:
    fn = call.func
    if isinstance(fn, ast.Attribute):
        return fn.attr
    if isinstance(fn, ast.Name):
        return fn.id
    return ""


def _is_built_string(node: ast.AST) -> bool:
    """True when an attribute name is assembled from hidden constant pieces.

    Matches ``'ex' + 'ec'``, ``''.join(['e', 'x', ...])``, ``chr(101) + chr(120)``,
    ``'cexe'[::-1]`` and decoder output (``b64decode(...).decode()``).

    Not matched: names built from a *variable*, such as ``getattr(self, "visit_" + kind)``.
    That is the ordinary dispatch idiom (the ``cmd`` and ``ast`` modules use it), and
    flagging it made the rule fire on many harmless libraries.
    """
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _all_hidden_constant(node)
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in PY_DECODERS and name != "decode":
            return True
        if name == "decode":
            # bytes([101, 120]).decode() or b64decode(...).decode()
            inner = node.func.value if isinstance(node.func, ast.Attribute) else None
            return inner is not None and (_all_hidden_constant(inner) or (
                isinstance(inner, ast.Call) and _call_name(inner) in PY_DECODERS))
        if name == "join" and node.args:
            return _all_hidden_constant(node.args[0])
        if name == "chr":
            return True
        if name == "format":
            return _all_hidden_constant(node)
        return False
    if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
        return isinstance(node.value, ast.Constant)
    return False


def _all_hidden_constant(node: ast.AST) -> bool:
    """Every leaf is a literal or chr()/bytes() of literals: no variables involved."""
    for n in ast.walk(node):
        if isinstance(n, ast.Name) and n.id not in ("chr", "bytes", "bytearray", "str"):
            return False
        if isinstance(n, ast.Attribute) and n.attr not in ("join", "decode", "format"):
            return False
    return True
