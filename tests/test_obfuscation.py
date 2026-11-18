"""obfuscation: encoded blobs that get executed, packer output, noise strings."""

import base64
import random

from helpers import fired, npm_pkg, py_pkg, rules, weight_of

from tripwire.analyzers.obfuscation import ObfuscationAnalyzer

A = ObfuscationAnalyzer()


def blob(seed=1, n=300) -> str:
    return base64.b64encode(random.Random(seed).randbytes(n)).decode()


# ------------------------------------------------------------- Python positives

def test_exec_b64decode():
    ev = A.analyze(py_pkg({"p/__init__.py": f'import base64\nexec(base64.b64decode("{blob()}"))\n'}))
    assert weight_of(ev, "exec_decoded_blob") == 0.85
    assert "base64_blob" in rules(ev)  # the blob itself is context in runtime code


def test_exec_zlib_chain_names_both_decoders():
    ev = A.analyze(py_pkg({"p/x.py": 'import zlib, base64\nexec(zlib.decompress(base64.b64decode("eJw=")))\n'}))
    msg = next(e.message for e in ev if e.rule == "exec_decoded_blob")
    assert "b64decode" in msg and "decompress" in msg


def test_eval_of_unhexlify():
    ev = A.analyze(py_pkg({"p/x.py": "import binascii\neval(binascii.unhexlify('7072696e74'))\n"}))
    assert "exec_decoded_blob" in fired(ev)


def test_exec_reversed_string():
    ev = A.analyze(py_pkg({"p/x.py": "exec(\")'EKAF'(tnirp\"[::-1])\n"}))
    assert weight_of(ev, "exec_reversed_string") == 0.7


def test_getattr_with_constant_pieces():
    ev = A.analyze(py_pkg({"p/x.py": 'import builtins\ngetattr(builtins, "ex" + "ec")("FAKE = 1")\n'}))
    assert weight_of(ev, "hidden_attribute") == 0.45


def test_getattr_with_chr_pieces():
    src = "import builtins\nf = getattr(builtins, chr(101) + chr(120) + chr(101) + chr(99))\n"
    assert "hidden_attribute" in fired(A.analyze(py_pkg({"p/x.py": src})))


def test_getattr_with_joined_literals():
    src = "import os\nf = getattr(os, ''.join(['sy', 'st', 'em']))\n"
    assert "hidden_attribute" in fired(A.analyze(py_pkg({"p/x.py": src})))


def test_unparsable_python_uses_pattern_fallback():
    ev = A.analyze(py_pkg({"p/x.py": "def (:\nexec(base64.b64decode('cGFzcw=='))\n"}))
    assert weight_of(ev, "exec_decoded_blob") == 0.8


# ------------------------------------------------------------- Python benign near-misses

def test_getattr_dispatch_on_variable_is_benign():
    # bug fix: the visitor idiom used to score 0.45 and fire
    src = 'class V:\n    def visit(self, node):\n        return getattr(self, "visit_" + node.kind)(node)\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_getattr_join_of_variables_is_benign():
    src = "def get(obj, parts):\n    return getattr(obj, '_'.join(parts))\n"
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_exec_compile_of_source_is_benign():
    src = 'def run(src, path):\n    exec(compile(src, path, "exec"), {})\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_base64_without_exec_is_only_context():
    ev = A.analyze(py_pkg({"p/x.py": f'import base64\nKEY = base64.b64decode("{blob(2)}")\n'}))
    assert fired(ev) == set()


def test_data_uri_is_ignored():
    ev = A.analyze(py_pkg({"p/icons.py": f'ICON = "data:image/png;base64,{blob(3, 400)}"\n'}))
    assert ev == []


def test_low_entropy_base64_is_ignored():
    repetitive = base64.b64encode(b"hello world " * 40).decode()
    assert A.analyze(py_pkg({"p/x.py": f'S = "{repetitive}"\n'})) == []


def test_base64_blob_weighs_more_in_install_code():
    ev = A.analyze(py_pkg({"setup.py": f'S = "{blob(4)}"\nfrom setuptools import setup\nsetup()\n'}))
    assert weight_of(ev, "base64_blob") == 0.45


# ------------------------------------------------------------- JavaScript

def test_js_eval_atob():
    ev = A.analyze(npm_pkg(files={"index.js": f'eval(atob("{blob(5)}"));\n'}))
    assert weight_of(ev, "exec_decoded_blob") == 0.75


def test_js_eval_atob_in_install_file_is_stronger():
    pkg = npm_pkg({"postinstall": "node i.js"}, {"i.js": f'eval(atob("{blob(6)}"));\n'})
    assert weight_of(A.analyze(pkg), "exec_decoded_blob") == 0.85


def test_js_new_function_buffer_base64():
    ev = A.analyze(npm_pkg(files={"index.js": 'new Function(Buffer.from("cGFzcw==", "base64").toString())();\n'}))
    assert "exec_decoded_blob" in fired(ev)


def test_js_function_fromcharcode():
    ev = A.analyze(npm_pkg(files={"index.js": "Function(String.fromCharCode(97,98,99))();\n"}))
    assert "exec_decoded_blob" in fired(ev)


def test_js_packer_identifiers():
    names = "".join(f"var _0x{0x1a00 + i:x}={i};" for i in range(10))
    assert weight_of(A.analyze(npm_pkg(files={"index.js": names})), "packer_identifiers") == 0.6


def test_js_few_hex_names_are_fine():
    names = "".join(f"var _0x{0x1a00 + i:x}={i};" for i in range(5))
    assert A.analyze(npm_pkg(files={"index.js": names})) == []


def test_js_eval_variable_only_counts_at_install():
    code = "module.exports = (s) => eval(s);\n"
    assert A.analyze(npm_pkg(files={"index.js": code})) == []
    pkg = npm_pkg({"postinstall": "node index.js"}, {"index.js": code})
    assert "eval_variable" in fired(A.analyze(pkg))


def test_minified_install_code_is_flagged():
    line = "var a=" + "+".join(str(i) for i in range(400)) + ";\n"
    pkg = npm_pkg({"postinstall": "node setup.js"}, {"setup.js": line})
    assert weight_of(A.analyze(pkg), "minified_install_code") == 0.5


def test_minified_runtime_bundle_is_benign():
    line = "!function(e){" + ";".join(f"var a{i}=e.b{i}" for i in range(120)) + "}(window);\n"
    assert A.analyze(npm_pkg(files={"dist/app.min.js": line})) == []


def test_globalthis_polyfill_is_benign():
    src = 'module.exports = new Function("return this")();\n'
    assert A.analyze(npm_pkg(files={"index.js": src})) == []


def test_jwt_atob_without_eval_is_benign():
    src = 'module.exports = (t) => JSON.parse(atob(t.split(".")[1]));\n'
    assert A.analyze(npm_pkg(files={"index.js": src})) == []


# ------------------------------------------------------------- blob shapes

def test_hex_blob():
    hx = random.Random(7).randbytes(200).hex()
    ev = A.analyze(py_pkg({"p/x.py": f'H = "{hx}"\n'}))
    assert rules(ev) == {"hex_blob"} and fired(ev) == set()


def test_escape_run():
    esc = "".join(f"\\x{b:02x}" for b in random.Random(8).randbytes(50))
    ev = A.analyze(py_pkg({"p/x.py": f'S = b"{esc}"\n'}))
    assert weight_of(ev, "escaped_bytes") == 0.4


def test_high_entropy_string():
    rnd = random.Random(9)
    s = "".join(rnd.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-;<=>@^_{|}~")
                for _ in range(200))
    ev = A.analyze(py_pkg({"p/x.py": f"S = '{s}'\n"}))
    assert rules(ev) == {"high_entropy_string"}
    assert weight_of(ev, "high_entropy_string") == 0.15


def test_non_code_files_are_skipped():
    assert A.analyze(py_pkg({"README.md": f"exec(base64.b64decode('{blob()}'))\n"})) == []
