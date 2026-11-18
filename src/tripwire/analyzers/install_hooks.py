"""Code that runs when the package is installed.

This is where most real supply-chain attacks live: ``setup.py`` runs during
``pip install`` of an sdist, ``.pth`` files run on every Python start-up, and
npm runs ``preinstall`` / ``install`` / ``postinstall`` scripts by default.

Install-time code is not bad by itself (native builds need it), so the weight
depends on *what* the code does: building is weak, process spawning is
medium, network access and download-and-run are strong.
"""

from __future__ import annotations

import ast
import re
from urllib.parse import urlparse

from ..models import Evidence, Package, PackageFile
from .base import ImportMap, clip, ev, is_js, is_python, line_of, parse_python, snippet_at

NAME = "install_hooks"

PY_NET = (
    "urllib.request.urlopen", "urllib.request.urlretrieve", "urllib.request.Request",
    "urllib.urlopen", "urllib2.urlopen", "requests.", "httpx.", "http.client.HTTPConnection",
    "http.client.HTTPSConnection", "socket.socket", "socket.create_connection", "ftplib.FTP",
    "smtplib.SMTP", "aiohttp.", "urllib3.", "socket.gethostbyname", "socket.getaddrinfo",
)
PY_PROC = (
    "subprocess.Popen", "subprocess.call", "subprocess.run", "subprocess.check_call",
    "subprocess.check_output", "subprocess.getoutput", "subprocess.getstatusoutput",
    "os.system", "os.popen", "os.startfile", "os.posix_spawn", "pty.spawn", "commands.getoutput",
)
PY_PROC_PREFIX = ("os.exec", "os.spawn")
BUILD_TOOLS = {"git", "cmake", "make", "gcc", "g++", "cc", "clang", "cython", "pkg-config", "nvcc",
               "ninja", "cargo", "rustc", "meson", "swig", "msbuild", "go"}
SHELL_DROPPER = re.compile(
    r"\b(curl|wget|Invoke-WebRequest|iwr|Invoke-Expression|iex|powershell(?:\.exe)?|pwsh|certutil|bitsadmin|"
    r"mshta|rundll32|regsvr32|ncat|nc\s+-e|/dev/tcp/|base64\s+-d|chmod\s+\+x)\b",
    re.IGNORECASE,
)
INSTALL_CMDS = {"install", "develop", "egg_info", "build_py", "sdist", "bdist_egg", "build_ext", "build"}

NPM_BENIGN = re.compile(
    r"^\s*(node-gyp(?:-build)?(?:\s+rebuild)?|prebuild-install(?:\s+\|\|\s+node-gyp rebuild)?|"
    r"node-pre-gyp install(?:\s+--fallback-to-build)?|husky(?:\s+install)?|patch-package|"
    r"opencollective(?:-postinstall)?|is-ci\s*\|\|\s*husky(?:\s+install)?|echo\b[^|;&]*|exit 0|tsc|"
    r"npm run [\w:-]+)\s*$"
)
JS_CHILD = re.compile(r"""require\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]""")
JS_NET = re.compile(
    r"""require\(\s*['"](?:node:)?(?:https?|net|dgram|dns|tls|http2)['"]\s*\)|"""
    r"""from\s+['"](?:node:)?(?:https?|net|dgram|dns|tls|http2)['"]|"""
    r"""require\(\s*['"](?:axios|node-fetch|request|got|undici|superagent)['"]\s*\)|\bfetch\s*\(""",
)
JS_EXEC_SHELL = re.compile(r"""\b(?:exec|execSync|spawn|spawnSync|execFile)\s*\(\s*[`'"]([^`'"]{0,300})""")
URL = re.compile(r"""https?://[^\s'"`<>)]+""")
# Hosts that real install scripts commonly download prebuilt binaries from.
KNOWN_ARTIFACT_HOSTS = (
    "registry.npmjs.org", "github.com", "objects.githubusercontent.com", "nodejs.org",
    "storage.googleapis.com", "pypi.org", "files.pythonhosted.org", "download.cypress.io",
    "cdn.cypress.io", "registry.yarnpkg.com",
)


class InstallHooksAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        out: list[Evidence] = []
        if pkg.ecosystem == "npm":
            out += self._npm(pkg)
        for path in sorted(pkg.install_files):
            f = pkg.file(path)
            if f is None:
                continue
            if f.suffix == ".pth":
                out += self._pth(f)
            elif is_python(f):
                out += self._python(f)
            elif is_js(f) and pkg.ecosystem == "npm":
                out += self._js(f, where=f"{f.path} (run by an install script)")
            elif f.suffix in (".sh", ".ps1", ".bat", ".cmd"):
                out += self._shell_file(f)
        return out

    # ------------------------------------------------------------ Python

    def _python(self, f: PackageFile) -> list[Evidence]:
        tree = parse_python(f)
        if tree is None:
            return self._python_regex(f)
        imports = ImportMap(tree)
        out: list[Evidence] = []
        for cls in (n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)):
            bases = {imports.dotted(b).rsplit(".", 1)[-1] for b in cls.bases}
            if bases & INSTALL_CMDS and any(isinstance(b, ast.FunctionDef) and b.name == "run" for b in cls.body):
                out.append(ev(NAME, "custom_install_command", 0.15,
                              f"{f.path} overrides the '{sorted(bases & INSTALL_CMDS)[0]}' command, so its code "
                              "runs during pip install.", f, cls.lineno))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = imports.dotted(node.func)
            if not target:
                continue
            if target.startswith(PY_NET):
                out.append(ev(NAME, "install_network", 0.6,
                              f"{f.path} contacts the network at install time ({target}).", f, node.lineno))
            elif target in PY_PROC or target.startswith(PY_PROC_PREFIX):
                out.append(self._py_process(f, node, target))
            elif target in ("exec", "eval", "builtins.exec", "builtins.eval"):
                if _is_read_of_local_file(node):
                    continue  # exec(open("pkg/version.py").read()) is a common, harmless idiom
                out.append(ev(NAME, "install_exec", 0.4,
                              f"{f.path} runs dynamically built code with {target}() at install time.",
                              f, node.lineno))
        return out

    def _py_process(self, f: PackageFile, node: ast.Call, target: str) -> Evidence:
        cmd_text = ast.get_source_segment(f.text, node) or ""
        first = _first_command_word(node)
        if SHELL_DROPPER.search(cmd_text):
            return ev(NAME, "install_download_exec", 0.75,
                      f"{f.path} starts a downloader or shell at install time ({target}).", f, node.lineno)
        if first in BUILD_TOOLS or first in ("sys.executable",):
            return ev(NAME, "install_build_tool", 0.1,
                      f"{f.path} runs the build tool '{first}' at install time.", f, node.lineno)
        return ev(NAME, "install_process", 0.35,
                  f"{f.path} starts another program at install time ({target}).", f, node.lineno)

    def _python_regex(self, f: PackageFile) -> list[Evidence]:
        out = []
        rules = [
            (re.compile(r"\b(urlopen|urlretrieve|requests\.(get|post)|socket\.socket)\s*\("), "install_network", 0.55,
             "contacts the network at install time"),
            (re.compile(r"\b(os\.system|os\.popen|subprocess\.\w+)\s*\("), "install_process", 0.35,
             "starts another program at install time"),
        ]
        for rx, rule, w, msg in rules:
            m = rx.search(f.text)
            if m:
                ln = line_of(f.text, m.start())
                out.append(ev(NAME, rule, w, f"{f.path} {msg} (file does not parse, matched by pattern).", f, ln))
        return out

    def _pth(self, f: PackageFile) -> list[Evidence]:
        out = []
        for i, line in enumerate(f.text.splitlines(), 1):
            s = line.strip()
            if not s.startswith(("import ", "import\t")):
                continue
            if re.search(r"exec|eval|b64decode|urlopen|subprocess|os\.system|socket|__import__", s):
                out.append(ev(NAME, "pth_exec", 0.8,
                              f"{f.path} is a .pth file that runs code on every Python start-up and the code "
                              "executes or fetches something.", f, i))
            else:
                out.append(ev(NAME, "pth_import", 0.3,
                              f"{f.path} is a .pth file with an import line, which runs on every Python start-up.",
                              f, i))
        return out

    # --------------------------------------------------------------- npm

    def _npm(self, pkg: Package) -> list[Evidence]:
        pj = pkg.file("package.json")
        out: list[Evidence] = []
        for hook, cmd in pkg.install_scripts.items():
            line = _json_key_line(pj.text, hook) if pj else None
            snip = clip(f'"{hook}": "{cmd}"')
            if pkg.metadata.get("implicit_node_gyp") and hook == "install":
                out.append(ev(NAME, "npm_hook_build", 0.05,
                              "binding.gyp makes npm run node-gyp at install time (native build).",
                              pj, None, "binding.gyp"))
                continue
            if NPM_BENIGN.match(cmd):
                out.append(ev(NAME, "npm_hook_build", 0.05,
                              f"'{hook}' script runs a common build/setup tool.", pj, line, snip))
            elif SHELL_DROPPER.search(cmd):
                out.append(ev(NAME, "npm_hook_download_exec", 0.8,
                              f"'{hook}' script downloads or launches a shell command when the package is "
                              "installed.", pj, line, snip))
            elif re.search(r"\bnode\s+(-e|--eval|-p|--print)\b", cmd):
                out.append(ev(NAME, "npm_hook_inline_code", 0.45,
                              f"'{hook}' script runs inline JavaScript at install time.", pj, line, snip))
                out += self._js_text(pkg, pj, cmd, line, where=f"the '{hook}' script")
            elif re.search(r"\bnode\s+\S", cmd):
                out.append(ev(NAME, "npm_hook_runs_file", 0.2,
                              f"'{hook}' script runs a JavaScript file at install time.", pj, line, snip))
            else:
                out.append(ev(NAME, "npm_hook_other", 0.25,
                              f"'{hook}' script runs a command at install time.", pj, line, snip))
        return out

    def _js(self, f: PackageFile, where: str) -> list[Evidence]:
        return self._js_text(None, f, f.text, None, where)

    def _js_text(self, pkg, f: PackageFile | None, text: str, fixed_line: int | None, where: str) -> list[Evidence]:
        out: list[Evidence] = []

        def at(m: re.Match) -> tuple[int | None, str | None]:
            if fixed_line is not None:
                return fixed_line, clip(text.strip())
            ln = line_of(text, m.start())
            return ln, snippet_at(text, ln)

        m = JS_CHILD.search(text)
        if m:
            ln, sn = at(m)
            out.append(ev(NAME, "install_process", 0.35, f"Code in {where} can start other programs (child_process).",
                          f, ln, sn))
        for m in JS_EXEC_SHELL.finditer(text):
            if SHELL_DROPPER.search(m.group(1)):
                ln, sn = at(m)
                out.append(ev(NAME, "install_download_exec", 0.75,
                              f"Code in {where} runs a downloader or shell command.", f, ln, sn))
                break
        m = JS_NET.search(text)
        if m:
            ln, sn = at(m)
            hosts = {urlparse(u).hostname or "" for u in URL.findall(text)}
            if hosts and all(_is_known_host(h) for h in hosts):
                out.append(ev(NAME, "install_network_known_host", 0.25,
                              f"Code in {where} downloads from a well-known host ({', '.join(sorted(hosts))}).",
                              f, ln, sn))
            else:
                out.append(ev(NAME, "install_network", 0.55, f"Code in {where} uses the network.", f, ln, sn))
        return out

    def _shell_file(self, f: PackageFile) -> list[Evidence]:
        m = SHELL_DROPPER.search(f.text)
        if not m:
            return [ev(NAME, "install_shell_script", 0.2, f"{f.path} is a shell script run at install time.", f, 1)]
        ln = line_of(f.text, m.start())
        return [ev(NAME, "install_download_exec", 0.75,
                   f"{f.path} runs at install time and downloads or launches a shell command.", f, ln)]


def _is_known_host(host: str) -> bool:
    """Exact host or a real subdomain of it ("evilgithub.com" is not github.com)."""
    host = host.lower().rstrip(".")
    return any(host == k or host.endswith("." + k) for k in KNOWN_ARTIFACT_HOSTS)


def _json_key_line(text: str, key: str) -> int | None:
    m = re.search(r'"%s"\s*:' % re.escape(key), text)
    return line_of(text, m.start()) if m else None


def _is_read_of_local_file(call: ast.Call) -> bool:
    if not call.args:
        return False
    arg = call.args[0]
    src = ast.dump(arg)
    return ("attr='read'" in src or "attr='read_text'" in src) and ("id='open'" in src or "Path" in src) \
        and "urlopen" not in src and "b64decode" not in src


def _first_command_word(call: ast.Call) -> str:
    if not call.args:
        return ""
    a = call.args[0]
    if isinstance(a, (ast.List, ast.Tuple)) and a.elts:
        first = a.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.rsplit("/", 1)[-1].lower()
        if isinstance(first, ast.Attribute) and isinstance(first.value, ast.Name):
            return f"{first.value.id}.{first.attr}"
    if isinstance(a, ast.Constant) and isinstance(a.value, str):
        return a.value.split()[0].rsplit("/", 1)[-1].lower() if a.value.split() else ""
    return ""
