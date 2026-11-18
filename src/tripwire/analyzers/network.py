"""Network destinations that legitimate libraries rarely hard-code.

Ordinary URLs (docs, homepages, APIs) are ignored. What gets flagged is the
short list of places stolen data usually goes: chat webhooks, paste sites,
request catchers and tunnels, raw IP addresses, and DNS lookups built from
data (DNS exfiltration).

One rule looks at data flow instead of destinations: the *whole* environment
(``os.environ`` / ``process.env`` as a mapping, not one named variable) ending
up in a network call. A client sending its own ``API_TOKEN`` in a header is
normal; posting every environment variable somewhere is not.
"""

from __future__ import annotations

import ast
import ipaddress
import re

from ..models import Evidence, Package, PackageFile
from .base import DOC_NAMES, ImportMap, ev, fold, has_any, is_js, is_python, line_of, parse_python, snippet_at

NAME = "network"

ENDPOINTS: list[tuple[str, re.Pattern[str], float, str]] = [
    ("discord_webhook", re.compile(r"discord(?:app)?\.com/api/webhooks/", re.I), 0.6, "a Discord webhook"),
    ("telegram_bot", re.compile(r"api\.telegram\.org/bot", re.I), 0.6, "the Telegram bot API"),
    ("request_catcher", re.compile(
        r"\b(?:webhook\.site|requestbin\.(?:net|com)|[\w-]+\.m\.pipedream\.net|pipedream\.net|"
        r"[\w.-]*\.?(?:oast\.(?:fun|me|pro|live|site|online)|interact\.sh|burpcollaborator\.net|"
        r"canarytokens\.com|dnslog\.cn|ceye\.io))\b", re.I), 0.65, "a request-catcher / out-of-band testing service"),
    ("tunnel", re.compile(r"\b[\w-]+\.(?:ngrok(?:-free)?\.(?:io|app|dev)|trycloudflare\.com|serveo\.net|"
                          r"loca\.lt|localhost\.run)\b", re.I), 0.55, "a tunnelling service"),
    ("paste_site", re.compile(r"\b(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co/[\w-]+/raw|"
                              r"ghostbin\.\w+|transfer\.sh|termbin\.com|0x0\.st|paste\.c-net\.org)\b", re.I),
     0.5, "a paste / anonymous file host"),
]
RAW_IP_URL = re.compile(r"""\b(?:https?|ftp|tcp|wss?)://((?:\d{1,3}\.){3}\d{1,3})(?::\d+)?""", re.I)
RAW_IP_CONNECT = re.compile(r"""(?:connect|create_connection|createConnection|Socket)\s*\(\s*\(?\s*['"]((?:\d{1,3}\.){3}\d{1,3})['"]""")
DNS_EXFIL = re.compile(
    r"""(?:gethostbyname|getaddrinfo|dns\.(?:lookup|resolve\w*)|resolver\.(?:resolve|query)|nslookup|dig\s)"""
    r"""\s*\(?\s*(?:f['"][^'"]*\{[^}]+\}[^'"]*\.[a-z]{2,}|[^\n]{0,80}?\+\s*['"]\.[\w.-]+\.[a-z]{2,}['"]|"""
    r"""[`][^`]*\$\{[^}]+\}\.[\w.-]+[`]|['"][^'"]*['"]\s*%\s*\(?[\w.]+|[\w.()]+\.format\(|"""
    # "{}.evil.example".format(data): the old pattern only matched name.format(...)
    r"""['"][^'"]*\{[^}]*\}[^'"]*\.[a-z]{2,}['"]\.format\()""",
    re.I,
)
# Literals each pattern needs (lower case). Used only to skip hopeless regex
# searches; see base.has_any.
ENDPOINT_KEYS = {
    "discord_webhook": ("/api/webhooks/",),
    "telegram_bot": ("api.telegram.org",),
    "request_catcher": ("webhook.site", "requestbin.", "pipedream.net", "oast.", "interact.sh",
                        "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io"),
    "tunnel": ("ngrok", "trycloudflare.com", "serveo.net", "loca.lt", "localhost.run"),
    "paste_site": ("pastebin.com/raw", "paste.ee/r", "hastebin.com/raw", "rentry.co/", "ghostbin.", "transfer.sh",
                   "termbin.com", "0x0.st", "paste.c-net.org"),
}
IP_KEYS = ("://", "connect", "socket")
DNS_KEYS = ("gethostbyname", "getaddrinfo", "dns.", "resolver.", "nslookup", "dig")
PRIVATE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
IGNORE_FILES = (".md", ".rst", ".txt", ".html")

# Python calls that send data somewhere. Method names are matched on any object
# (session.post, sock.sendall) because the receiver's type is unknown statically.
PY_SEND_TARGETS = ("requests.", "httpx.", "urllib.request.urlopen", "urllib.request.Request", "aiohttp.",
                   "urllib3.", "http.client.")
# Only names that are unambiguous on an unknown object. "put", "patch" and
# "request" are too common on caches, stores and queues (a live run flagged a
# local artifact store's .put()), so they count only via PY_SEND_TARGETS.
PY_SEND_METHODS = {"post", "sendall", "sendto", "urlopen"}
JS_BARE_ENV = re.compile(r"process\.env(?![\w$.\[])")
# "env: process.env" and "...process.env" hand the environment to a child process
# (spawn/exec options). That is ordinary and was the main false positive live.
JS_CHILD_ENV_BEFORE = re.compile(r"(?:\.\.\.|\benv\s*:\s*)$")
JS_SEND = re.compile(r"\bfetch\s*\(|\b(?:https?|http2)\.request\s*\(|\baxios(?:\.(?:post|put|request))?\s*\(|"
                     r"\.(?:write|end|send)\s*\(\s*JSON\.stringify")


def _ip_kind(ip: str) -> str | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified or addr.is_multicast or str(addr).startswith("255."):
        return None
    if any(addr in n for n in PRIVATE):
        return "private"
    return "public"


class NetworkAnalyzer:
    name = NAME

    def analyze(self, pkg: Package) -> list[Evidence]:
        out: list[Evidence] = []
        for f in pkg.files:
            if f.suffix in IGNORE_FILES or f.basename.upper().startswith(DOC_NAMES):
                continue
            install = f.path in pkg.install_files
            out += self._scan(f, install)
        return out

    def _scan(self, f: PackageFile, install: bool) -> list[Evidence]:
        out = []
        text = f.text
        low = fold(text)
        bump = 0.1 if install else 0.0
        for rule, rx, w, label in ENDPOINTS:
            m = rx.search(text) if has_any(low, ENDPOINT_KEYS[rule]) else None
            if m:
                ln = line_of(text, m.start())
                out.append(ev(NAME, rule, w + bump, f"{f.path} sends to or loads from {label}.", f, ln))
        seen_ip = False
        for rx in (RAW_IP_URL, RAW_IP_CONNECT) if has_any(low, IP_KEYS) else ():
            for m in rx.finditer(text):
                kind = _ip_kind(m.group(1))
                if kind is None:
                    continue
                ln = line_of(text, m.start())
                if kind == "public":
                    out.append(ev(NAME, "raw_ip", 0.45 + bump,
                                  f"{f.path} talks to a hard-coded IP address ({m.group(1)}) instead of a domain.",
                                  f, ln))
                else:
                    out.append(ev(NAME, "private_ip", 0.1,
                                  f"{f.path} mentions a private-network IP address ({m.group(1)}).", f, ln))
                seen_ip = True
                break
            if seen_ip:
                break
        if is_python(f) and "environ" in text:
            out += self._py_env_sent(f, install)
        elif is_js(f) and "process.env" in text:
            out += self._js_env_sent(f, install)
        m = DNS_EXFIL.search(text) if has_any(low, DNS_KEYS) else None
        if m:
            ln = line_of(text, m.start())
            out.append(ev(NAME, "dns_exfil", 0.6 + bump,
                          f"{f.path} looks up a hostname built from data, a common way to leak data over DNS.",
                          f, ln, snippet_at(text, ln)))
        return out

    # ------------------------------------------------- whole-environment flow

    def _py_env_sent(self, f: PackageFile, install: bool) -> list[Evidence]:
        tree = parse_python(f)
        if tree is None:
            return []
        imports = ImportMap(tree)
        module_taint = _taint(_scope_nodes(tree), set(), imports)
        scopes = [(tree, module_taint)]
        for fn in ast.walk(tree):
            if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = {a.arg for a in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs)}
                inherited = module_taint - params  # a parameter shadows a module-level name
                scopes.append((fn, _taint(_scope_nodes(fn), inherited, imports)))
        for scope, tainted in scopes:
            for node in _scope_nodes(scope):
                if not isinstance(node, ast.Call):
                    continue
                target = imports.dotted(node.func)
                method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
                if not (target.startswith(PY_SEND_TARGETS) or method in PY_SEND_METHODS):
                    continue
                payload = [*node.args, *(k.value for k in node.keywords)]
                if any(_carries_whole_env(a, tainted, imports) for a in payload):
                    return [ev(NAME, "env_sent", 0.65 + (0.1 if install else 0.0),
                               f"{f.path} sends the whole environment (every variable, including any secrets) "
                               "over the network.", f, node.lineno)]
        return []

    def _js_env_sent(self, f: PackageFile, install: bool) -> list[Evidence]:
        env = next((m for m in JS_BARE_ENV.finditer(f.text)
                    if not JS_CHILD_ENV_BEFORE.search(f.text[max(0, m.start() - 12):m.start()])), None)
        if not env:
            return []
        send = JS_SEND.search(f.text)
        if not send:
            return []
        ln = line_of(f.text, env.start())
        return [ev(NAME, "env_sent", 0.55 + (0.1 if install else 0.0),
                   f"{f.path} handles the whole process.env object and also sends data over the network.",
                   f, ln)]


def _is_whole_environ(node: ast.AST, imports: ImportMap) -> bool:
    return isinstance(node, (ast.Attribute, ast.Name)) and imports.dotted(node) == "os.environ"


def _scope_nodes(scope: ast.AST) -> list[ast.AST]:
    """Nodes that belong to one scope: nested functions are their own scopes."""
    out: list[ast.AST] = []
    stack = list(ast.iter_child_nodes(scope))
    while stack:
        node = stack.pop()
        out.append(node)
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(ast.iter_child_nodes(node))
    return out


def _taint(nodes: list[ast.AST], start: set[str], imports: ImportMap) -> set[str]:
    """Names in one scope that hold the whole environment, followed through a few assignments."""
    tainted = set(start)
    assigns = [n for n in nodes if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for _ in range(3):  # env -> data -> payload chains
        for node in assigns:
            if node.value is None or not _carries_whole_env(node.value, tainted, imports):
                continue
            for tgt in node.targets if isinstance(node, ast.Assign) else [node.target]:
                tainted.update(n.id for n in ast.walk(tgt) if isinstance(n, ast.Name))
    return tainted


def _carries_whole_env(expr: ast.AST, tainted: set[str], imports: ImportMap) -> bool:
    """True if ``expr`` contains os.environ used as a whole, or a name already tainted.

    ``os.environ["HOME"]`` and ``os.environ.get("X")`` read one value and do not
    count, and neither do the same reads through a tainted alias (``env.get("X")``).
    """
    parents: dict[int, ast.AST] = {}
    for parent in ast.walk(expr):
        for child in ast.iter_child_nodes(parent):
            parents[id(child)] = parent
    for n in ast.walk(expr):
        whole = _is_whole_environ(n, imports) or (
            isinstance(n, ast.Name) and n.id in tainted and isinstance(n.ctx, ast.Load))
        if whole:
            up = parents.get(id(n))
            if isinstance(up, ast.Subscript) and up.value is n:
                continue  # os.environ["X"]
            if isinstance(up, ast.Attribute) and up.attr in ("get", "setdefault", "pop", "__getitem__"):
                continue  # os.environ.get("X")
            return True
    return False
