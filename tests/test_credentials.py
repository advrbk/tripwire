"""credentials: reads of keys, tokens, browser data, wallets; environment harvesting."""

import pytest
from helpers import fired, npm_pkg, py_pkg, rules, weight_of

from tripwire.analyzers.credentials import CredentialsAnalyzer

A = CredentialsAnalyzer()


@pytest.mark.parametrize("code,rule", [
    ('open(os.path.expanduser("~/.ssh/id_rsa")).read()', "ssh_keys"),
    ('Path.home() / ".aws/credentials"', "cloud_credentials"),
    ('Path.home() / ".kube/config"', "cloud_credentials"),
    ('os.path.join(HOME, ".npmrc")', "registry_tokens"),
    ('os.path.join(HOME, ".git-credentials")', "registry_tokens"),
    ('os.path.join(LOCAL, "Google", "Chrome", "User Data", "Default", "Login Data")', "browser_data"),
    ('os.path.join(HOME, ".mozilla/firefox")', "browser_data"),
    ('os.path.join(HOME, ".bitcoin", "wallet.dat")', "crypto_wallets"),
    ('r"%APPDATA%\\discord\\Local Storage\\leveldb"', "chat_tokens"),
    ('Path.home() / ".bash_history"', "shell_history"),
])
def test_secret_paths(code, rule):
    ev = A.analyze(py_pkg({"p/x.py": f"X = {code}\n"}))
    assert rule in fired(ev)


def test_install_time_reference_weighs_more():
    runtime = weight_of(A.analyze(py_pkg({"p/x.py": 'P = "~/.ssh/id_rsa"\n'})), "ssh_keys")
    install = weight_of(A.analyze(py_pkg({"setup.py": 'P = "~/.ssh/id_rsa"\n'})), "ssh_keys")
    assert install == pytest.approx(runtime + 0.1)


def test_one_finding_per_rule_per_file():
    src = 'A = "~/.ssh/id_rsa"\nB = "~/.ssh/id_ed25519"\nC = "~/.ssh/known_hosts"\n'
    ev = A.analyze(py_pkg({"p/x.py": src}))
    assert sum(1 for e in ev if e.rule == "ssh_keys") == 1


@pytest.mark.parametrize("code,weight", [
    ("json.dumps(os.environ)", 0.55),
    ("json.dumps(dict(os.environ))", 0.55),
    ("str(os.environ)", 0.5),
    ("urlencode(dict(os.environ))", 0.5),
])
def test_env_serialisation(code, weight):
    ev = A.analyze(py_pkg({"p/x.py": f"import os, json\nX = {code}\n"}))
    assert weight_of(ev, "env_harvest") == weight


def test_js_stringify_env():
    ev = A.analyze(npm_pkg(files={"index.js": "const s = JSON.stringify(process.env);\n"}))
    assert weight_of(ev, "env_harvest") == 0.55


def test_walking_env_is_context():
    ev = A.analyze(py_pkg({"p/x.py": "import os\nfor k, v in os.environ.items():\n    pass\n"}))
    assert rules(ev) == {"env_harvest"} and fired(ev) == set()


def test_three_secret_env_names():
    src = 'import os\nK = [os.environ.get(n) for n in ("AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "NPM_TOKEN")]\n'
    assert weight_of(A.analyze(py_pkg({"p/x.py": src})), "secret_env_names") == 0.35


# ------------------------------------------------------------- benign near-misses

def test_reading_home_is_benign():
    src = 'import os\nBASE = os.path.join(os.environ["HOME"], ".config")\nX = os.environ.get("XDG_CONFIG_HOME")\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_two_secret_env_names_is_benign():
    src = 'import os\nA = os.environ.get("GITHUB_TOKEN")\nB = os.environ.get("NPM_TOKEN")\n'
    assert A.analyze(py_pkg({"p/x.py": src})) == []


def test_browser_name_alone_is_benign():
    src = 'const path = require("path");\nmodule.exports = path.join(cacheDir, "Google Chrome for Testing");\n'
    assert A.analyze(npm_pkg(files={"index.js": src})) == []


def test_copy_of_env_for_subprocess_is_below_context():
    ev = A.analyze(py_pkg({"p/x.py": "import os\nenv = dict(os.environ)\n"}))
    assert fired(ev) == set()


def test_docs_and_licenses_are_skipped():
    ev = A.analyze(py_pkg({"README.md": "Put your key in ~/.ssh/id_rsa\n", "LICENSE": "~/.aws/credentials\n"}))
    assert ev == []


def test_known_weakness_ssh_config_tool_fires():
    # Documented weakness: a path is a capability, not proof. A deployment tool
    # that edits ~/.ssh/config is flagged just like a stealer would be.
    ev = A.analyze(npm_pkg(files={"index.js": 'const p = path.join(os.homedir(), ".ssh/config");\n'}))
    assert "ssh_keys" in fired(ev)


def test_property_named_ssh_is_not_a_path():
    # live-run false positive: "before.ssh === undefined" matched the old pattern
    src = "if (before.ssh === undefined) delete process.env.WORKER_SSH;\nconst t = cfg.ssh ? 1 : 0;\n"
    assert A.analyze(npm_pkg(files={"index.js": src})) == []


@pytest.mark.parametrize("code", ['"~/.ssh/id_ed25519"', 'path.join(home, ".ssh")', 'Path.home() / ".ssh" / "config"',
                                  "'C:\\Users\\x\\.ssh\\id_rsa'"])
def test_ssh_paths_still_match(code):
    assert "ssh_keys" in fired(A.analyze(py_pkg({"p/x.py": f"X = {code}\n"})))


def test_package_metadata_prose_is_skipped():
    # PKG-INFO / METADATA carry the README; a table mentioning ~/.ssh is documentation.
    desc = "Name: x\nVersion: 1\n\n| `X_KNOWN_HOSTS` | `~/.ssh/known_hosts` | where host keys go |\n"
    ev = A.analyze(py_pkg({"PKG-INFO": desc, "x.egg-info/PKG-INFO": desc, "x-1.dist-info/METADATA": desc}))
    assert ev == []
