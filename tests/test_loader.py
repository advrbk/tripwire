"""Turning extracted files into a Package: roots, metadata, install files."""

import json
from pathlib import Path

from helpers import npm_pkg

from tripwire import loader
from tripwire.loader import load_package, package_from_texts


def write_tree(root: Path, files: dict[str, str | bytes]) -> list[str]:
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content.encode() if isinstance(content, str) else content)
    return list(files)


def test_sdist_root_folder_is_stripped(tmp_path):
    files = write_tree(tmp_path, {"demo-1.0/PKG-INFO": "Name: demo\nVersion: 1.0\nSummary: A demo\n",
                                  "demo-1.0/demo/__init__.py": "x = 1\n"})
    pkg = load_package(tmp_path, files)
    assert {f.path for f in pkg.files} == {"PKG-INFO", "demo/__init__.py"}
    assert (pkg.ecosystem, pkg.name, pkg.version) == ("pypi", "demo", "1.0")
    assert pkg.metadata["description"] == "A demo"


def test_npm_package_folder_is_stripped_and_detected(tmp_path):
    files = write_tree(tmp_path, {"package/package.json": json.dumps({"name": "demo", "version": "2.0.0"}),
                                  "package/index.js": "module.exports = 1;\n"})
    pkg = load_package(tmp_path, files)
    assert pkg.ecosystem == "npm" and pkg.name == "demo" and pkg.version == "2.0.0"


def test_wheel_layout_is_not_stripped(tmp_path):
    files = write_tree(tmp_path, {"demo/__init__.py": "", "demo-1.0.dist-info/METADATA": "Name: demo\nVersion: 1.0\n"})
    pkg = load_package(tmp_path, files)
    assert {f.path for f in pkg.files} == {"demo/__init__.py", "demo-1.0.dist-info/METADATA"}
    assert pkg.name == "demo"


def test_binary_and_non_text_files_are_counted_not_read(tmp_path):
    files = write_tree(tmp_path, {"p/a.py": "x = 1\n", "p/img.png": b"\x89PNG\r\n", "p/data.txt": b"ab\x00cd"})
    pkg = load_package(tmp_path, files, ecosystem="pypi", name="p", version="1")
    assert [f.path for f in pkg.files] == ["a.py"]  # the shared "p/" root is stripped
    assert pkg.binary_file_count == 2


def test_large_files_are_truncated(tmp_path, monkeypatch):
    monkeypatch.setattr(loader, "READ_LIMIT", 100)
    files = write_tree(tmp_path, {"p/big.py": "#" * 500})
    f = load_package(tmp_path, files, ecosystem="pypi").files[0]
    assert f.truncated and len(f.text) == 100 and f.size == 500


def test_unreadable_files_are_recorded(tmp_path, monkeypatch):
    files = write_tree(tmp_path, {"p/a.py": "x = 1\n", "p/b.py": "y = 2\n"})
    real = loader._read_text

    def flaky(path):
        if path.name == "b.py":
            raise OSError(22, "Invalid argument")  # what Windows returns when antivirus removed the file
        return real(path)

    monkeypatch.setattr(loader, "_read_text", flaky)
    pkg = load_package(tmp_path, files, ecosystem="pypi")
    assert pkg.unreadable == ["b.py"] and [f.path for f in pkg.files] == ["a.py"]


def test_npm_install_scripts_and_files():
    pkg = npm_pkg({"preinstall": "node ./scripts/pre.js", "postinstall": "sh ./bin/setup.sh", "test": "jest"},
                  {"scripts/pre.js": "", "bin/setup.sh": "", "index.js": ""})
    assert set(pkg.install_scripts) == {"preinstall", "postinstall"}
    assert pkg.install_files == {"package.json", "scripts/pre.js", "bin/setup.sh"}


def test_npm_node_ref_without_extension():
    pkg = npm_pkg({"install": "node install"}, {"install.js": ""})
    assert "install.js" in pkg.install_files
    pkg = npm_pkg({"install": "node lib"}, {"lib/index.js": ""})
    assert "lib/index.js" in pkg.install_files


def test_npm_dotfile_reference_keeps_its_dot():
    # bug fix: str.lstrip("./") turned ".hooks/run.js" into "hooks/run.js"
    pkg = npm_pkg({"postinstall": "node .hooks/run.js"}, {".hooks/run.js": "", "hooks/run.js": ""})
    assert ".hooks/run.js" in pkg.install_files and "hooks/run.js" not in pkg.install_files


def test_npm_node_flags_are_skipped():
    pkg = npm_pkg({"postinstall": "node --max-old-space-size=4096 build.js"}, {"build.js": ""})
    assert "build.js" in pkg.install_files


def test_empty_scripts_are_ignored():
    assert npm_pkg({"postinstall": "   "}).install_scripts == {}


def test_bad_package_json():
    pkg = package_from_texts({"package.json": "{not json", "index.js": ""}, "npm")
    assert pkg.metadata["parse_error"] and pkg.install_scripts == {}


def test_package_json_that_is_not_an_object():
    pkg = package_from_texts({"package.json": "[1, 2]"}, "npm")
    assert pkg.install_scripts == {} and pkg.name == "unknown"


def test_setup_kwargs_are_read_without_running():
    pkg = package_from_texts({"setup.py": 'from setuptools import setup\nsetup(name="from-setup", version="3.1")\n'},
                             "pypi")
    assert (pkg.name, pkg.version) == ("from-setup", "3.1")
    assert pkg.install_files == {"setup.py"}


def test_setup_with_syntax_error_still_loads():
    pkg = package_from_texts({"setup.py": "setup(name=\n"}, "pypi")
    assert pkg.name == "unknown" and "setup.py" in pkg.install_files


def test_local_imports_from_setup_are_install_files():
    pkg = package_from_texts({
        "setup.py": "import buildhelp\nfrom tools.gen import go\nimport os\nsetup()\n",
        "buildhelp.py": "", "tools/gen/__init__.py": "", "tools/other.py": "",
    }, "pypi")
    assert pkg.install_files == {"setup.py", "buildhelp.py", "tools/gen/__init__.py"}


def test_pth_files_are_install_files():
    pkg = package_from_texts({"x.pth": "import y\n", "y.py": ""}, "pypi")
    assert pkg.install_files == {"x.pth"}


def test_explicit_name_and_version_win():
    pkg = package_from_texts({"PKG-INFO": "Name: meta\nVersion: 1\n"}, "pypi", name="given", version="9")
    assert (pkg.name, pkg.version) == ("given", "9")


def test_code_files_include_install_files():
    pkg = npm_pkg({"postinstall": "node x.js"}, {"x.js": "", "README.md": "", "a.ts": ""})
    assert {f.path for f in pkg.code_files()} == {"x.js", "a.ts", "package.json"}
