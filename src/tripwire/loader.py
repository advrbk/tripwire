"""Turn an extracted release into a :class:`Package` the analysers can read.

This reads files as bytes and decodes them as text. It never imports or runs
them. ``setup.py`` and ``package.json`` are parsed as data only (``ast`` and
``json``), which cannot execute code.
"""

from __future__ import annotations

import ast
import json
import re
from email.parser import HeaderParser
from pathlib import Path

from .models import CODE_SUFFIXES, Package, PackageFile

READ_LIMIT = 2 * 1024 * 1024  # analyse at most 2 MB of any one file
TEXT_SUFFIXES = CODE_SUFFIXES | {
    ".json", ".toml", ".cfg", ".ini", ".txt", ".md", ".rst", ".yml", ".yaml", ".html",
    ".gyp", ".gypi", ".in", ".xml", ".css", "",
}
NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def _read_text(path: Path) -> tuple[str, bool] | None:
    with open(path, "rb") as fh:
        raw = fh.read(READ_LIMIT + 1)
    truncated = len(raw) > READ_LIMIT
    raw = raw[:READ_LIMIT]
    if b"\x00" in raw[:8192]:
        return None  # binary
    return raw.decode("utf-8", errors="replace"), truncated


def _strip_common_root(paths: list[str]) -> str:
    """sdists use 'name-1.0/', npm tarballs use 'package/'. Find that prefix."""
    tops = {p.split("/", 1)[0] for p in paths if "/" in p}
    if len(tops) == 1 and all("/" in p for p in paths):
        return tops.pop() + "/"
    return ""


def load_package(root: Path, files: list[str], ecosystem: str | None = None,
                 name: str | None = None, version: str | None = None,
                 blocked: list[tuple[str, str]] | None = None,
                 disk_paths: dict[str, Path] | None = None) -> Package:
    """``disk_paths`` maps a relative path to where the extractor actually
    wrote it, for files that could not live at ``root/<rel>`` (name collisions)."""
    prefix = _strip_common_root(files)
    disk_paths = disk_paths or {}
    pkg_files: list[PackageFile] = []
    binary = 0
    unreadable: list[str] = []
    for rel in sorted(files):
        disk = disk_paths.get(rel, root / rel)
        short = rel[len(prefix):] if prefix and rel.startswith(prefix) else rel
        suffix = "." + short.rsplit(".", 1)[-1].lower() if "." in short.rsplit("/", 1)[-1] else ""
        if suffix not in TEXT_SUFFIXES and not short.endswith("PKG-INFO") and not short.endswith("METADATA"):
            binary += 1
            continue
        try:
            got = _read_text(disk)
            size = disk.stat().st_size
        except OSError:
            # The file was written a moment ago, so this is almost always an
            # antivirus removing or locking it. Record it instead of hiding it.
            unreadable.append(short)
            continue
        if got is None:
            binary += 1
            continue
        text, truncated = got
        pkg_files.append(PackageFile(path=short, text=text, size=size, truncated=truncated))

    if ecosystem is None:
        ecosystem = "npm" if any(f.path == "package.json" for f in pkg_files) or "package.json" in unreadable \
            else "pypi"
    pkg = Package(ecosystem=ecosystem, name=name or "", version=version or "", files=pkg_files,
                  blocked_entries=list(blocked or []), binary_file_count=binary, unreadable=unreadable)
    return _finish(pkg, name, version)


def package_from_texts(files: dict[str, str], ecosystem: str | None = None, name: str | None = None,
                       version: str | None = None) -> Package:
    """Build a Package straight from {path: text}, without touching the disk.

    Same metadata and install-file logic as :func:`load_package`. Used by tests
    and by anything that already holds file contents in memory.
    """
    pkg_files = [PackageFile(path=p, text=t, size=len(t.encode("utf-8"))) for p, t in sorted(files.items())]
    if ecosystem is None:
        ecosystem = "npm" if "package.json" in files else "pypi"
    pkg = Package(ecosystem=ecosystem, name=name or "", version=version or "", files=pkg_files)
    return _finish(pkg, name, version)


def _finish(pkg: Package, name: str | None, version: str | None) -> Package:
    if pkg.ecosystem == "npm":
        _load_npm(pkg)
    else:
        _load_pypi(pkg)
    pkg.name = name or pkg.metadata.get("name") or "unknown"
    pkg.version = version or str(pkg.metadata.get("version") or "0")
    return pkg


# --------------------------------------------------------------------- npm

_NODE_FILE = re.compile(r"\bnode\s+(?:--?[\w-]+(?:=\S+)?\s+)*([\w./@-]+)")


def _load_npm(pkg: Package) -> None:
    pj = pkg.file("package.json")
    if pj is None:
        return
    try:
        data = json.loads(pj.text)
    except ValueError:
        pkg.metadata["parse_error"] = "package.json is not valid JSON"
        return
    if not isinstance(data, dict):
        return
    pkg.metadata.update({k: data.get(k) for k in ("name", "version", "description", "repository",
                                                    "homepage", "author", "license", "main")})
    scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
    for hook in NPM_INSTALL_HOOKS:
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and cmd.strip():
            pkg.install_scripts[hook] = cmd
    # npm runs "node-gyp rebuild" by itself when binding.gyp exists and no install script is set
    if "install" not in pkg.install_scripts and "preinstall" not in pkg.install_scripts and pkg.file("binding.gyp"):
        pkg.install_scripts["install"] = "node-gyp rebuild"
        pkg.metadata["implicit_node_gyp"] = True
    pkg.install_files.add("package.json")
    known = {f.path for f in pkg.files}
    for cmd in pkg.install_scripts.values():
        for m in _NODE_FILE.finditer(cmd):
            ref = _relative_ref(m.group(1))
            for candidate in (ref, ref + ".js", ref + "/index.js"):
                if candidate in known:
                    pkg.install_files.add(candidate)
                    break
        for m in re.finditer(r"([\w./-]+\.(?:sh|ps1|bat|cmd|py))\b", cmd):
            ref = _relative_ref(m.group(1))
            if ref in known:
                pkg.install_files.add(ref)


def _relative_ref(ref: str) -> str:
    """'./scripts/x.js' -> 'scripts/x.js'. (str.lstrip('./') would also eat '.hidden.js'.)"""
    while ref.startswith("./"):
        ref = ref[2:]
    return ref


# -------------------------------------------------------------------- PyPI

def _load_pypi(pkg: Package) -> None:
    meta_file = pkg.file("PKG-INFO") or next(
        (f for f in pkg.files if f.path.endswith(".dist-info/METADATA")), None)
    if meta_file is not None:
        headers = HeaderParser().parsestr(meta_file.text)
        for key in ("Name", "Version", "Summary", "Home-page", "Author"):
            if headers.get(key):
                pkg.metadata[key.lower()] = headers[key]
        pkg.metadata["description"] = pkg.metadata.get("summary")
    setup = pkg.file("setup.py")
    if setup is not None:
        pkg.install_files.add("setup.py")
        if "name" not in pkg.metadata or "version" not in pkg.metadata:
            _setup_kwargs(setup.text, pkg.metadata)
        # Local modules imported by setup.py also run at install time.
        try:
            tree = ast.parse(setup.text)
        except (SyntaxError, ValueError):
            tree = None
        if tree is not None:
            known = {f.path for f in pkg.files}
            for node in ast.walk(tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    mods = [node.module]
                for mod in mods:
                    path = mod.replace(".", "/")
                    for cand in (path + ".py", path + "/__init__.py"):
                        if cand in known:
                            pkg.install_files.add(cand)
    # .pth files in site-packages are executed by Python at every start-up
    # when a line begins with "import". Any shipped .pth is worth reading.
    for f in pkg.files:
        if f.suffix == ".pth":
            pkg.install_files.add(f.path)


def _setup_kwargs(text: str, out: dict) -> None:
    """Read literal name=/version= from a setup() call without running it."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            fname = fn.id if isinstance(fn, ast.Name) else fn.attr if isinstance(fn, ast.Attribute) else ""
            if fname != "setup":
                continue
            for kw in node.keywords:
                if kw.arg in ("name", "version", "description") and isinstance(kw.value, ast.Constant) \
                        and isinstance(kw.value.value, str):
                    out.setdefault(kw.arg, kw.value.value)
