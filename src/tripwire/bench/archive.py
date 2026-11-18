"""Pack a dict of {path: text} into real package archives, in memory.

Used by the benchmark and the tests. The archives are ordinary sdists, wheels
and npm tarballs, so they go through exactly the same extraction and loading
code as a download from a registry.
"""

from __future__ import annotations

import io
import json
import tarfile
import time
import zipfile

from .corpus import Fixture

FIXED_MTIME = 1_700_000_000  # reproducible archives


def tar_gz(files: dict[str, str | bytes], prefix: str = "") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, content in files.items():
            data = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(prefix + path)
            info.size = len(data)
            info.mtime = FIXED_MTIME
            info.mode = 0o644
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_bytes(files: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            info = zipfile.ZipInfo(path, date_time=time.gmtime(FIXED_MTIME)[:6])
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, content)
    return buf.getvalue()


def package_json(fx: Fixture) -> str:
    data: dict = {"name": fx.name, "version": fx.version, "main": "index.js", "license": "MIT"}
    if fx.description:
        data["description"] = fx.description
    if fx.scripts:
        data["scripts"] = fx.scripts
    return json.dumps(data, indent=2) + "\n"


def pkg_info(fx: Fixture) -> str:
    lines = ["Metadata-Version: 2.1", f"Name: {fx.name}", f"Version: {fx.version}"]
    if fx.description:
        lines.append(f"Summary: {fx.description}")
    return "\n".join(lines) + "\n"


def build(fx: Fixture) -> tuple[str, bytes]:
    """Return (file name, archive bytes) for a fixture."""
    if fx.kind == "npm":
        files = {"package.json": package_json(fx), **fx.files}
        return f"{fx.name.replace('/', '-').lstrip('@')}-{fx.version}.tgz", tar_gz(files, "package/")
    dist = fx.name.replace("-", "_")
    if fx.kind == "wheel":
        info = f"{dist}-{fx.version}.dist-info/"
        files = {**fx.files, info + "METADATA": pkg_info(fx), info + "RECORD": "", info + "WHEEL":
                 "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
        return f"{dist}-{fx.version}-py3-none-any.whl", zip_bytes(files)
    files = {"PKG-INFO": pkg_info(fx), **fx.files}
    return f"{fx.name}-{fx.version}.tar.gz", tar_gz(files, f"{fx.name}-{fx.version}/")
