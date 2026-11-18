"""Small builders shared by the tests.

Analyser tests build packages in memory with ``package_from_texts`` so no
suspicious-looking text is ever written to disk. Archive tests build real
archives in memory; their contents are benign, because what they test is the
archive *format* (paths, links, sizes), not the code inside.
"""

from __future__ import annotations

import io
import json
import tarfile
import zipfile

from tripwire.loader import package_from_texts
from tripwire.models import FIRE_THRESHOLD, Evidence, Package


def py_pkg(files: dict[str, str], name: str = "sample-lib", version: str = "1.0.0") -> Package:
    return package_from_texts(files, "pypi", name, version)


def npm_pkg(scripts: dict[str, str] | None = None, files: dict[str, str] | None = None,
            name: str = "sample-lib", version: str = "1.0.0", **extra) -> Package:
    data = {"name": name, "version": version, **extra}
    if scripts:
        data["scripts"] = scripts
    return package_from_texts({"package.json": json.dumps(data, indent=2), **(files or {})}, "npm", name, version)


def rules(evidence: list[Evidence], min_weight: float = 0.0) -> set[str]:
    return {e.rule for e in evidence if e.weight >= min_weight}


def fired(evidence: list[Evidence]) -> set[str]:
    return {e.rule for e in evidence if e.weight >= FIRE_THRESHOLD}


def weight_of(evidence: list[Evidence], rule: str) -> float:
    return max(e.weight for e in evidence if e.rule == rule)


def tar_with(members: list[tarfile.TarInfo | tuple[str, bytes]], mode: str = "w:gz") -> bytes:
    """Members are (name, data) for regular files or ready TarInfo objects (links, devices)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for m in members:
            if isinstance(m, tarfile.TarInfo):
                tf.addfile(m)
            else:
                name, data = m
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def zip_with(members: list[tuple[str, bytes] | zipfile.ZipInfo | tuple[zipfile.ZipInfo, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for m in members:
            if isinstance(m, tuple) and isinstance(m[0], zipfile.ZipInfo):
                zf.writestr(m[0], m[1])
            else:
                name, data = m
                zf.writestr(name, data)
    return buf.getvalue()


def link_member(name: str, target: str, hard: bool = False) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.LNKTYPE if hard else tarfile.SYMTYPE
    info.linkname = target
    return info
