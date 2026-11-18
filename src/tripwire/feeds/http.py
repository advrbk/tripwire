"""A small HTTP client that is polite to public registries.

* Identifies itself with a fixed User-Agent.
* Waits a minimum interval between requests to the same host.
* Retries 429 / 5xx with backoff and honours ``Retry-After``.
* Streams downloads to disk with a hard byte cap.

Tests pass an ``httpx.MockTransport`` so nothing touches the network.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import httpx

from .. import USER_AGENT


class DownloadTooLarge(Exception):
    pass


class DownloadRefused(Exception):
    """The artifact URL points somewhere Tripwire does not download from."""


# Archives are only fetched from the registries' own file hosts, over HTTPS.
# A release's metadata names its download URL, so without this check a crafted
# record could make the watcher fetch from (or probe) any address.
DOWNLOAD_HOSTS = frozenset({"files.pythonhosted.org", "registry.npmjs.org"})


def check_download_url(url: str, allowed: frozenset[str] = DOWNLOAD_HOSTS) -> None:
    parts = urlparse(url)
    if parts.scheme != "https" or (parts.hostname or "") not in allowed:
        raise DownloadRefused(f"refusing to download from {parts.scheme}://{parts.hostname}")


class PoliteClient:
    def __init__(self, *, min_interval: float = 0.5, per_host: dict[str, float] | None = None,
                 transport: httpx.BaseTransport | None = None, timeout: float = 30.0, retries: int = 3,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self._client = httpx.Client(headers={"User-Agent": USER_AGENT, "Accept-Encoding": "gzip"},
                                    timeout=timeout, follow_redirects=True, transport=transport)
        self.min_interval = min_interval
        self.per_host = per_host or {}
        self.retries = retries
        self._last: dict[str, float] = {}
        self._sleep = sleep
        self._clock = clock
        self.request_count = 0

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "PoliteClient":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _wait_turn(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        gap = self.per_host.get(host, self.min_interval)
        last = self._last.get(host)
        now = self._clock()
        if last is not None and now - last < gap:
            self._sleep(gap - (now - last))
        self._last[host] = self._clock()

    def _send(self, method: str, url: str, *, stream: bool = False, follow_redirects: bool = True,
              **kw) -> httpx.Response:
        delay = 1.0
        for attempt in range(self.retries + 1):
            self._wait_turn(url)
            self.request_count += 1
            try:
                req = self._client.build_request(method, url, **kw)
                resp = self._client.send(req, stream=stream, follow_redirects=follow_redirects)
            except httpx.TransportError:
                if attempt == self.retries:
                    raise
                self._sleep(delay)
                delay *= 2
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt == self.retries:
                    return resp
                retry_after = resp.headers.get("Retry-After", "")
                wait = float(retry_after) if retry_after.isdigit() else delay
                resp.close()
                self._sleep(min(wait, 60.0))
                delay *= 2
                continue
            return resp
        raise RuntimeError("unreachable")  # pragma: no cover

    def get_json(self, url: str, max_bytes: int = 20 * 1024 * 1024, **kw) -> object:
        return json.loads(self.get_text(url, max_bytes=max_bytes, **kw))

    def get_text(self, url: str, max_bytes: int = 5 * 1024 * 1024, **kw) -> str:
        resp = self._send("GET", url, stream=True, **kw)
        try:
            resp.raise_for_status()
            chunks, total = [], 0
            for chunk in resp.iter_bytes():
                total += len(chunk)
                if total > max_bytes:
                    raise DownloadTooLarge(f"{url} is larger than {max_bytes} bytes")
                chunks.append(chunk)
            return b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")
        finally:
            resp.close()

    def download(self, url: str, dest: Path, max_bytes: int,
                 allowed_hosts: frozenset[str] = DOWNLOAD_HOSTS) -> int:
        """Stream ``url`` to ``dest``. Stops as soon as ``max_bytes`` is passed.

        Redirects are not followed here, so the host check cannot be bypassed.
        """
        check_download_url(url, allowed_hosts)
        resp = self._send("GET", url, stream=True, headers={"Accept-Encoding": "identity"},
                          follow_redirects=False)
        try:
            if resp.is_redirect:
                raise DownloadRefused(f"download redirected ({resp.status_code}); not followed")
            resp.raise_for_status()
            declared = resp.headers.get("Content-Length")
            if declared and declared.isdigit() and int(declared) > max_bytes:
                raise DownloadTooLarge(f"declared size {declared} > {max_bytes}")
            total = 0
            with open(dest, "wb") as fh:
                for chunk in resp.iter_raw():
                    total += len(chunk)
                    if total > max_bytes:
                        raise DownloadTooLarge(f"download passed {max_bytes} bytes")
                    fh.write(chunk)
            return total
        except DownloadTooLarge:
            dest.unlink(missing_ok=True)
            raise
        finally:
            resp.close()
