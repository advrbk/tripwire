"""npm: the public replication changes feed plus the per-package "latest" doc.

``https://replicate.npmjs.com/registry/_changes?since=<seq>`` returns every
package document that changed after sequence number ``seq``. That number is a
real cursor, so resume is exact: save the last sequence handled, start after
it next time. A change does not always mean a new version (dist-tags,
deprecations and unpublishes also count), so the database's
(ecosystem, name, version) key filters out versions already scanned.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import quote

from ..db import Database
from ..models import ReleaseRef
from .http import PoliteClient

REPLICATE_ROOT = "https://replicate.npmjs.com/registry/"
CHANGES_URL = "https://replicate.npmjs.com/registry/_changes"
LATEST_URL = "https://registry.npmjs.org/{name}/latest"
STATE_KEY = "npm"


@dataclass(frozen=True)
class NpmCandidate:
    name: str
    seq: int
    batch_end: int | None = None  # set on the last candidate of a batch: the batch's last_seq


def encode_name(name: str) -> str:
    # "@scope/pkg" -> "@scope%2Fpkg", which the registry accepts for scoped names
    return quote(name, safe="@")


class NpmFeed:
    ecosystem = "npm"

    def __init__(self, client: PoliteClient, db: Database, *, start_backlog: int = 200, batch: int = 100):
        self.client = client
        self.db = db
        self.batch = batch
        self.start_backlog = start_backlog
        state = db.get_state(STATE_KEY) or {}
        self.since: int | None = state.get("since")

    def _initial_since(self) -> int:
        root = self.client.get_json(REPLICATE_ROOT)
        seq = int(root.get("update_seq", 0)) if isinstance(root, dict) else 0
        return max(0, seq - self.start_backlog)

    def poll(self) -> list[NpmCandidate]:
        if self.since is None:
            self.since = self._initial_since()
            self.db.set_state(STATE_KEY, {"since": self.since})
        data = self.client.get_json(CHANGES_URL, params={"since": self.since, "limit": self.batch})
        results = data.get("results", []) if isinstance(data, dict) else []
        out: dict[str, NpmCandidate] = {}
        for r in results:
            if not isinstance(r, dict) or r.get("deleted") or not isinstance(r.get("id"), str):
                continue
            name = r["id"]
            if name.startswith("_design/"):
                continue
            out.pop(name, None)
            out[name] = NpmCandidate(name, int(r.get("seq", 0)))  # keep the last change per name
        last_seq = data.get("last_seq") if isinstance(data, dict) else None
        cands = sorted(out.values(), key=lambda c: c.seq)
        if isinstance(last_seq, int):
            if not cands:
                # Everything in the batch was a deletion or design doc: move past it.
                if last_seq > (self.since or 0):
                    self.since = last_seq
                    self.db.set_state(STATE_KEY, {"since": self.since})
            else:
                end = max(last_seq, cands[-1].seq)
                cands[-1] = NpmCandidate(cands[-1].name, cands[-1].seq, end)
        return cands

    def resolve(self, cand: NpmCandidate) -> ReleaseRef | None:
        doc = self.client.get_json(LATEST_URL.format(name=encode_name(cand.name)))
        if not isinstance(doc, dict):
            return None
        dist = doc.get("dist") or {}
        tarball, version = dist.get("tarball"), doc.get("version")
        if not tarball or not version:
            return None
        return ReleaseRef(
            ecosystem="npm", name=doc.get("name") or cand.name, version=str(version), artifact_url=tarball,
            filename=tarball.rsplit("/", 1)[-1], size=None, integrity=dist.get("integrity"),
            published_at=None,
        )

    def commit(self, cand: NpmCandidate) -> None:
        """Mark one candidate handled. The last one of a batch moves the cursor to the batch end."""
        target = cand.batch_end if cand.batch_end is not None else cand.seq
        if self.since is None or target > self.since:
            self.since = target
            self.db.set_state(STATE_KEY, {"since": self.since})
