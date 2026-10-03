"""Small process-local memory example with authorization, expiry and re-scanning.

The application supplies authenticated principals and trusted source identifiers.
Stored facts remain untrusted: scanning cannot establish factual correctness.
Use a transactional, access-controlled store for persistent or concurrent use.
"""

from __future__ import annotations

import hashlib
import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ragguard import Boundary, ContentBoundary, Document


@dataclass(frozen=True)
class MemoryEntry:
    source_id: str
    text: str = field(repr=False)
    content_sha256: str
    expires_at: float
    ruleset_version_at_write: str


class GuardedMemory:
    """One authenticated owner; bounded entries; fresh checks on every read."""

    def __init__(
        self, *, owner: str, trusted_sources: frozenset[str],
        boundary: ContentBoundary | None = None, max_entries: int = 100,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not isinstance(owner, str) or not owner:
            raise ValueError("owner must be nonempty")
        if type(max_entries) is not int or max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._owner = owner
        self._sources = frozenset(trusted_sources)
        self.boundary = boundary if boundary is not None else ContentBoundary()
        self._max_entries = max_entries
        self._clock = clock
        self._entries: dict[str, MemoryEntry] = {}

    def _authorize(self, principal: str) -> None:
        if principal != self._owner:
            raise PermissionError("memory access denied")

    def write(
        self, *, authenticated_principal: str, key: str, source_id: str, text: str,
        ttl_seconds: float = 3600,
    ) -> None:
        self._authorize(authenticated_principal)
        if source_id not in self._sources:
            raise PermissionError("memory source is not authorized")
        if type(ttl_seconds) not in (int, float) or not math.isfinite(ttl_seconds) \
                or not 0 < ttl_seconds <= 86_400:
            raise ValueError("TTL must be within one day")
        if not isinstance(key, str) or not 1 <= len(key) <= 128:
            raise ValueError("invalid memory key")
        now = self._clock()
        self._entries = {k: entry for k, entry in self._entries.items() if entry.expires_at > now}
        if key not in self._entries and len(self._entries) >= self._max_entries:
            raise ValueError("memory entry budget exceeded")
        result = self.boundary.check(Document(text), boundary=Boundary.MEMORY_WRITE)
        if result.decision != "accept" or result.released_text is None:
            raise PermissionError("memory write withheld")
        self._entries[key] = MemoryEntry(
            source_id, result.released_text, result.content_sha256,
            now + ttl_seconds, result.ruleset_version,
        )

    def read(self, *, authenticated_principal: str, key: str) -> str | None:
        self._authorize(authenticated_principal)
        entry = self._entries.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            del self._entries[key]
            return None
        if hashlib.sha256(entry.text.encode()).hexdigest() != entry.content_sha256:
            raise PermissionError("stored memory content changed")
        # Never reuse the earlier verdict after a ruleset or policy update.
        result = self.boundary.check(Document(entry.text), boundary=Boundary.MEMORY_READ)
        if result.decision != "accept" or result.released_text is None:
            raise PermissionError("memory read withheld")
        return result.released_text


def main() -> None:
    memory = GuardedMemory(owner="alice", trusted_sources=frozenset({"reviewed-guide"}))
    memory.write(authenticated_principal="alice", key="deployment", source_id="reviewed-guide",
                 text="Deployment uses the blue environment.")
    assert memory.read(authenticated_principal="alice", key="deployment") is not None
    print("Memory checked on write and read.")


if __name__ == "__main__":
    main()
