"""The decision cache, and the five conditions an entry must satisfy.

This is a port of services/cmd/stratium-pep/cache.go's cacheEntryUsable. The
conditions are ALL required and are checked in one place, because a hit that
fails any of them must be indistinguishable from a miss -- fail closed means
an invalid entry is not a separate outcome a caller could decide to handle.
"""

from __future__ import annotations

import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from ._types import Decision, Effect


@dataclass(frozen=True)
class CacheEntry:
    decision: Decision
    cached_at: float
    epoch: int
    delegation_expires_at: float
    token: str


class DecisionCache:
    def __init__(
        self, staleness_window: float, *, max_entries: int = 512,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._window = staleness_window
        self._max = max_entries
        self._clock = clock
        self._entries: OrderedDict[str, CacheEntry] = OrderedDict()

    def key(self, *, agent_id: str, subject: str, tool: str, raw_input: str) -> str:
        # raw_input is already canonical (see _types.canonical_raw_input), so
        # equal arguments hash equal regardless of how the caller spelled them.
        h = hashlib.sha256()
        for part in (agent_id, subject, tool, raw_input):
            h.update(part.encode())
            h.update(b"\x00")
        return h.hexdigest()

    def put(
        self, key: str, decision: Decision, *, epoch: int,
        delegation_expires_at: float, token: str,
    ) -> None:
        # W4, write side. An ESCALATE means a human must approve THIS call;
        # replaying it would approve a call nobody ever saw. The read side
        # refuses one too -- both halves, because the failure is silent.
        if decision.effect is Effect.ESCALATE:
            return
        # A decision that was never reached is not a decision to cache.
        if decision.effect is None:
            return

        self._entries[key] = CacheEntry(
            decision=decision, cached_at=self._clock(), epoch=epoch,
            delegation_expires_at=delegation_expires_at, token=token,
        )
        self._entries.move_to_end(key)
        while len(self._entries) > self._max:
            self._entries.popitem(last=False)

    def get(
        self, key: str, *, last_known_epoch: int, token: str, token_expires_at: float,
    ) -> Decision | None:
        entry = self._entries.get(key)
        if entry is None:
            return None
        if not self._usable(entry, last_known_epoch, token, token_expires_at):
            # Deleted rather than left to rot: an unusable entry can never
            # become usable again, since none of the five conditions recovers.
            del self._entries[key]
            return None
        return entry.decision

    def _usable(
        self, entry: CacheEntry, last_known_epoch: int, token: str,
        token_expires_at: float,
    ) -> bool:
        now = self._clock()
        return (
            entry.decision.effect is not Effect.ESCALATE
            and entry.epoch == last_known_epoch
            and now < entry.delegation_expires_at
            and now < token_expires_at
            and entry.token == token
            # INCLUSIVE at the boundary, matching Go's
            # !now.After(CachedAt.Add(staleness)). The clock runs from the
            # entry's own cached_at, so reading never extends the window.
            and now <= entry.cached_at + self._window
        )
