"""Deterministic action limits alongside content scanning; no external side effects.

The application authenticates users and owns tool definitions, destination IDs,
and permissions. Never construct these policies from retrieved text or a model's
claims. This example supports one narrowly defined action, not arbitrary tools.
"""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from ragguard import Boundary, ContentBoundary, Document


@dataclass(frozen=True)
class ReportAction:
    destination: str
    body: str = field(repr=False)


class ReportDispatcher:
    """Validate, reserve a per-session call budget, and dispatch an exact snapshot.

    ``send`` resolves destination IDs through trusted application configuration;
    it must never interpret an ID as a URL, filesystem path, or shell fragment.
    It must enforce its own deadlines and network permissions. A failed send
    still consumes a call. This is not DLP or an authorization service.
    """

    def __init__(
        self, *, trusted_permissions: Mapping[str, frozenset[str]],
        approved_description: str, send: Callable[[ReportAction], None],
        max_calls: int = 3, max_body_chars: int = 10_000,
        boundary: ContentBoundary | None = None,
    ) -> None:
        if type(max_calls) is not int or max_calls < 1:
            raise ValueError("max_calls must be positive")
        if type(max_body_chars) is not int or max_body_chars < 1:
            raise ValueError("max_body_chars must be positive")
        self._permissions = {key: frozenset(value) for key, value in trusted_permissions.items()}
        self._boundary = boundary if boundary is not None else ContentBoundary()
        checked = self._boundary.require(
            Document(approved_description), boundary=Boundary.TOOL_DESCRIPTION,
        )
        self._description_digest = hashlib.sha256(checked.encode()).digest()
        self._send = send
        self._max_calls = max_calls
        self._max_body_chars = max_body_chars
        self._used = 0
        self._lock = threading.Lock()

    def dispatch(
        self, *, authenticated_principal: str, current_description: str,
        proposed_arguments: Mapping[str, object],
    ) -> None:
        """Reject unknown arguments, changed tool descriptions, and excess authority."""
        if hashlib.sha256(current_description.encode()).digest() != self._description_digest:
            raise PermissionError("tool description changed; registration required")
        arguments = dict(proposed_arguments)
        if set(arguments) != {"destination", "body"}:
            raise ValueError("unsupported action arguments")
        destination, body = arguments["destination"], arguments["body"]
        if not isinstance(destination, str) or not isinstance(body, str):
            raise ValueError("action arguments must be strings")
        if destination not in self._permissions.get(authenticated_principal, frozenset()):
            raise PermissionError("destination not authorized")
        if len(body) > self._max_body_chars:
            raise ValueError("action body exceeds budget")
        # A fixed action and exact destination authorization still apply when
        # scanning misses malicious intent. Never dispatch arbitrary model code.
        with self._lock:
            if self._used >= self._max_calls:
                raise PermissionError("action budget exhausted")
            self._used += 1
        self._send(ReportAction(destination, body))


def main() -> None:
    actions: list[ReportAction] = []
    description = "Send a report to an authorized internal destination."
    dispatcher = ReportDispatcher(
        trusted_permissions={"alice": frozenset({"internal-audit"})},
        approved_description=description, send=actions.append,
    )
    dispatcher.dispatch(
        authenticated_principal="alice", current_description=description,
        proposed_arguments={"destination": "internal-audit", "body": "Deployment complete."},
    )
    assert len(actions) == 1
    try:
        dispatcher.dispatch(
            authenticated_principal="alice", current_description=description,
            proposed_arguments={"destination": "https://untrusted.invalid", "body": "Report"},
        )
    except PermissionError:
        pass
    else:
        raise AssertionError("unauthorized destination was dispatched")
    assert len(actions) == 1
    print("Authorized action dispatched; unauthorized destination withheld.")


if __name__ == "__main__":
    main()
