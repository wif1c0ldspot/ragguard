"""Local retrieval-to-context example; no model, network or external dependencies.

Run after installing the package: python examples/retrieval_pipeline.py.
The application authenticates the principal before calling prepare_context.
ACLs and collection membership come from trusted application storage, never from
retrieved document metadata. Replace the local search with a backend that enforces
the same authorized collection filter inside its retrieval query.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from ragguard import RULESET_VERSION, Boundary, ContentBoundary, Document


@dataclass(frozen=True)
class RetrievedDocument:
    """Untrusted text and title; chunks retain their source order."""

    title: str
    chunks: tuple[str, ...]


def render(document: RetrievedDocument) -> str:
    # Titles are model-visible too. Preserve chunk adjacency before scanning.
    return f"{document.title}\n{''.join(document.chunks)}"


class LocalStore:
    """Toy collection-scoped keyword retrieval, not a vector-store adapter."""

    def __init__(self, collections: Mapping[str, tuple[RetrievedDocument, ...]]) -> None:
        self.collections = dict(collections)

    def search(self, collection: str, query: str) -> tuple[RetrievedDocument, ...]:
        return tuple(
            document for document in self.collections.get(collection, ())
            if query.casefold() in render(document).casefold()
        )[:8]


@dataclass(frozen=True)
class PreparedContext:
    context: str | None = field(repr=False)
    # A deliberately small log projection; never log the complete scan report,
    # query, principal, source title, document ID, evidence or exception text.
    audit: dict[str, str | int | tuple[str, ...]]


def prepare_context(
    *,
    authenticated_principal: str,
    collection: str,
    query: str,
    trusted_acl: Mapping[str, frozenset[str]],
    store: LocalStore,
    boundary: ContentBoundary | None = None,
) -> PreparedContext:
    """Authorize, retrieve, render, scan, then return exactly the checked text.

    A request's principal must come from verified authentication, not a submitted
    user ID. This example returns no context on review, rejection or scan failure.
    A real reviewer approves a separate workflow; this function never auto-releases.
    """
    audit: dict[str, str | int | tuple[str, ...]] = {
        "decision": "unauthorized", "documents": 0, "families": (),
        "ruleset_version": RULESET_VERSION,
    }
    if collection not in trusted_acl.get(authenticated_principal, frozenset()):
        return PreparedContext(None, audit)

    gate = boundary if boundary is not None else ContentBoundary()
    try:
        retrieved = store.search(collection, query)
        audit["documents"] = len(retrieved)
        # The final rendered projection is the only value eligible for release.
        # Checking individual chunks alone misses instructions split across them.
        context = "\n\n".join(render(document) for document in retrieved)
        result = gate.check(
            Document(text=context, id="assembled-context"), boundary=Boundary.FINAL_CONTEXT,
        )
        audit.update(decision=result.decision, families=result.families)
        if result.decision != "accept" or result.released_text is None:
            return PreparedContext(None, audit)
        return PreparedContext(result.released_text, audit)
    except Exception:
        # Fail closed; errors may contain raw source text or backend credentials.
        audit["decision"] = "error"
        return PreparedContext(None, audit)


def main() -> None:
    acl = {"authenticated-demo-user": frozenset({"public-guide"})}
    store = LocalStore({"public-guide": (
        RetrievedDocument("Deployment guide", ("The service supports role-based access control.",)),
    )})
    prepared = prepare_context(
        authenticated_principal="authenticated-demo-user", collection="public-guide",
        query="guide", trusted_acl=acl, store=store,
    )
    print(prepared.audit)
    assert prepared.context == "Deployment guide\nThe service supports role-based access control."
    # Pass prepared.context unchanged to the application's model-context slot.
    # This demonstration deliberately makes no model call.


if __name__ == "__main__":
    main()
