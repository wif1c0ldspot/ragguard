"""Framework-neutral checks before untrusted text enters an agent's context.

The caller owns authorization, tool side effects, prompt assembly and logging.
This adapter never runs a tool or sends content to a model.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum

from ragguard.pipeline import RAGPipelineGuard
from ragguard.scanner import Document


class Boundary(str, Enum):
    INGESTION = "ingestion"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"


@dataclass(frozen=True)
class BoundaryResult:
    """Decision and permitted content; held text is never included.

    Do not serialize this object to logs: released text may contain private data.
    Its repr deliberately excludes content.
    """

    boundary: Boundary
    document_id: str
    decision: str
    review_required: bool
    families: tuple[str, ...]
    released_text: str | None = field(repr=False)

    @property
    def released(self) -> bool:
        return self.released_text is not None


class ContentBlockedError(Exception):
    """The harness must stop, quarantine, or request review of this result."""

    def __init__(self, result: BoundaryResult):
        self.result = result
        super().__init__(f"Content withheld at {result.boundary.value}: {result.decision}")


class ContentBoundary:
    """Withhold rejected and review-required text before context assembly.

    ``allow_review=True`` explicitly releases review decisions (for example in
    a monitored rollout); reject decisions are always withheld. Never catch a
    scan exception and fall back to the original content.
    """

    def __init__(
        self,
        guard: RAGPipelineGuard | None = None,
        *,
        allow_review: bool = False,
        max_text_chars: int = 1_000_000,
    ) -> None:
        if not isinstance(allow_review, bool):
            raise ValueError("allow_review must be a bool")
        if isinstance(max_text_chars, bool) or not isinstance(max_text_chars, int):
            raise ValueError("max_text_chars must be a positive integer")
        if max_text_chars < 1:
            raise ValueError("max_text_chars must be a positive integer")
        self.guard = guard if guard is not None else RAGPipelineGuard(auto_reject=True)
        self.allow_review = allow_review
        self.max_text_chars = max_text_chars

    def check(
        self, document: Document, *, boundary: Boundary = Boundary.RETRIEVAL,
    ) -> BoundaryResult:
        """Return a decision; text is present only if policy permits release.

        Scan the complete text exactly as it will reach the model. If metadata
        will be rendered too, include that rendering in ``document.text``.
        """
        boundary = Boundary(boundary)
        text = document.text
        if not isinstance(text, str):
            raise TypeError("document.text must be a string")
        if len(text) > self.max_text_chars:
            raise ValueError("content exceeds max_text_chars; refusing partial scanning")
        report = self.guard.ingest(
            text, document.metadata, id=document.id, source=document.source,
        )
        released = report["accepted"] and (
            not report["review_required"] or self.allow_review
        )
        return BoundaryResult(
            boundary=boundary,
            document_id=report["document_id"],
            decision=report["decision"],
            review_required=report["review_required"],
            families=tuple(sorted({f["family"] for f in report["findings"]})),
            released_text=text if released else None,
        )

    def require(
        self, document: Document, *, boundary: Boundary = Boundary.RETRIEVAL,
    ) -> str:
        """Return permitted text, otherwise raise without echoing the payload."""
        result = self.check(document, boundary=boundary)
        if result.released_text is None:
            raise ContentBlockedError(result)
        return result.released_text

    async def arequire(
        self, document: Document, *, boundary: Boundary = Boundary.RETRIEVAL,
    ) -> str:
        """Run the same check off the event-loop thread before releasing text."""
        return await asyncio.to_thread(self.require, document, boundary=boundary)
