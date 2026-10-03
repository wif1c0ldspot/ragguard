"""Framework-neutral checks before untrusted text enters an agent's context.

The caller owns authorization, tool side effects, prompt assembly and logging.
This adapter never runs a tool or sends content to a model.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass, field
from enum import Enum

from ragguard.detectors import DetectorProvenance
from ragguard.pipeline import RAGPipelineGuard
from ragguard.scanner import RULESET_VERSION, Document


class Boundary(str, Enum):
    INGESTION = "ingestion"
    RETRIEVAL = "retrieval"
    TOOL_OUTPUT = "tool_output"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    TOOL_DESCRIPTION = "tool_description"
    FINAL_CONTEXT = "final_context"


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
    advisory_families: tuple[str, ...] = ()
    scan_complete: bool = True
    content_sha256: str = ""
    ruleset_version: str = RULESET_VERSION
    policy_sha256: str = ""

    def matches_text(self, text: str) -> bool:
        """Check exact UTF-8 content binding; this is not a signature or authorization."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest() == self.content_sha256

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
    a monitored rollout); reject decisions are always withheld. Findings below
    the guard's ``review_floor`` are advisory and do not withhold content. Never
    catch a scan exception and fall back to the original content.
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

    def _policy_sha256(self) -> str:
        """Bind declared policy/scanner/detector settings, not custom adapter code."""
        policy = self.guard.policy
        scanner = self.guard.scanner
        detector = self.guard.detector
        provenance = getattr(detector, "provenance", None)
        if provenance is not None and not isinstance(provenance, DetectorProvenance):
            raise ValueError("invalid detector provenance")
        value = {
            "auto_reject": policy.auto_reject,
            "blocking_severities": sorted(item.value for item in policy.blocking_severities),
            "family_actions": {key: item.value for key, item in policy.family_actions.items()},
            "review_floor": policy.review_floor.value,
            "allow_review": self.allow_review, "max_text_chars": self.max_text_chars,
            "ruleset_version": RULESET_VERSION,
            "scanner": {
                "enabled_families": sorted(scanner.enabled_families),
                "redact_evidence": scanner.redact_evidence,
                "max_matches_per_family": scanner.max_matches_per_family,
                "max_metadata_nodes": scanner.max_metadata_nodes,
                "max_metadata_chars": scanner.max_metadata_chars,
            },
            "detector_config": asdict(self.guard.detector_config),
            "detector_type": (None if detector is None else
                              f"{type(detector).__module__}.{type(detector).__qualname__}"),
            "detector_provenance": asdict(provenance) if provenance is not None else None,
            "detector_configuration": getattr(detector, "configuration", None),
        }
        return hashlib.sha256(json.dumps(value, sort_keys=True).encode("utf-8")).hexdigest()

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
        content_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
        policy_sha256 = self._policy_sha256()
        # Scan the captured text so the released value is exactly what was checked.
        decision = self.guard.evaluate(Document(
            text=text, metadata=document.metadata, id=document.id, source=document.source,
        ))
        if self._policy_sha256() != policy_sha256:
            raise RuntimeError("boundary policy changed during scan")
        released = (decision.scan_complete and decision.accepted
                    and (not decision.review_required or self.allow_review))
        return BoundaryResult(
            boundary=boundary,
            document_id=decision.document_id,
            decision=decision.decision.value,
            review_required=decision.review_required,
            families=decision.families,
            released_text=text if released else None,
            advisory_families=decision.advisory_families,
            scan_complete=decision.scan_complete,
            content_sha256=content_sha256,
            policy_sha256=policy_sha256,
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
