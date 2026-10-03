"""Framework-independent security decisions for ingestion and retrieved content."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import Enum
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ragguard.detectors import DetectorConfig, DetectorRun, SemanticDetector, run_detector
from ragguard.scanner import (
    RULESET_VERSION,
    Document,
    Finding,
    RAGScanner,
    ScanReport,
    Severity,
    resolve_document_id,
)

# 1.1 adds ``advisory_families`` to every per-document result.
REPORT_SCHEMA_VERSION = "1.1"

SEVERITY_RANK: Mapping[Severity, int] = MappingProxyType({
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
})

_SCHEMA_FILES: Mapping[str, str] = MappingProxyType({
    "report": "report.schema.json",
    "worker-protocol": "worker-protocol.schema.json",
})


class IngestionDecision(str, Enum):
    """Caller action: pass content, flag it for review, or exclude it."""

    ACCEPT = "accept"
    REVIEW = "review"
    REJECT = "reject"


@dataclass(frozen=True)
class IngestionPolicy:
    """Immutable snapshot of a guard's validated enforcement configuration."""

    auto_reject: bool
    blocking_severities: frozenset[Severity]
    family_actions: Mapping[str, IngestionDecision]
    review_floor: Severity = Severity.MEDIUM


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    """Use the scanner's redacted evidence consistently on every output path."""
    return {
        ("type" if name == "finding_type" else name): (
            value.value if isinstance(value, Enum)
            else list(value) if isinstance(value, tuple)
            else value
        )
        for name, value in asdict(finding).items()
    }


@dataclass(frozen=True)
class DocumentDecision:
    """Typed decision for one input occurrence; ``to_dict`` gives the report shape.

    ``families`` lists every family that fired. ``advisory_families`` is the
    subset whose findings all ranked below the review floor (and had no family
    action), so they did not affect ``decision``.
    """

    document_id: str
    document_index: int
    source: str | None
    decision: IngestionDecision
    findings: tuple[Finding, ...]
    families: tuple[str, ...]
    advisory_families: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return self.decision is not IngestionDecision.REJECT

    @property
    def review_required(self) -> bool:
        return self.decision is IngestionDecision.REVIEW

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.document_id,
            "document_id": self.document_id,
            "document_index": self.document_index,
            "source": self.source,
            "accepted": self.accepted,
            "review_required": self.review_required,
            "decision": self.decision.value,
            "findings_count": len(self.findings),
            "families": list(self.families),
            "advisory_families": list(self.advisory_families),
            "findings": [_serialize_finding(finding) for finding in self.findings],
        }


@dataclass(frozen=True)
class BatchDecision:
    """Typed decisions for a batch, in input order, plus the underlying scan report."""

    documents: tuple[DocumentDecision, ...]
    report: ScanReport
    detector_runs: tuple[DetectorRun, ...] = ()

    @property
    def total(self) -> int:
        return len(self.documents)

    @property
    def clean(self) -> bool:
        return self.report.is_clean

    @property
    def accepted_count(self) -> int:
        return sum(document.accepted for document in self.documents)

    @property
    def review_count(self) -> int:
        return sum(document.review_required for document in self.documents)

    @property
    def rejected_count(self) -> int:
        return sum(not document.accepted for document in self.documents)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION,
            "total": self.total,
            "clean": self.clean,
            "summary": self.report.summary(),
            "severity_summary": self.report.severity_summary,
            "accepted_count": self.accepted_count,
            "review_count": self.review_count,
            "rejected_count": self.rejected_count,
            "documents": [document.to_dict() for document in self.documents],
        }


def load_schema(name: str) -> dict[str, Any]:
    """Load a bundled JSON Schema by name: ``"report"`` or ``"worker-protocol"``."""
    filename = _SCHEMA_FILES.get(name)
    if filename is None:
        raise ValueError(f"Unknown schema {name!r}; expected one of {sorted(_SCHEMA_FILES)}")
    resource = resources.files("ragguard").joinpath("schemas").joinpath(filename)
    schema: dict[str, Any] = json.loads(resource.read_text(encoding="utf-8"))
    return schema


class RAGPipelineGuard:
    """Scan untrusted content and return decisions for callers to enforce.

    Findings ranked below ``review_floor`` (medium by default; the order is
    info < low < medium < high < critical) are advisory: they are reported in
    ``findings``, ``families`` and ``advisory_families`` but yield accept.
    Other findings are accepted with a review flag by default;
    ``auto_reject=True`` enforces the blocking severities (critical/high by
    default). A family action overrides severity and the review floor for that
    family; reject actions still become review in monitoring mode. Invalid
    configuration fails during construction. The guard never writes documents
    to a store or invokes downstream tools.
    """

    def __init__(
        self,
        auto_reject: bool = False,
        *,
        scanner: RAGScanner | None = None,
        blocking_severities: Iterable[Severity | str] = (Severity.CRITICAL, Severity.HIGH),
        family_actions: Mapping[str, IngestionDecision | str] | None = None,
        review_floor: Severity | str = Severity.MEDIUM,
        detector: SemanticDetector | None = None,
        detector_config: DetectorConfig | None = None,
    ):
        if not isinstance(auto_reject, bool):
            raise ValueError("auto_reject must be a bool")
        if isinstance(blocking_severities, str):
            raise ValueError("blocking_severities must be an iterable of severity values")
        severities = frozenset(Severity(value) for value in blocking_severities)
        if not isinstance(review_floor, str):
            raise ValueError("review_floor must be a severity value")
        floor = Severity(review_floor)
        if any(SEVERITY_RANK[value] < SEVERITY_RANK[floor] for value in severities):
            # Otherwise a blocking severity would silently become advisory.
            raise ValueError("blocking_severities must not rank below review_floor")
        actions = {
            family: IngestionDecision(action) for family, action in (family_actions or {}).items()
        }
        if any(not isinstance(family, str) or not family.strip() for family in actions):
            raise ValueError("family_actions keys must be nonempty family names")
        self.scanner = scanner if scanner is not None else RAGScanner()
        self.policy = IngestionPolicy(auto_reject, severities, MappingProxyType(actions), floor)
        if detector is not None and not callable(getattr(detector, "detect", None)):
            raise ValueError("detector must provide a callable detect method")
        if detector_config is not None and not isinstance(detector_config, DetectorConfig):
            raise ValueError("detector_config must be a DetectorConfig")
        self.detector = detector
        self.detector_config = detector_config if detector_config is not None else DetectorConfig()

    @property
    def auto_reject(self) -> bool:
        return self.policy.auto_reject

    @property
    def review_floor(self) -> Severity:
        return self.policy.review_floor

    def _is_advisory(self, finding: Finding) -> bool:
        return (
            finding.family not in self.policy.family_actions
            and SEVERITY_RANK[Severity(finding.severity)] < SEVERITY_RANK[self.policy.review_floor]
        )

    def _action(self, finding: Finding) -> IngestionDecision:
        action = self.policy.family_actions.get(finding.family)
        if action is not None:
            return action
        if self._is_advisory(finding):
            return IngestionDecision.ACCEPT
        if Severity(finding.severity) in self.policy.blocking_severities:
            return IngestionDecision.REJECT
        return IngestionDecision.REVIEW

    def _decide(self, findings: Sequence[Finding]) -> IngestionDecision:
        actions = {self._action(finding) for finding in findings}
        if IngestionDecision.REJECT in actions:
            return IngestionDecision.REJECT if self.auto_reject else IngestionDecision.REVIEW
        if IngestionDecision.REVIEW in actions:
            return IngestionDecision.REVIEW
        return IngestionDecision.ACCEPT

    def _document_decision(
        self, document: Document, index: int, findings: Sequence[Finding],
    ) -> DocumentDecision:
        families = sorted({finding.family for finding in findings if finding.family})
        effective = {
            finding.family for finding in findings
            if finding.family and not self._is_advisory(finding)
        }
        return DocumentDecision(
            document_id=resolve_document_id(document),
            document_index=index,
            source=document.source,
            decision=self._decide(findings),
            findings=tuple(findings),
            families=tuple(families),
            advisory_families=tuple(family for family in families if family not in effective),
        )

    def evaluate(self, document: Document) -> DocumentDecision:
        """Scan one document and return its typed decision."""
        return self.evaluate_batch([document]).documents[0]

    def evaluate_batch(self, documents: Sequence[Document]) -> BatchDecision:
        """Scan a batch, correlating findings by input occurrence, not content ID.

        Duplicate explicit IDs are ambiguous and rejected before scanning. Equal
        generated content IDs are allowed: each occurrence retains its own
        metadata, provenance, findings and decision.
        """
        docs = self._validate_documents(documents)
        return self._batch_decision(docs, self.scanner.scan_documents(docs))

    def evaluate_chunks(
        self, chunks: Sequence[Document], *, window_chars: int = 256,
    ) -> BatchDecision:
        """Apply policy to ordered chunks of one source, including their boundaries.

        A boundary finding affects both participating chunks. The report retains
        one finding per detected boundary pattern; per-document decisions include
        that same finding for each participant, preserving its original indices.
        Use ``family_actions["split_payload"]`` to tune boundary findings.
        Scan the final assembled context separately when retrieval changes order
        or combines sources.
        """
        docs = self._validate_documents(chunks)
        return self._batch_decision(
            docs, self.scanner.scan_chunks(docs, window_chars=window_chars),
            include_related=True,
        )

    @staticmethod
    def _validate_documents(documents: Sequence[Document]) -> list[Document]:
        docs = list(documents)
        explicit_ids = [document.id for document in docs if document.id is not None]
        if any(not isinstance(value, str) or not value.strip() for value in explicit_ids):
            raise ValueError("Explicit document IDs must be nonempty strings")
        if len(set(explicit_ids)) != len(explicit_ids):
            raise ValueError("Duplicate explicit document IDs are not allowed in a batch")
        return docs

    def _batch_decision(
        self, docs: list[Document], report: ScanReport, *, include_related: bool = False,
    ) -> BatchDecision:
        detector_runs: tuple[DetectorRun, ...] = ()
        if self.detector is not None:
            semantic_findings, detector_runs = run_detector(
                self.detector, docs, self.detector_config,
            )
            findings = [*report.findings, *semantic_findings]
            summary = dict(report.severity_summary)
            for finding in semantic_findings:
                summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
            report = ScanReport(report.total_documents, findings, summary)
        by_index: dict[int, list[Finding]] = {}
        for finding in report.findings:
            indices: tuple[int | None, ...] = (finding.document_index,)
            if include_related:
                indices += finding.related_document_indices
            seen: set[int] = set()
            for index in indices:
                if type(index) is not int or not 0 <= index < len(docs):
                    raise ValueError("Scanner findings must include a valid document_index")
                if index not in seen:
                    by_index.setdefault(index, []).append(finding)
                    seen.add(index)
        return BatchDecision(
            documents=tuple(
                self._document_decision(document, index, by_index.get(index, []))
                for index, document in enumerate(docs)
            ),
            report=report,
            detector_runs=detector_runs,
        )

    def ingest(
        self, text: str, metadata: dict[str, Any] | None = None,
        *, id: str | None = None, source: str | None = None,
    ) -> dict[str, Any]:
        """Scan one document; the caller must honor ``accepted`` before using it."""
        batch = self.evaluate_batch([Document(text=text, metadata=metadata, id=id, source=source)])
        return {
            **batch.documents[0].to_dict(),
            "report": batch.report.summary(),
            "schema_version": REPORT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION,
        }

    def batch_ingest(self, documents: list[dict[str, Any]]) -> dict[str, Any]:
        """Dictionary form of :meth:`evaluate_batch` for JSON-oriented callers."""
        return self.evaluate_batch([
            Document(
                text=document["text"], metadata=document.get("metadata"),
                id=document.get("id"), source=document.get("source"),
            )
            for document in documents
        ]).to_dict()

    def export_report(self, report: ScanReport, path: str | Path) -> None:
        """Export a versioned JSON report using redacted scanner evidence."""
        data = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION,
            "total_documents": report.total_documents,
            "summary": report.summary(),
            "severity_summary": report.severity_summary,
            "findings": [_serialize_finding(finding) for finding in report.findings],
        }
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
