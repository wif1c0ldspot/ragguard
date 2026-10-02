"""Framework-independent security decisions for ingestion and retrieved content."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any

from ragguard.scanner import (
    RULESET_VERSION,
    Document,
    Finding,
    RAGScanner,
    ScanReport,
    Severity,
    resolve_document_id,
)

REPORT_SCHEMA_VERSION = "1.0"


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


class RAGPipelineGuard:
    """Scan untrusted content and return decisions for callers to enforce.

    By default, findings are accepted with a review flag. ``auto_reject=True``
    enforces the blocking severities (critical/high by default). A family action
    overrides severity for that family; reject actions still become review in
    monitoring mode. Unknown severity/action values fail during construction.
    The guard never writes documents to a store or invokes downstream tools.
    """

    def __init__(
        self,
        auto_reject: bool = False,
        *,
        scanner: RAGScanner | None = None,
        blocking_severities: Iterable[Severity | str] = (Severity.CRITICAL, Severity.HIGH),
        family_actions: Mapping[str, IngestionDecision | str] | None = None,
    ):
        if not isinstance(auto_reject, bool):
            raise ValueError("auto_reject must be a bool")
        if isinstance(blocking_severities, str):
            raise ValueError("blocking_severities must be an iterable of severity values")
        severities = frozenset(Severity(value) for value in blocking_severities)
        actions = {
            family: IngestionDecision(action) for family, action in (family_actions or {}).items()
        }
        if any(not isinstance(family, str) or not family.strip() for family in actions):
            raise ValueError("family_actions keys must be nonempty family names")
        self.scanner = scanner if scanner is not None else RAGScanner()
        self.policy = IngestionPolicy(auto_reject, severities, MappingProxyType(actions))

    @property
    def auto_reject(self) -> bool:
        return self.policy.auto_reject

    def _decide(self, findings: list[Finding]) -> IngestionDecision:
        actions = {
            self.policy.family_actions.get(
                finding.family,
                IngestionDecision.REJECT
                if finding.severity in self.policy.blocking_severities
                else IngestionDecision.REVIEW,
            )
            for finding in findings
        }
        if IngestionDecision.REJECT in actions:
            return IngestionDecision.REJECT if self.auto_reject else IngestionDecision.REVIEW
        if IngestionDecision.REVIEW in actions:
            return IngestionDecision.REVIEW
        return IngestionDecision.ACCEPT

    def _document_result(
        self, document: Document, index: int, findings: list[Finding],
    ) -> dict[str, Any]:
        decision = self._decide(findings)
        document_id = resolve_document_id(document)
        return {
            "id": document_id,
            "document_id": document_id,
            "document_index": index,
            "source": document.source,
            "accepted": decision is not IngestionDecision.REJECT,
            "review_required": decision is IngestionDecision.REVIEW,
            "decision": decision.value,
            "findings_count": len(findings),
            "families": sorted({finding.family for finding in findings if finding.family}),
            "findings": [_serialize_finding(finding) for finding in findings],
        }

    def ingest(
        self, text: str, metadata: dict[str, Any] | None = None,
        *, id: str | None = None, source: str | None = None,
    ) -> dict[str, Any]:
        """Scan one document; the caller must honor ``accepted`` before using it."""
        batch = self.batch_ingest([
            {"text": text, "metadata": metadata, "id": id, "source": source},
        ])
        return {
            **batch["documents"][0],
            "report": batch["summary"],
            "schema_version": REPORT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION,
        }

    def batch_ingest(self, documents: list[dict[str, Any]]) -> dict[str, Any]:
        """Scan a batch, correlating findings by input occurrence, not content ID.

        Duplicate explicit IDs are ambiguous and rejected before scanning. Equal
        generated content IDs are allowed: each occurrence retains its own
        metadata, provenance, findings and decision.
        """
        docs = [
            Document(
                text=document["text"], metadata=document.get("metadata"),
                id=document.get("id"), source=document.get("source"),
            )
            for document in documents
        ]
        explicit_ids = [document.id for document in docs if document.id is not None]
        if any(not isinstance(value, str) or not value.strip() for value in explicit_ids):
            raise ValueError("Explicit document IDs must be nonempty strings")
        if len(set(explicit_ids)) != len(explicit_ids):
            raise ValueError("Duplicate explicit document IDs are not allowed in a batch")
        report = self.scanner.scan_documents(docs)
        by_index: dict[int, list[Finding]] = {}
        for finding in report.findings:
            index = finding.document_index
            if type(index) is not int or not 0 <= index < len(docs):
                raise ValueError("Scanner findings must include a valid document_index")
            by_index.setdefault(index, []).append(finding)
        results = [
            self._document_result(document, index, by_index.get(index, []))
            for index, document in enumerate(docs)
        ]
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "ruleset_version": RULESET_VERSION,
            "total": len(docs),
            "clean": report.is_clean,
            "summary": report.summary(),
            "severity_summary": report.severity_summary,
            "accepted_count": sum(result["accepted"] for result in results),
            "review_count": sum(result["review_required"] for result in results),
            "rejected_count": sum(not result["accepted"] for result in results),
            "documents": results,
        }

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
