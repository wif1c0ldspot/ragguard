"""Pipeline integration utilities for embedding ragguard into existing RAG systems."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ragguard.scanner import (
    Document,
    RAGScanner,
    ScanReport,
    resolve_document_id,
)


class RAGPipelineGuard:
    """Middleware guard for RAG pipelines. Call ingest() at ingestion time."""

    def __init__(self, auto_reject: bool = False):
        self.scanner = RAGScanner()
        self.auto_reject = auto_reject

    def ingest(self, text: str, metadata: dict[str, Any] | None = None) -> dict:
        """Process a document through the security pipeline.

        Returns:
            dict with keys: accepted (bool), document_id, findings, report
        """
        doc = Document(text=text, metadata=metadata or {})
        report = self.scanner.scan_documents([doc])

        blocked = self.auto_reject and report.has_blocking_findings

        return {
            "accepted": not blocked,
            "document_id": resolve_document_id(doc),
            "review_required": bool(report.findings) and not blocked,
            "findings": [
                {
                    "type": f.finding_type.value,
                    "severity": f.severity.value,
                    "family": f.family,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "owasp_mapping": f.owasp_mapping,
                }
                for f in report.findings
            ],
            "report": report.summary(),
        }

    def batch_ingest(
        self,
        documents: list[dict[str, Any]],
    ) -> dict:
        """Process multiple documents through the security pipeline.

        Args:
            documents: List of dicts with 'text' and optional 'metadata' keys.

        Returns:
            dict with summary stats and per-document results
        """
        docs = [
            Document(
                text=d["text"],
                metadata=d.get("metadata"),
                id=d.get("id"),
                source=d.get("source"),
            )
            for d in documents
        ]

        report = self.scanner.scan_documents(docs)

        # Findings carry the scanner's own document id, so correlate with the
        # same resolver — deriving ids from doc.text here silently matches nothing.
        by_document: dict[str, list] = {}
        for finding in report.findings:
            by_document.setdefault(finding.document_id, []).append(finding)

        documents_out = []
        for doc in docs:
            doc_id = resolve_document_id(doc)
            findings = by_document.get(doc_id, [])
            documents_out.append({
                "id": doc_id,
                "accepted": not any(
                    f.severity.value in ("critical", "high") for f in findings
                ),
                "findings_count": len(findings),
                "families": sorted({f.family for f in findings if f.family}),
            })

        return {
            "total": len(docs),
            "clean": report.is_clean,
            "summary": report.summary(),
            "severity_summary": report.severity_summary,
            "documents": documents_out,
        }

    def export_report(self, report: ScanReport, path: str | Path) -> None:
        """Export scan report as JSON."""
        data = {
            "total_documents": report.total_documents,
            "summary": report.summary(),
            "severity_summary": report.severity_summary,
            "findings": [
                {
                    "type": f.finding_type.value,
                    "severity": f.severity.value,
                    "family": f.family,
                    "document_id": f.document_id,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "owasp_mapping": f.owasp_mapping,
                }
                for f in report.findings
            ],
        }
        Path(path).write_text(json.dumps(data, indent=2))
