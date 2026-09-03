"""Pipeline integration utilities for embedding ragguard into existing RAG systems."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ragguard.scanner import Document, RAGScanner, ScanReport


class RAGPipelineGuard:
    """Middleware guard for RAG pipelines. Call scan() at ingestion time."""

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

        if self.auto_reject and not report.is_clean:
            return {
                "accepted": False,
                "document_id": doc.id,
                "findings": [
                    {
                        "type": f.finding_type.value,
                        "severity": f.severity.value,
                        "description": f.description,
                        "remediation": f.remediation,
                    }
                    for f in report.findings
                ],
                "report": report.summary(),
            }

        return {
            "accepted": True,
            "document_id": doc.id,
            "findings": [
                {
                    "type": f.finding_type.value,
                    "severity": f.severity.value,
                    "description": f.description,
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

        return {
            "total": len(docs),
            "clean": report.is_clean,
            "summary": report.summary(),
            "severity_summary": report.severity_summary,
            "documents": [
                {
                    "id": doc.id,
                    "accepted": not any(
                        f.document_id == (doc.id or doc.text[:50])
                        for f in report.findings
                        if f.severity.value in ("critical", "high")
                    ),
                    "findings_count": sum(
                        1 for f in report.findings
                        if f.document_id == (doc.id or doc.text[:50])
                    ),
                }
                for doc in docs
            ],
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