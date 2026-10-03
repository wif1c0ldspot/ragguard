"""Shared document, finding, and report types without scanner dependencies."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

# --- OWASP Top 10 for LLM Applications (2025) categories used by the scanner ---

LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
LLM02_SENSITIVE_INFO = "LLM02: Sensitive Information Disclosure"
LLM04_POISONING = "LLM04: Data and Model Poisoning"
LLM05_IMPROPER_OUTPUT = "LLM05: Improper Output Handling"
LLM07_SYSTEM_PROMPT = "LLM07: System Prompt Leakage"
LLM08_VECTOR_WEAKNESSES = "LLM08: Vector and Embedding Weaknesses"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of RAG pipeline vulnerabilities detected."""
    PROMPT_INJECTION_IN_DOCUMENT = "prompt_injection_in_document"
    METADATA_INJECTION = "metadata_injection"
    CHUNK_SPLIT_ATTACK = "chunk_split_attack"
    EMBEDDING_POISONING = "embedding_poisoning"
    CROSS_USER_CONTAMINATION = "cross_user_contamination"
    CANONICAL_INJECTION = "canonical_injection"
    SCAN_INCOMPLETE = "scan_incomplete"


@dataclass(frozen=True, kw_only=True)
class Finding:
    """A single, immutable security finding from a RAG pipeline scan.

    Construct with keywords; use :func:`dataclasses.replace` to derive variants.
    """
    finding_type: FindingType
    severity: Severity
    document_id: str
    description: str
    evidence: str
    remediation: str
    owasp_mapping: str = ""
    family: str = ""
    document_index: int | None = None
    metadata_path: str | None = None
    related_document_ids: tuple[str, ...] = ()
    confidence: str = "heuristic"
    related_document_indices: tuple[int, ...] = ()


@dataclass
class Document:
    """A document in the RAG pipeline."""
    text: str
    metadata: dict[str, Any] | None = None
    id: str | None = None
    source: str | None = None
    embedding: list[float] | None = None


@dataclass
class ScanReport:
    """Aggregated scan results."""
    total_documents: int
    findings: list[Finding]
    severity_summary: dict[str, int]

    @property
    def scan_complete(self) -> bool:
        """False when requested scan work exceeded a resource budget."""
        return not any(f.finding_type == FindingType.SCAN_INCOMPLETE for f in self.findings)

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def has_blocking_findings(self) -> bool:
        """True when any finding is critical or high severity."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    def summary(self) -> str:
        lines = [
            "RAG Security Scan Report",
            "=" * 40,
            f"Documents scanned: {self.total_documents}",
            f"Total findings: {len(self.findings)}",
        ]
        for sev, count in sorted(self.severity_summary.items()):
            lines.append(f"  {sev.upper()}: {count}")
        return "\n".join(lines)
