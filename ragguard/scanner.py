"""Core scanning engine for RAG pipeline security assessment."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


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


@dataclass
class Finding:
    """A single security finding from a RAG pipeline scan."""
    finding_type: FindingType
    severity: Severity
    document_id: str
    description: str
    evidence: str
    remediation: str
    owasp_mapping: str = ""


# --- Prompt injection payloads for detection ---

_INJECTION_PATTERNS = [
    # Direct instruction override
    re.compile(r"(?i)(ignore\s+(the\s+)?(above|previous|system)\s*(instructions?|prompt|context))"),
    re.compile(r"(?i)(you\s+(are\s+)?now\s+(a\s+)?(different\s+)?(model|assistant|entity))"),
    re.compile(r"(?i)((new\s+)?(instruction|rule|directive)\s*:)", re.MULTILINE),
    # System prompt extraction
    re.compile(r"(?i)(repeat\s+(your|the)\s+(system\s+)?prompt)"),
    re.compile(r"(?i)(what\s+(were|are)\s+(your\s+)?(instructions?|system\s+prompt))"),
    re.compile(r"(?i)(((begin|start)\s+(output|response).*(end|stop)\s+(output|response)))", re.DOTALL),
    # Instruction hijacking
    re.compile(r"(?i)((\\\\|`|<\/?script)[^<]*>|(javascript:|data:))", re.MULTILINE),
    re.compile(r"(?i)((previous|above)\s+(response|output|message)[^\n]*(contains|reveals|shows))"),
    # Encoding tricks
    re.compile(r"(&#x[0-9a-fA-F]+;|%[0-9a-fA-F]{2})"),
    re.compile(r"(\x80|\x9b|\x90|\x9d)", re.MULTILINE),  # Invisible control chars
    # Jailbreak patterns
    re.compile(r"(?i)((developer|debug|test|maintenance)\s+mode)"),
    re.compile(r"(?i)((d\s*a\s*r\s*k\s*w\s*e\s*b|shadow)\s*(net|web|zone))"),
    # Data exfiltration patterns
    re.compile(r"(?i)(output\s+(all|everything)\s+(text|content|data))"),
    re.compile(r"(?i)(base64|hex|encode)\s*(this|the\s+following|above)"),
]

# --- Metadata injection patterns ---

_METADATA_INJECTION_PATTERNS = [
    # KEY=VALUE format (common in EXIF, PDF metadata)
    re.compile(r"(\b[A-Z_]{4,}\s*=\s*[\"'][^\"'<>\n]{10,})"),
    # JSON-style metadata: "FUNCTION": "write_file", "ACTION": "INVOKE"
    re.compile(r"[\"']?(\bFUNCTION\b|\bACTION\b|\bTOOL\b)[\"']?\s*[:=]\s*[\"']?(\b(write_|exec|invoke|rm_|curl|wget|http|POST|GET)\b|[^\"'\n]{3,})[\"']?", re.IGNORECASE),
    # Code execution in any metadata value
    re.compile(r"(\b(?:eval|exec|compile|import|require|load)\s*\()", re.IGNORECASE),
    re.compile(r"(\b(?:os\.system|subprocess|exec|spawn)\s)", re.IGNORECASE),
    # Data exfiltration commands in metadata
    re.compile(r"\b(?:curl|wget|nc|ncat)\s+[\"']?https?://", re.IGNORECASE),
    # API key or credential patterns in metadata
    re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,}|api[-_]?key\s*[:=]\s*[^\s\n]{10,})", re.IGNORECASE),
]

# --- Chunk-splitting detection ---

_SPLIT_INJECTION_MARKERS = [
    # Instruction fragments that only become malicious when concatenated
    re.compile(r"(?<=[.!?])\s*(begin|start|first\s+part|step\s+1)", re.IGNORECASE),
    re.compile(r"(?<=[.!?])\s*(end|stop|finish|last\s+part|step\s+\d+)", re.IGNORECASE),
    # HTML/XML tag injection across chunks
    re.compile(r"(<[a-z][a-z0-9]*[^>]*>)", re.IGNORECASE),
    re.compile(r"(</[a-z][a-z0-9]*>)", re.IGNORECASE),
    # SQL-like patterns in documents
    re.compile(r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b)", re.IGNORECASE),
]


class RAGScanner:
    """Main scanner class for RAG pipeline security assessment."""

    def __init__(
        self,
        *,
        chunk_size: int = 500,
        chunk_overlap: int = 50,
        embedding_dim: int = 1536,
        similarity_threshold: float = 0.95,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.embedding_dim = embedding_dim
        self.similarity_threshold = similarity_threshold
        self._findings: list[Finding] = []

    def scan_documents(
        self,
        documents: list[Document],
        *,
        check_prompt_injection: bool = True,
        check_metadata: bool = True,
        check_chunk_splitting: bool = True,
    ) -> ScanReport:
        """Scan a collection of documents for RAG pipeline security issues."""
        self._findings = []

        for doc in documents:
            doc_id = doc.id or self._hash_content(doc.text[:100])

            if check_prompt_injection:
                self._scan_prompt_injection(doc, doc_id)

            if check_metadata:
                self._scan_metadata(doc, doc_id)

            if check_chunk_splitting:
                self._scan_chunk_splitting(doc, doc_id)

            self._scan_canonical_injection(doc, doc_id)

        return ScanReport(
            total_documents=len(documents),
            findings=self._findings,
            severity_summary=self._severity_summary(),
        )

    def _scan_prompt_injection(self, doc: Document, doc_id: str) -> None:
        for i, pattern in enumerate(_INJECTION_PATTERNS):
            matches = list(pattern.finditer(doc.text))
            if matches:
                self._findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION_IN_DOCUMENT,
                    severity=Severity.CRITICAL,
                    document_id=doc_id,
                    description=f"Prompt injection pattern detected in document",
                    evidence=matches[0].group(0)[:100],
                    remediation=f"Sanitize or reject document containing injection payload: pattern {i}",
                    owasp_mapping="LLM07: Training Data Poisoning",
                ))

    def _scan_metadata(self, doc: Document, doc_id: str) -> None:
        metadata_str = str(doc.metadata or {})
        for i, pattern in enumerate(_METADATA_INJECTION_PATTERNS):
            matches = list(pattern.finditer(metadata_str))
            if matches:
                self._findings.append(Finding(
                    finding_type=FindingType.METADATA_INJECTION,
                    severity=Severity.HIGH,
                    document_id=doc_id,
                    description=f"Malicious payload detected in document metadata",
                    evidence=matches[0].group(0)[:100],
                    remediation="Strip all executable fields from document metadata before ingestion",
                    owasp_mapping="LLM07: Training Data Poisoning",
                ))

    def _scan_chunk_splitting(self, doc: Document, doc_id: str) -> None:
        for i, pattern in enumerate(_SPLIT_INJECTION_MARKERS):
            matches = list(pattern.finditer(doc.text))
            if matches:
                self._findings.append(Finding(
                    finding_type=FindingType.CHUNK_SPLIT_ATTACK,
                    severity=Severity.MEDIUM,
                    document_id=doc_id,
                    description=f"Potential chunk-splitting attack marker detected",
                    evidence=matches[0].group(0)[:80],
                    remediation="Validate cross-chunk instruction boundaries and reassemble before scanning",
                    owasp_mapping="LLM06: Insecure Output Handling",
                ))

    def _scan_canonical_injection(self, doc: Document, doc_id: str) -> None:
        """Detect canonicalization bypass attempts."""
        normalized = doc.text.lower().strip()
        if "ignore previous" in normalized and "instruction:" in normalized:
            self._findings.append(Finding(
                finding_type=FindingType.CANONICAL_INJECTION,
                severity=Severity.CRITICAL,
                document_id=doc_id,
                description="Canonical injection bypass attempt in document body",
                evidence="Combined 'ignore previous' + 'instruction' pattern",
                remediation="Apply input canonicalization and reject adversarial patterns",
                owasp_mapping="LLM01: Prompt Injection",
            ))

    def _severity_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in self._findings:
            key = f.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    @staticmethod
    def _hash_content(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:12]


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
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    def summary(self) -> str:
        lines = [
            f"RAG Security Scan Report",
            f"=" * 40,
            f"Documents scanned: {self.total_documents}",
            f"Total findings: {len(self.findings)}",
        ]
        for sev, count in sorted(self.severity_summary.items()):
            lines.append(f"  {sev.upper()}: {count}")
        return "\n".join(lines)