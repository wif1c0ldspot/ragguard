"""RAG Pipeline Security Scanner.

ragguard detects security vulnerabilities in Retrieval-Augmented Generation
(RAG) pipelines: prompt injection via poisoned documents, metadata injection,
chunk-splitting exploits, embedding poisoning, and cross-user contamination in
shared vector stores.

Findings map to the **OWASP Top 10 for LLM Applications 2025** — primarily
LLM01 (Prompt Injection), LLM02 (Sensitive Information Disclosure),
LLM05 (Improper Output Handling), LLM07 (System Prompt Leakage) and
LLM08 (Vector and Embedding Weaknesses).
"""

from ragguard.boundary import Boundary, BoundaryResult, ContentBlockedError, ContentBoundary
from ragguard.pipeline import (
    REPORT_SCHEMA_VERSION,
    IngestionDecision,
    IngestionPolicy,
    RAGPipelineGuard,
)
from ragguard.scanner import (
    RULESET_VERSION,
    Document,
    Finding,
    FindingType,
    RAGScanner,
    ScanReport,
    Severity,
    canonicalize,
    resolve_document_id,
)
from ragguard.vector_check import VectorAssessment, VectorStoreIntegrityChecker

__version__ = "0.1.1"

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "RULESET_VERSION",
    "Boundary",
    "BoundaryResult",
    "ContentBlockedError",
    "ContentBoundary",
    "Document",
    "Finding",
    "FindingType",
    "IngestionDecision",
    "IngestionPolicy",
    "RAGPipelineGuard",
    "RAGScanner",
    "ScanReport",
    "Severity",
    "VectorAssessment",
    "VectorStoreIntegrityChecker",
    "canonicalize",
    "resolve_document_id",
    "__version__",
]
