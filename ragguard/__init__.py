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

from typing import TYPE_CHECKING, Any

from ragguard.boundary import Boundary, BoundaryResult, ContentBlockedError, ContentBoundary
from ragguard.pipeline import (
    REPORT_SCHEMA_VERSION,
    BatchDecision,
    DocumentDecision,
    IngestionDecision,
    IngestionPolicy,
    RAGPipelineGuard,
    load_schema,
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

if TYPE_CHECKING:
    from ragguard.vector_check import VectorAssessment, VectorStoreIntegrityChecker

__version__ = "0.2.0"

# The vector checker needs numpy, which ships in the optional ``vector`` extra.
# Import it lazily so text scanning and the worker stay standard-library only.
_VECTOR_EXPORTS = frozenset({"VectorAssessment", "VectorStoreIntegrityChecker"})


def __getattr__(name: str) -> Any:
    if name in _VECTOR_EXPORTS:
        try:
            from ragguard import vector_check
        except ModuleNotFoundError as exc:
            if exc.name != "numpy":
                raise
            raise ImportError(
                f"ragguard.{name} requires numpy; install the extra: ragguard[vector]"
            ) from exc
        return getattr(vector_check, name)
    raise AttributeError(f"module 'ragguard' has no attribute {name!r}")

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "RULESET_VERSION",
    "BatchDecision",
    "Boundary",
    "BoundaryResult",
    "ContentBlockedError",
    "ContentBoundary",
    "Document",
    "DocumentDecision",
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
    "load_schema",
    "resolve_document_id",
    "__version__",
]
