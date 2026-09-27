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

from ragguard.pipeline import RAGPipelineGuard
from ragguard.scanner import (
    Document,
    Finding,
    FindingType,
    RAGScanner,
    ScanReport,
    Severity,
    canonicalize,
    resolve_document_id,
)
from ragguard.vector_check import VectorStoreIntegrityChecker

__version__ = "0.1.1"

__all__ = [
    "Document",
    "Finding",
    "FindingType",
    "RAGPipelineGuard",
    "RAGScanner",
    "ScanReport",
    "Severity",
    "VectorStoreIntegrityChecker",
    "canonicalize",
    "resolve_document_id",
    "__version__",
]
