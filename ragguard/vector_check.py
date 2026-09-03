"""Vector store integrity checker — detects embedding poisoning and cross-user contamination."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

import numpy as np

from ragguard.scanner import (
    Document,
    Finding,
    FindingType,
    RAGScanner,
    Severity,
)


class VectorStoreIntegrityChecker:
    """Validates vector store integrity and detects embedding-space attacks."""

    def __init__(self, similarity_threshold: float = 0.95):
        self.similarity_threshold = similarity_threshold

    def check_embedding_consistency(
        self,
        documents: list[Document],
        query_embedding: list[float],
        top_k: int = 10,
    ) -> list[Finding]:
        """Check if top-k retrievals are consistent with expected document set."""
        findings: list[Finding] = []

        # Compute pairwise similarities
        docs_with_embeddings = [d for d in documents if d.embedding is not None]
        if len(docs_with_embeddings) < 2:
            return findings

        vectors = np.array([d.embedding for d in docs_with_embeddings])  # type: ignore[union-attr]
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1e-10
        normalized = vectors / norms

        # Cosine similarity matrix
        sim_matrix = normalized @ normalized.T

        # Detect near-duplicate embeddings (potential poisoning)
        n = len(docs_with_embeddings)
        for i in range(n):
            for j in range(i + 1, n):
                if i == j:
                    continue
                sim = float(sim_matrix[i, j])
                if sim > self.similarity_threshold:
                    doc_i = docs_with_embeddings[i]
                    doc_j = docs_with_embeddings[j]
                    # Only flag if text content differs significantly
                    text_sim = self._text_similarity(doc_i.text, doc_j.text)
                    if text_sim < 0.8:
                        findings.append(Finding(
                            finding_type=FindingType.EMBEDDING_POISONING,
                            severity=Severity.HIGH,
                            document_id=doc_i.id or self._hash(doc_i.text[:50]),
                            description=(
                                f"High embedding similarity ({sim:.4f}) but low text "
                                f"similarity ({text_sim:.4f}) — possible embedding poisoning"
                            ),
                            evidence=f"cos_sim={sim:.4f}, text_sim={text_sim:.4f}",
                            remediation=(
                                "Investigate document pair for adversarial embedding "
                                "injection. Re-embed from verified source."
                            ),
                            owasp_mapping="LLM07: Training Data Poisoning",
                        ))

        return findings

    def check_cross_user_contamination(
        self,
        user_documents: dict[str, list[Document]],
    ) -> list[Finding]:
        """Check for cross-user contamination in shared vector stores.

        Args:
            user_documents: Map of user_id -> list of their documents.
                All documents share the same vector space.
        """
        findings: list[Finding] = []

        # Build per-user embedding clusters
        user_embeddings: dict[str, list[tuple[Document, list[float]]]] = {}
        for user_id, docs in user_documents.items():
            user_embeddings[user_id] = [
                (d, d.embedding) for d in docs if d.embedding is not None  # type: ignore[misc]
            ]

        # Compare across users for anomalous proximity
        users = list(user_embeddings.keys())
        for i in range(len(users)):
            for j in range(i + 1, len(users)):
                u1, u2 = users[i], users[j]
                for doc1, emb1 in user_embeddings[u1]:
                    for doc2, emb2 in user_embeddings[u2]:
                        if emb1 is None or emb2 is None:
                            continue
                        cos_sim = self._cosine_similarity(
                            np.array(emb1), np.array(emb2)
                        )
                        if cos_sim > self.similarity_threshold:
                            findings.append(Finding(
                                finding_type=FindingType.CROSS_USER_CONTAMINATION,
                                severity=Severity.CRITICAL,
                                document_id=doc1.id or self._hash(doc1.text[:50]),
                                description=(
                                    f"Cross-user contamination detected between "
                                    f"user '{u1}' and user '{u2}' documents "
                                    f"(similarity: {cos_sim:.4f})"
                                ),
                                evidence=f"Shared embedding space proximity: {cos_sim:.4f}",
                                remediation=(
                                    "Enforce per-user document isolation in vector store. "
                                    "Use metadata-based filtering and validate tenant boundaries."
                                ),
                                owasp_mapping="LLM01: Prompt Injection",
                            ))

        return findings

    @staticmethod
    def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
        norm_a = np.linalg.norm(a)
        norm_b = np.linalg.norm(b)
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return float(np.dot(a, b) / (norm_a * norm_b))

    @staticmethod
    def _text_similarity(text_a: str, text_b: str) -> float:
        """Rough Jaccard-based text similarity for flagging."""
        words_a = set(text_a.lower().split())
        words_b = set(text_b.lower().split())
        if not words_a or not words_b:
            return 0.0
        return len(words_a & words_b) / len(words_a | words_b)

    @staticmethod
    def _hash(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:12]