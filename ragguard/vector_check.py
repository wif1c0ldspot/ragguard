"""Vector store integrity checker — detects embedding poisoning and cross-user contamination."""

from __future__ import annotations

import hashlib

import numpy as np

from ragguard.scanner import (
    LLM08_VECTOR_WEAKNESSES,
    Document,
    Finding,
    FindingType,
    Severity,
)

#: Text-similarity ceiling below which near-identical embeddings are treated as
#: suspicious (legitimate duplicates are usually near-identical in text too).
TEXT_SIMILARITY_CEILING = 0.8


class VectorStoreIntegrityChecker:
    """Validates vector store integrity and detects embedding-space attacks."""

    def __init__(self, similarity_threshold: float = 0.95):
        self.similarity_threshold = similarity_threshold

    def check_embedding_consistency(
        self,
        documents: list[Document],
        query_embedding: list[float] | None = None,
        top_k: int = 10,
    ) -> list[Finding]:
        """Flag near-duplicate embeddings whose underlying text is dissimilar.

        That signature — high cosine similarity, low text similarity — is the
        cheap way to detect adversarial embeddings injected alongside legitimate
        documents in the same vector space.

        Args:
            documents: Documents that carry embeddings.
            query_embedding: Accepted for API compatibility; unused (the check
                is self-contained over the stored corpus).
            top_k: Accepted for API compatibility; unused.
        """
        findings: list[Finding] = []

        pairs = [(d, d.embedding) for d in documents if d.embedding is not None]
        if len(pairs) < 2:
            return findings

        docs_with_embeddings = [d for d, _ in pairs]
        vectors = np.array([emb for _, emb in pairs], dtype=float)
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1e-10
        normalized = vectors / norms
        sim_matrix = normalized @ normalized.T

        n = len(docs_with_embeddings)
        for i in range(n):
            for j in range(i + 1, n):
                sim = float(sim_matrix[i, j])
                if sim <= self.similarity_threshold:
                    continue
                doc_i = docs_with_embeddings[i]
                doc_j = docs_with_embeddings[j]
                text_sim = self._text_similarity(doc_i.text, doc_j.text)
                if text_sim >= TEXT_SIMILARITY_CEILING:
                    continue  # legitimate near-duplicate
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
                        "Investigate the document pair for adversarial embedding injection "
                        "(OWASP LLM04/LLM08) and re-embed from a verified source."
                    ),
                    owasp_mapping=LLM08_VECTOR_WEAKNESSES,
                    family="embedding_poisoning_cos_high_text_low",
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

        user_embeddings: dict[str, list[tuple[Document, list[float]]]] = {}
        for user_id, docs in user_documents.items():
            user_embeddings[user_id] = [
                (d, d.embedding) for d in docs if d.embedding is not None
            ]

        users = list(user_embeddings.keys())
        for i in range(len(users)):
            for j in range(i + 1, len(users)):
                u1, u2 = users[i], users[j]
                for doc1, emb1 in user_embeddings[u1]:
                    for _doc2, emb2 in user_embeddings[u2]:
                        cos_sim = self._cosine_similarity(
                            np.asarray(emb1, dtype=float), np.asarray(emb2, dtype=float)
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
                                    "Partition the index per tenant rather than filtering after "
                                    "search (OWASP LLM02/LLM08), and re-check entitlements on "
                                    "retrieved chunks before they enter the context window."
                                ),
                                owasp_mapping=LLM08_VECTOR_WEAKNESSES,
                                family="cross_user_embedding_proximity",
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
