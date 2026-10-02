"""Bounded embedding anomaly checks; similarity alone does not prove an attack."""

from __future__ import annotations

import warnings
from dataclasses import dataclass

import numpy as np

from ragguard.scanner import (
    LLM08_VECTOR_WEAKNESSES,
    Document,
    Finding,
    FindingType,
    Severity,
    resolve_document_id,
)

TEXT_SIMILARITY_CEILING = 0.8


@dataclass
class VectorAssessment:
    """Coverage and findings for one complete assessment (never silently truncated)."""

    findings: list[Finding]
    total_documents: int
    assessed_documents: int
    skipped_document_indices: tuple[int, ...]
    compared_pairs: int


class VectorStoreIntegrityChecker:
    """Assess anomalies in a single embedding space with explicit resource budgets.

    Missing embeddings are skipped and counted by the assessment methods. Invalid
    embeddings raise ValueError even for singleton inputs. The checker cannot
    establish tenant leakage without independent entitlement/retrieval evidence.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.95,
        *,
        max_documents: int = 2000,
        max_findings: int = 10000,
        max_comparisons: int = 2_000_000,
        max_dimensions: int = 16384,
    ):
        if (
            isinstance(similarity_threshold, bool)
            or not isinstance(similarity_threshold, (int, float))
            or not np.isfinite(similarity_threshold)
            or not -1 <= similarity_threshold <= 1
        ):
            raise ValueError("similarity_threshold must be finite and between -1 and 1")
        for name, value in (
            ("max_documents", max_documents), ("max_findings", max_findings),
            ("max_comparisons", max_comparisons), ("max_dimensions", max_dimensions),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.similarity_threshold = similarity_threshold
        self.max_documents = max_documents
        self.max_findings = max_findings
        self.max_comparisons = max_comparisons
        self.max_dimensions = max_dimensions

    def _prepare(self, documents: list[Document]) -> tuple[list[int], list[np.ndarray]]:
        if len(documents) > self.max_documents:
            raise ValueError("max_documents exceeded; assess a bounded corpus")
        indices: list[int] = []
        vectors: list[np.ndarray] = []
        dimension: int | None = None
        for index, document in enumerate(documents):
            if document.embedding is None:
                continue
            try:
                raw = np.asarray(document.embedding)
                if raw.ndim != 1 or raw.size == 0 or raw.dtype.kind not in "ifu":
                    raise ValueError("expected a nonempty numeric vector")
                if raw.size > self.max_dimensions:
                    raise ValueError("max_dimensions exceeded")
                vector = raw.astype(float)
                if not np.isfinite(vector).all():
                    raise ValueError("all components must be finite")
                if dimension is not None and vector.size != dimension:
                    raise ValueError("embedding dimensions must match")
                dimension = vector.size
                # Scale first so very large/small finite inputs normalize safely.
                scale = float(np.max(np.abs(vector)))
                if scale == 0:
                    raise ValueError("embedding norm must be nonzero")
                vector = vector / scale
                vector = vector / np.linalg.norm(vector)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"Invalid embedding at document index {index}: {exc}") from exc
            indices.append(index)
            vectors.append(vector)
        return indices, vectors

    def _append(self, findings: list[Finding], finding: Finding) -> None:
        if len(findings) >= self.max_findings:
            raise ValueError("max_findings exceeded; narrow the assessment or raise the budget")
        findings.append(finding)

    def check_embedding_consistency(
        self,
        documents: list[Document],
        query_embedding: list[float] | None = None,
        top_k: int | None = None,
    ) -> list[Finding]:
        """Return anomalies; deprecated query_embedding/top_k do not affect this check."""
        if query_embedding is not None or top_k is not None:
            warnings.warn(
                "query_embedding and top_k are unused and deprecated; this is a corpus check",
                DeprecationWarning,
                stacklevel=2,
            )
        return self.assess_embedding_consistency(documents).findings

    def assess_embedding_consistency(self, documents: list[Document]) -> VectorAssessment:
        """Return anomaly findings and explicit missing-embedding coverage."""
        return self._assess(documents)

    def check_cross_user_contamination(
        self, user_documents: dict[str, list[Document]],
    ) -> list[Finding]:
        """Return cross-user proximity anomalies, not confirmed contamination.

        The method name and CROSS_USER_CONTAMINATION finding type are retained
        for API compatibility. Exact/near text duplicates are not anomalies;
        public copies in different users' corpora do not establish a violation.
        """
        return self.assess_cross_user_proximity(user_documents).findings

    def assess_cross_user_proximity(
        self, user_documents: dict[str, list[Document]],
    ) -> VectorAssessment:
        """Compare across users; coverage indices follow mapping/list insertion order."""
        documents: list[Document] = []
        owners: list[str] = []
        for owner, docs in user_documents.items():
            if len(documents) + len(docs) > self.max_documents:
                raise ValueError("max_documents exceeded; assess a bounded corpus")
            documents.extend(docs)
            owners.extend([owner] * len(docs))
        return self._assess(documents, owners)

    def _assess(
        self, documents: list[Document], owners: list[str] | None = None,
    ) -> VectorAssessment:
        indices, vectors = self._prepare(documents)
        pair_count = len(indices) * (len(indices) - 1) // 2
        if owners is not None:
            counts: dict[str, int] = {}
            for index in indices:
                counts[owners[index]] = counts.get(owners[index], 0) + 1
            pair_count -= sum(n * (n - 1) // 2 for n in counts.values())
        if pair_count > self.max_comparisons:
            raise ValueError("max_comparisons exceeded; narrow the assessment or raise the budget")
        findings: list[Finding] = []
        # Pairwise dot products bound auxiliary memory to O(dimensions), not O(n²).
        for i, index_i in enumerate(indices):
            for j in range(i + 1, len(indices)):
                index_j = indices[j]
                if owners is not None and owners[index_i] == owners[index_j]:
                    continue
                similarity = float(np.clip(np.dot(vectors[i], vectors[j]), -1, 1))
                if similarity <= self.similarity_threshold:
                    continue
                first, second = documents[index_i], documents[index_j]
                text_similarity = self._text_similarity(first.text, second.text)
                if text_similarity >= TEXT_SIMILARITY_CEILING:
                    continue
                cross_user = owners is not None
                self._append(findings, Finding(
                    finding_type=(FindingType.CROSS_USER_CONTAMINATION if cross_user
                                  else FindingType.EMBEDDING_POISONING),
                    severity=Severity.MEDIUM if cross_user else Severity.HIGH,
                    document_id=resolve_document_id(first),
                    document_index=index_i,
                    related_document_ids=(resolve_document_id(first), resolve_document_id(second)),
                    related_document_indices=(index_i, index_j),
                    description=(
                        "Cross-user embedding proximity anomaly; "
                        "not evidence of unauthorized access"
                        if cross_user else
                        "High embedding similarity with dissimilar text; possible embedding anomaly"
                    ),
                    evidence=(
                        f"cos_sim={similarity:.4f}, text_sim={text_similarity:.4f}"
                        + (f", users=({owners[index_i]!r}, {owners[index_j]!r})"
                           if owners is not None else "")
                    ),
                    remediation=(
                        "Check source provenance, retrieval results and document entitlements; "
                        "embedding proximity alone does not establish leakage."
                        if cross_user else
                        "Review the pair's source provenance and embedding model/version; "
                        "re-embed from verified text if tampering is confirmed."
                    ),
                    owasp_mapping=LLM08_VECTOR_WEAKNESSES,
                    family=("cross_user_embedding_proximity" if cross_user
                            else "embedding_poisoning_cos_high_text_low"),
                ))
        assessed = set(indices)
        return VectorAssessment(
            findings=findings,
            total_documents=len(documents),
            assessed_documents=len(indices),
            skipped_document_indices=tuple(i for i in range(len(documents)) if i not in assessed),
            compared_pairs=pair_count,
        )

    @staticmethod
    def _text_similarity(text_a: str, text_b: str) -> float:
        """Rough lexical overlap; an anomaly signal, not semantic ground truth."""
        if text_a.strip().lower() == text_b.strip().lower():
            return 1.0
        words_a = set(text_a.lower().split())
        words_b = set(text_b.lower().split())
        if not words_a or not words_b:
            return 0.0
        return len(words_a & words_b) / len(words_a | words_b)
