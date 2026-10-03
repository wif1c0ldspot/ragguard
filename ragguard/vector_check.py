"""Bounded embedding anomaly checks; similarity alone does not prove an attack."""

from __future__ import annotations

import re
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

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
# Lexical similarity only inspects this many leading characters per text, which
# bounds per-pair cost on very long documents.
TEXT_SIMILARITY_MAX_CHARS = 20_000

_WORD_RE = re.compile(r"\w+")
_WHITESPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class _TextFeatures:
    normalized: str
    words: np.ndarray  # sorted unique int64 hashes of normalized word tokens
    trigrams: np.ndarray  # sorted unique int64 encodings of character 3-grams


def _text_features(text: str) -> _TextFeatures:
    normalized = _WHITESPACE_RE.sub(" ", text[:TEXT_SIMILARITY_MAX_CHARS].lower()).strip()
    words = np.unique(np.fromiter(
        (hash(word) for word in _WORD_RE.findall(normalized)), dtype=np.int64,
    ))
    codes = np.frombuffer(normalized.encode("utf-32-le"), dtype=np.uint32).astype(np.int64)
    if codes.size >= 3:
        # Code points fit in 21 bits, so three of them pack losslessly into 63 bits.
        trigrams = np.unique((codes[:-2] << 42) | (codes[1:-1] << 21) | codes[2:])
    else:
        trigrams = np.empty(0, dtype=np.int64)
    return _TextFeatures(normalized, words, trigrams)


def _jaccard(a: np.ndarray, b: np.ndarray) -> float:
    if a.size == 0 or b.size == 0:
        return 0.0
    shared = np.intersect1d(a, b, assume_unique=True).size
    return shared / (a.size + b.size - shared)


def _feature_similarity(a: _TextFeatures, b: _TextFeatures) -> float:
    if a.normalized == b.normalized:
        return 1.0
    return max(_jaccard(a.words, b.words), _jaccard(a.trigrams, b.trigrams))


def _validate_unit_interval(name: str, value: object) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not np.isfinite(value)
        or not -1 <= value <= 1
    ):
        raise ValueError(f"{name} must be finite and between -1 and 1")


def _validate_positive_int(name: str, value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")


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

    Pairwise similarities are computed in row tiles of ``block_size`` rows, so
    auxiliary memory is O(block_size x documents) rather than O(documents²).
    """

    def __init__(
        self,
        similarity_threshold: float = 0.95,
        *,
        max_documents: int = 2000,
        max_findings: int = 10000,
        max_comparisons: int = 2_000_000,
        max_dimensions: int = 16384,
        block_size: int = 256,
    ):
        _validate_unit_interval("similarity_threshold", similarity_threshold)
        for name, value in (
            ("max_documents", max_documents), ("max_findings", max_findings),
            ("max_comparisons", max_comparisons), ("max_dimensions", max_dimensions),
            ("block_size", block_size),
        ):
            _validate_positive_int(name, value)
        self.similarity_threshold = similarity_threshold
        self.max_documents = max_documents
        self.max_findings = max_findings
        self.max_comparisons = max_comparisons
        self.max_dimensions = max_dimensions
        self.block_size = block_size

    def _normalize(self, embedding: Any, dimension: int | None) -> np.ndarray:
        """Validate one embedding and return it as a unit-length float64 vector."""
        raw = np.asarray(embedding)
        if raw.ndim != 1 or raw.size == 0 or raw.dtype.kind not in "ifu":
            raise ValueError("expected a nonempty numeric vector")
        if raw.size > self.max_dimensions:
            raise ValueError("max_dimensions exceeded")
        vector = raw.astype(np.float64)
        if not np.isfinite(vector).all():
            raise ValueError("all components must be finite")
        if dimension is not None and vector.size != dimension:
            raise ValueError("embedding dimensions must match")
        # Scale first so very large/small finite inputs normalize safely.
        scale = float(np.max(np.abs(vector)))
        if scale == 0:
            raise ValueError("embedding norm must be nonzero")
        vector = vector / scale
        normalized: np.ndarray = vector / np.linalg.norm(vector)
        return normalized

    def _prepare(self, documents: list[Document]) -> tuple[list[int], np.ndarray]:
        if len(documents) > self.max_documents:
            raise ValueError("max_documents exceeded; assess a bounded corpus")
        indices: list[int] = []
        vectors: list[np.ndarray] = []
        dimension: int | None = None
        for index, document in enumerate(documents):
            if document.embedding is None:
                continue
            try:
                vector = self._normalize(document.embedding, dimension)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"Invalid embedding at document index {index}: {exc}") from exc
            dimension = vector.size
            indices.append(index)
            vectors.append(vector)
        matrix = np.vstack(vectors) if vectors else np.empty((0, 0), dtype=np.float64)
        return indices, matrix

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
        """Return anomaly findings and explicit missing-embedding coverage.

        Pairs with near-identical embeddings but low lexical overlap are reported
        as MEDIUM heuristics: paraphrases and translations trigger them too. Use
        :meth:`assess_embedding_fidelity` for a verified tampering signal.
        """
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

    def assess_embedding_fidelity(
        self,
        documents: list[Document],
        embed_fn: Callable[[list[str]], Sequence[Sequence[float]]],
        *,
        min_similarity: float = 0.9,
        batch_size: int = 64,
    ) -> VectorAssessment:
        """Re-embed each document's text and compare it with its stored embedding.

        This is the reliable tampering signal: it compares the stored vector with
        the same model's embedding of the stored text, so a vector that was
        swapped, perturbed or computed from different text shows up as low
        cosine similarity regardless of what other documents look like. The
        caller must pass an ``embed_fn`` backed by the same embedding model and
        version that produced the stored vectors; otherwise every document may
        be flagged.

        ``embed_fn`` receives lists of at most ``batch_size`` texts and must
        return one vector per text, in order. Re-embedded vectors are validated
        like stored ones (numeric, finite, nonzero) and must match the stored
        dimension. Documents without a stored embedding are skipped and listed
        in the coverage; ``compared_pairs`` counts stored/re-embedded
        comparisons. A finding is emitted when cosine < ``min_similarity``.
        The comparison budget is checked before calling ``embed_fn``.
        """
        _validate_unit_interval("min_similarity", min_similarity)
        _validate_positive_int("batch_size", batch_size)
        indices, stored = self._prepare(documents)
        if len(indices) > self.max_comparisons:
            raise ValueError("max_comparisons exceeded; narrow the assessment or raise the budget")
        dimension = stored.shape[1] if indices else None
        findings: list[Finding] = []
        for start in range(0, len(indices), batch_size):
            batch = indices[start:start + batch_size]
            returned = embed_fn([documents[index].text for index in batch])
            try:
                count = len(returned)
            except TypeError as exc:
                raise ValueError("embed_fn must return a sequence of vectors") from exc
            if count != len(batch):
                raise ValueError(
                    f"embed_fn returned {count} vectors for a batch of {len(batch)} texts"
                )
            for offset, index in enumerate(batch):
                try:
                    vector = self._normalize(returned[offset], None)
                except (TypeError, ValueError, OverflowError) as exc:
                    raise ValueError(
                        f"Invalid re-embedding at document index {index}: {exc}"
                    ) from exc
                if vector.size != dimension:
                    raise ValueError(
                        f"Invalid re-embedding at document index {index}: dimension "
                        f"{vector.size} does not match stored dimension {dimension}"
                    )
                similarity = float(np.clip(stored[start + offset] @ vector, -1, 1))
                if similarity >= min_similarity:
                    continue
                document = documents[index]
                self._append(findings, Finding(
                    finding_type=FindingType.EMBEDDING_POISONING,
                    severity=Severity.HIGH,
                    document_id=resolve_document_id(document),
                    document_index=index,
                    description=(
                        "Stored embedding does not match a re-embedding of the stored text; "
                        "the vector may have been tampered with or computed from other content"
                    ),
                    evidence=f"cos(stored, re-embedded)={similarity:.4f}",
                    remediation=(
                        "Confirm the same embedding model/version was used, then re-embed "
                        "from verified text and investigate how the stored vector changed."
                    ),
                    owasp_mapping=LLM08_VECTOR_WEAKNESSES,
                    family="embedding_text_mismatch",
                    confidence="verified-by-reembedding",
                ))
        return self._coverage(findings, documents, indices, len(indices))

    @staticmethod
    def _coverage(
        findings: list[Finding], documents: list[Document], indices: list[int], compared: int,
    ) -> VectorAssessment:
        assessed = set(indices)
        return VectorAssessment(
            findings=findings,
            total_documents=len(documents),
            assessed_documents=len(indices),
            skipped_document_indices=tuple(i for i in range(len(documents)) if i not in assessed),
            compared_pairs=compared,
        )

    @staticmethod
    def _similarity_tile(matrix: np.ndarray, start: int, stop: int) -> np.ndarray:
        """Cosine similarities of rows [start, stop) against rows [start, n)."""
        tile: np.ndarray = matrix[start:stop] @ matrix[start:].T
        np.clip(tile, -1, 1, out=tile)
        return tile

    def _assess(
        self, documents: list[Document], owners: list[str] | None = None,
    ) -> VectorAssessment:
        indices, matrix = self._prepare(documents)
        pair_count = len(indices) * (len(indices) - 1) // 2
        owner_codes: np.ndarray | None = None
        if owners is not None:
            codes: dict[str, int] = {}
            counts: dict[str, int] = {}
            for index in indices:
                counts[owners[index]] = counts.get(owners[index], 0) + 1
                codes.setdefault(owners[index], len(codes))
            pair_count -= sum(n * (n - 1) // 2 for n in counts.values())
            owner_codes = np.array([codes[owners[index]] for index in indices], dtype=np.int64)
        if pair_count > self.max_comparisons:
            raise ValueError("max_comparisons exceeded; narrow the assessment or raise the budget")
        findings: list[Finding] = []
        features: dict[int, _TextFeatures] = {}

        def text_features(position: int) -> _TextFeatures:
            cached = features.get(position)
            if cached is None:
                cached = features[position] = _text_features(documents[indices[position]].text)
            return cached

        n = len(indices)
        for start in range(0, n, self.block_size):
            stop = min(start + self.block_size, n)
            tile = self._similarity_tile(matrix, start, stop)
            # Column c of the tile is position start + c; keep only j > i.
            mask = np.triu(tile > self.similarity_threshold, k=1)
            if owner_codes is not None:
                mask &= owner_codes[start:stop, None] != owner_codes[None, start:]
            # Row-major nonzero order preserves ascending (i, j) finding order.
            for row, col in zip(*np.nonzero(mask), strict=True):
                i, j = start + int(row), start + int(col)
                text_similarity = _feature_similarity(text_features(i), text_features(j))
                if text_similarity >= TEXT_SIMILARITY_CEILING:
                    continue
                self._append(findings, self._pair_finding(
                    documents, owners, indices[i], indices[j],
                    float(tile[row, col]), text_similarity,
                ))
        return self._coverage(findings, documents, indices, pair_count)

    @staticmethod
    def _pair_finding(
        documents: list[Document], owners: list[str] | None,
        index_i: int, index_j: int, similarity: float, text_similarity: float,
    ) -> Finding:
        first, second = documents[index_i], documents[index_j]
        cross_user = owners is not None
        return Finding(
            finding_type=(FindingType.CROSS_USER_CONTAMINATION if cross_user
                          else FindingType.EMBEDDING_POISONING),
            severity=Severity.MEDIUM,
            document_id=resolve_document_id(first),
            document_index=index_i,
            related_document_ids=(resolve_document_id(first), resolve_document_id(second)),
            related_document_indices=(index_i, index_j),
            description=(
                "Cross-user embedding proximity anomaly; "
                "not evidence of unauthorized access"
                if cross_user else
                "High embedding similarity with low lexical overlap; possible embedding "
                "anomaly. Lexical heuristic only: paraphrases and translations can "
                "trigger it. Use re-embedding verification to confirm tampering"
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
                "verify with assess_embedding_fidelity and re-embed from verified "
                "text if tampering is confirmed."
            ),
            owasp_mapping=LLM08_VECTOR_WEAKNESSES,
            family=("cross_user_embedding_proximity" if cross_user
                    else "embedding_poisoning_cos_high_text_low"),
            confidence="heuristic",
        )

    @staticmethod
    def _text_similarity(text_a: str, text_b: str) -> float:
        """Rough lexical overlap; an anomaly signal, not semantic ground truth.

        Returns the maximum of word-set Jaccard over normalized tokens (lowercase,
        punctuation stripped) and character 3-gram Jaccard over lowercase,
        whitespace-collapsed text. Only the first TEXT_SIMILARITY_MAX_CHARS
        characters of each text are considered.
        """
        return _feature_similarity(_text_features(text_a), _text_features(text_b))
