"""Tests for the vector store integrity checker."""

import math
import time

import numpy as np
import pytest

from ragguard.scanner import Document, FindingType, Severity, resolve_document_id
from ragguard.vector_check import VectorStoreIntegrityChecker


def test_detects_embedding_poisoning():
    checker = VectorStoreIntegrityChecker(similarity_threshold=0.95)
    findings = checker.check_embedding_consistency([
        Document(id="a", text="Quarterly revenue grew by 12 percent.", embedding=[1.0, 0.0, 0.0]),
        Document(id="b", text="Totally unrelated payload text.", embedding=[1.0, 0.0001, 0.0]),
    ])

    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.EMBEDDING_POISONING
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].owasp_mapping.startswith("LLM08")


def test_legitimate_duplicate_is_not_flagged():
    checker = VectorStoreIntegrityChecker(similarity_threshold=0.95)
    text = "Quarterly revenue grew by 12 percent."
    findings = checker.check_embedding_consistency([
        Document(id="a", text=text, embedding=[1.0, 0.0, 0.0]),
        Document(id="b", text=text, embedding=[1.0, 0.0, 0.0]),
    ])

    assert findings == []


def test_distinct_embeddings_are_not_flagged():
    checker = VectorStoreIntegrityChecker(similarity_threshold=0.95)
    findings = checker.check_embedding_consistency([
        Document(id="a", text="Revenue grew.", embedding=[1.0, 0.0, 0.0]),
        Document(id="b", text="Weather forecast.", embedding=[0.0, 1.0, 0.0]),
    ])

    assert findings == []


def test_detects_cross_user_contamination():
    checker = VectorStoreIntegrityChecker(similarity_threshold=0.95)
    findings = checker.check_cross_user_contamination({
        "user_a": [Document(id="a1", text="Private payroll data.", embedding=[1.0, 0.0, 0.0])],
        "user_b": [
            Document(id="b1", text="Unrelated weather notes.", embedding=[1.0, 0.0001, 0.0])
        ],
    })

    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.CROSS_USER_CONTAMINATION
    assert findings[0].severity.value == "medium"
    assert "not evidence of unauthorized access" in findings[0].description
    assert findings[0].related_document_ids == ("a1", "b1")
    assert "users=('user_a', 'user_b')" in findings[0].evidence
    assert findings[0].related_document_indices == (0, 1)
    assert findings[0].owasp_mapping.startswith("LLM08")


def test_documents_without_embeddings_are_skipped():
    checker = VectorStoreIntegrityChecker()
    assert checker.check_embedding_consistency([
        Document(id="a", text="no embedding"),
        Document(id="b", text="also none"),
    ]) == []


@pytest.mark.parametrize("embedding", [
    [], [0, 0], [float("nan")], [float("inf")], [[1, 2]], ["1"], [True],
])
def test_invalid_singleton_vectors_fail_explicitly(embedding):
    document = Document(text="a", embedding=embedding)
    checker = VectorStoreIntegrityChecker()
    with pytest.raises(ValueError, match="document index 0"):
        checker.check_embedding_consistency([document])
    with pytest.raises(ValueError, match="document index 0"):
        checker.check_cross_user_contamination({"user": [document]})


def test_mismatched_dimensions_fail_even_within_one_user():
    documents = [Document(text="a", embedding=[1]), Document(text="b", embedding=[1, 2])]
    checker = VectorStoreIntegrityChecker()
    with pytest.raises(ValueError, match="dimensions must match"):
        checker.check_embedding_consistency(documents)
    with pytest.raises(ValueError, match="dimensions must match"):
        checker.check_cross_user_contamination({"user": documents})


@pytest.mark.parametrize("threshold", [-1.1, 1.1, float("nan"), float("inf"), True, "0.9"])
def test_invalid_threshold(threshold):
    with pytest.raises(ValueError, match="similarity_threshold"):
        VectorStoreIntegrityChecker(threshold)


def test_threshold_boundary_is_strict():
    docs = [Document(text="a", embedding=[1, 0]), Document(text="b", embedding=[1, 0])]
    assert VectorStoreIntegrityChecker(1).check_embedding_consistency(docs) == []


def test_public_duplicates_are_not_cross_user_violations():
    text = "Public documentation licensed for sharing"
    assert VectorStoreIntegrityChecker().check_cross_user_contamination({
        "alice": [Document(text=text, embedding=[1, 0])],
        "bob": [Document(text=text, embedding=[1, 0])],
    }) == []


def test_report_counts_missing_and_pair_order_and_uses_full_ids():
    docs = [
        Document(text="no embedding"),
        Document(text="common prefix " * 10 + "alpha", embedding=[1, 0]),
        Document(text="unrelated beta", embedding=[1, 0]),
        Document(text="independent gamma", embedding=[1, 0]),
    ]
    report = VectorStoreIntegrityChecker().assess_embedding_consistency(docs)
    assert (report.total_documents, report.assessed_documents, report.compared_pairs) == (4, 3, 3)
    assert report.skipped_document_indices == (0,)
    assert [f.related_document_ids for f in report.findings] == [
        (resolve_document_id(docs[i]), resolve_document_id(docs[j]))
        for i, j in [(1, 2), (1, 3), (2, 3)]
    ]
    assert [f.document_index for f in report.findings] == [1, 1, 2]


def test_cross_user_report_only_counts_cross_user_pairs():
    doc = Document(text="public", embedding=[1, 0])
    report = VectorStoreIntegrityChecker().assess_cross_user_proximity({
        "alice": [doc, Document(text="missing"), doc], "bob": [doc],
    })
    assert report.compared_pairs == 2
    assert report.skipped_document_indices == (1,)
    assert report.findings == []


@pytest.mark.parametrize("budget", ["max_documents", "max_findings", "max_comparisons"])
def test_exceeded_budgets_fail_without_partial_result(budget):
    docs = [Document(text=t, embedding=[1, 0]) for t in ["alpha", "beta", "gamma"]]
    checker = VectorStoreIntegrityChecker(**{budget: 1})
    with pytest.raises(ValueError, match=budget):
        checker.check_embedding_consistency(docs)
    with pytest.raises(ValueError, match=budget):
        checker.check_cross_user_contamination({str(i): [doc] for i, doc in enumerate(docs)})


@pytest.mark.parametrize("budget", [
    "max_documents", "max_findings", "max_comparisons", "max_dimensions",
])
@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_budget_validation(budget, value):
    with pytest.raises(ValueError, match=budget):
        VectorStoreIntegrityChecker(**{budget: value})


def test_dimension_budget():
    with pytest.raises(ValueError, match="max_dimensions"):
        VectorStoreIntegrityChecker(max_dimensions=1).check_embedding_consistency([
            Document(text="a", embedding=[1, 2]),
        ])


@pytest.mark.parametrize("scale", [1e-300, 1e300])
def test_large_and_small_finite_vectors_normalize_safely(scale):
    findings = VectorStoreIntegrityChecker().check_embedding_consistency([
        Document(text="alpha", embedding=[scale, scale]),
        Document(text="beta", embedding=[scale, scale]),
    ])
    assert len(findings) == 1


@pytest.mark.parametrize("kwargs", [{"top_k": 10}, {"query_embedding": [1, 0]}])
def test_unused_parameters_emit_deprecation_warning(kwargs):
    with pytest.warns(DeprecationWarning, match="unused"):
        VectorStoreIntegrityChecker().check_embedding_consistency([], **kwargs)


def test_pair_indices_disambiguate_duplicate_explicit_ids():
    docs = [Document(id="same", text=t, embedding=[1]) for t in ["alpha", "beta"]]
    finding = VectorStoreIntegrityChecker().check_embedding_consistency(docs)[0]
    assert finding.related_document_ids == ("same", "same")
    assert finding.related_document_indices == (0, 1)


# --- Tiled similarity matches a brute-force reference ----------------------


def _reference_pairs(documents, threshold, owners=None):
    """Brute-force reference: every (i, j) pair above threshold, i < j, ascending."""
    indexed = [(i, np.asarray(d.embedding, dtype=float)) for i, d in enumerate(documents)
               if d.embedding is not None]
    pairs = []
    for a, (index_i, vi) in enumerate(indexed):
        for index_j, vj in indexed[a + 1:]:
            if owners is not None and owners[index_i] == owners[index_j]:
                continue
            cos = float(np.dot(vi, vj) / (np.linalg.norm(vi) * np.linalg.norm(vj)))
            if cos > threshold:
                pairs.append((index_i, index_j))
    return pairs


def _random_documents(n, dims=3, seed=0, missing_every=7):
    rng = np.random.default_rng(seed)
    vectors = rng.standard_normal((n, dims))
    # Distinct, lexically unrelated texts so every candidate pair is reported.
    return [
        Document(
            id=f"d{i}", text=f"token{i}x{i * 7919}",
            embedding=None if missing_every and i % missing_every == 3 else vectors[i].tolist(),
        )
        for i in range(n)
    ]


@pytest.mark.parametrize("n", [0, 1, 2, 5, 40])
@pytest.mark.parametrize("block_size", [1, 3, 256])
def test_tiled_single_corpus_matches_reference(n, block_size):
    docs = _random_documents(n)
    checker = VectorStoreIntegrityChecker(0.9, block_size=block_size)
    report = checker.assess_embedding_consistency(docs)
    got = [f.related_document_indices for f in report.findings]
    assert got == _reference_pairs(docs, 0.9)
    assert [f.document_index for f in report.findings] == [i for i, _ in got]
    assessed = [i for i, d in enumerate(docs) if d.embedding is not None]
    assert report.assessed_documents == len(assessed)
    assert report.compared_pairs == len(assessed) * (len(assessed) - 1) // 2
    assert report.skipped_document_indices == tuple(
        i for i, d in enumerate(docs) if d.embedding is None
    )
    if n == 40:
        assert got, "test data should produce findings"


@pytest.mark.parametrize("n", [0, 1, 2, 5, 40])
@pytest.mark.parametrize("block_size", [1, 3, 256])
def test_tiled_cross_user_matches_reference(n, block_size):
    docs = _random_documents(n, seed=1)
    owners = [f"user{i % 3}" for i in range(n)]
    grouped: dict[str, list[Document]] = {}
    order: list[int] = []
    for owner in sorted(set(owners)):
        for i, doc in enumerate(docs):
            if owners[i] == owner:
                grouped.setdefault(owner, []).append(doc)
                order.append(i)
    flat = [docs[i] for i in order]
    flat_owners = [owners[i] for i in order]
    checker = VectorStoreIntegrityChecker(0.9, block_size=block_size)
    report = checker.assess_cross_user_proximity(grouped)
    got = [f.related_document_indices for f in report.findings]
    assert got == _reference_pairs(flat, 0.9, flat_owners)
    for f in report.findings:
        i, j = f.related_document_indices
        assert flat_owners[i] != flat_owners[j]
        assert f.finding_type == FindingType.CROSS_USER_CONTAMINATION
    if n == 40:
        assert got, "test data should produce findings"


def test_tiled_evidence_matches_reference_similarity():
    docs = _random_documents(30, seed=2, missing_every=0)
    report = VectorStoreIntegrityChecker(0.8, block_size=4).assess_embedding_consistency(docs)
    assert report.findings
    for f in report.findings:
        i, j = f.related_document_indices
        vi = np.asarray(docs[i].embedding)
        vj = np.asarray(docs[j].embedding)
        expected = float(np.dot(vi, vj) / (np.linalg.norm(vi) * np.linalg.norm(vj)))
        assert f.evidence.startswith(f"cos_sim={expected:.4f}")


@pytest.mark.parametrize("value", [0, -1, True, 1.5, "8"])
def test_block_size_validation(value):
    with pytest.raises(ValueError, match="block_size"):
        VectorStoreIntegrityChecker(block_size=value)


def test_comparison_budget_checked_before_any_similarity_work(monkeypatch):
    docs = [Document(text=t, embedding=[1, 0]) for t in ["alpha", "beta", "gamma"]]
    checker = VectorStoreIntegrityChecker(max_comparisons=2)

    def boom(*args, **kwargs):  # pragma: no cover - must not be reached
        raise AssertionError("similarity computed before budget check")

    monkeypatch.setattr(VectorStoreIntegrityChecker, "_text_similarity", staticmethod(boom))
    monkeypatch.setattr(VectorStoreIntegrityChecker, "_similarity_tile", staticmethod(boom))
    with pytest.raises(ValueError, match="max_comparisons"):
        checker.assess_embedding_consistency(docs)


def test_findings_budget_raises_when_exceeded_not_when_reached():
    docs = [Document(text=t, embedding=[1, 0]) for t in ["alpha", "beta", "gamma"]]
    assert len(VectorStoreIntegrityChecker(max_findings=3, block_size=1)
               .check_embedding_consistency(docs)) == 3
    with pytest.raises(ValueError, match="max_findings"):
        VectorStoreIntegrityChecker(max_findings=2, block_size=1).check_embedding_consistency(docs)


def test_performance_2000_by_768():
    rng = np.random.default_rng(0)
    vectors = rng.standard_normal((2000, 768))
    docs = [Document(text=f"doc {i}", embedding=v) for i, v in enumerate(vectors)]
    checker = VectorStoreIntegrityChecker()
    start = time.perf_counter()
    report = checker.assess_embedding_consistency(docs)
    elapsed = time.perf_counter() - start
    assert report.compared_pairs == 2000 * 1999 // 2
    # Generous bound to avoid CI flakiness; typical runtime is well under 0.5 s.
    assert elapsed < 1.5, f"assessment took {elapsed:.2f}s"


# --- Lexical similarity and severity ----------------------------------------


def test_paraphrase_pair_is_medium_heuristic_not_high():
    findings = VectorStoreIntegrityChecker().check_embedding_consistency([
        Document(text="The cat sat on the mat.", embedding=[1.0, 0.0, 0.0]),
        Document(text="A feline was resting upon the rug.", embedding=[1.0, 0.001, 0.0]),
    ])
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == Severity.MEDIUM
    assert finding.family == "embedding_poisoning_cos_high_text_low"
    assert finding.confidence == "heuristic"
    assert "paraphrase" in finding.description.lower()
    assert "translation" in finding.description.lower()


@pytest.mark.parametrize(("text_a", "text_b"), [
    ("Revenue grew 12%.", "revenue grew 12 %"),
    ("The deployment pipeline failed overnight!",
     "the deployment pipelines failed overnight"),
    ("Reset   your password\nvia the portal.", "Reset your password via the portal"),
])
def test_near_duplicates_are_lexically_similar_and_not_flagged(text_a, text_b):
    assert VectorStoreIntegrityChecker._text_similarity(text_a, text_b) >= 0.8
    assert VectorStoreIntegrityChecker().check_embedding_consistency([
        Document(text=text_a, embedding=[1.0, 0.0]),
        Document(text=text_b, embedding=[1.0, 0.0001]),
    ]) == []


def test_text_similarity_edge_cases():
    sim = VectorStoreIntegrityChecker._text_similarity
    assert sim("", "") == 1.0
    assert sim("Hi", "hi") == 1.0
    assert sim("", "something") == 0.0
    assert sim("!!!", "???") == 0.0
    assert sim("The cat sat on the mat.", "A feline was resting upon the rug.") < 0.8
    assert 0.0 <= sim("alpha beta", "gamma delta") < 0.2


def test_text_similarity_only_considers_bounded_prefix():
    prefix = "lorem ipsum dolor sit amet " * 1000  # 27,000 chars
    assert VectorStoreIntegrityChecker._text_similarity(
        prefix + "first tail", prefix + "completely different tail",
    ) == 1.0


# --- Re-embedding fidelity --------------------------------------------------


def _embedder(table, calls=None):
    def embed(texts):
        if calls is not None:
            calls.append(list(texts))
        return [table[t] for t in texts]
    return embed


def test_fidelity_flags_swapped_stored_vector():
    table = {"alpha": [1.0, 0.0, 0.0], "beta": [0.0, 1.0, 0.0], "gamma": [0.0, 0.0, 1.0]}
    docs = [
        Document(id="a", text="alpha", embedding=[2.0, 0.0, 0.0]),  # scale only: consistent
        Document(id="b", text="beta", embedding=[0.0, 0.0, 1.0]),  # swapped vector
        Document(id="c", text="no vector"),
        Document(id="g", text="gamma", embedding=[0.0, 0.0, 1.0]),
    ]
    report = VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, _embedder(table))
    assert report.total_documents == 4
    assert report.assessed_documents == 3
    assert report.skipped_document_indices == (2,)
    assert report.compared_pairs == 3
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.finding_type == FindingType.EMBEDDING_POISONING
    assert finding.severity == Severity.HIGH
    assert finding.family == "embedding_text_mismatch"
    assert finding.confidence == "verified-by-reembedding"
    assert finding.owasp_mapping.startswith("LLM08")
    assert finding.document_id == "b"
    assert finding.document_index == 1
    assert finding.evidence == "cos(stored, re-embedded)=0.0000"


def test_fidelity_consistent_corpus_has_no_findings():
    rng = np.random.default_rng(3)
    table = {f"t{i}": rng.standard_normal(8).tolist() for i in range(10)}
    docs = [Document(text=t, embedding=[x * 3 for x in v]) for t, v in table.items()]
    report = VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, _embedder(table))
    assert report.findings == []
    assert report.assessed_documents == 10


def test_fidelity_min_similarity_boundary_is_strict():
    docs = [Document(text="a", embedding=[1.0, 0.0])]
    embed = _embedder({"a": [1.0, 1.0]})  # cos = 0.7071...
    checker = VectorStoreIntegrityChecker()
    assert checker.assess_embedding_fidelity(docs, embed, min_similarity=0.7).findings == []
    assert len(checker.assess_embedding_fidelity(docs, embed, min_similarity=0.75).findings) == 1
    same = _embedder({"a": [1.0, 0.0]})
    assert checker.assess_embedding_fidelity(docs, same, min_similarity=1).findings == []


@pytest.mark.parametrize(("n", "batch_size", "expected_calls"), [
    (0, 4, 0), (1, 4, 1), (4, 4, 1), (5, 4, 2), (9, 4, 3), (9, 1, 9), (9, 64, 1),
])
def test_fidelity_batches_embed_calls(n, batch_size, expected_calls):
    table = {f"t{i}": [1.0, float(i)] for i in range(n)}
    docs = [Document(text=t, embedding=v) for t, v in table.items()]
    calls: list[list[str]] = []
    VectorStoreIntegrityChecker().assess_embedding_fidelity(
        docs, _embedder(table, calls), batch_size=batch_size,
    )
    assert len(calls) == expected_calls == math.ceil(n / batch_size)
    assert [t for batch in calls for t in batch] == list(table)
    assert all(len(batch) <= batch_size for batch in calls)


def test_fidelity_dimension_mismatch_raises_with_index():
    docs = [Document(text="a", embedding=[1.0, 0.0]), Document(text="b", embedding=[0.0, 1.0])]
    embed = _embedder({"a": [1.0, 0.0], "b": [0.0, 1.0, 0.0]})
    with pytest.raises(ValueError, match=r"document index 1.*dimension"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, embed)


@pytest.mark.parametrize("bad", [
    [float("nan"), 0.0], [float("inf"), 0.0], [0.0, 0.0], ["x", "y"], [[1.0, 0.0]], [],
])
def test_fidelity_invalid_reembedding_raises_with_index(bad):
    docs = [Document(text="a", embedding=[1.0, 0.0]), Document(text="b", embedding=[0.0, 1.0])]
    embed = _embedder({"a": [1.0, 0.0], "b": bad})
    with pytest.raises(ValueError, match="document index 1"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, embed)


@pytest.mark.parametrize("returned", [[], [[1.0, 0.0]], [[1.0, 0.0]] * 3])
def test_fidelity_wrong_vector_count_raises(returned):
    docs = [Document(text="a", embedding=[1.0, 0.0]), Document(text="b", embedding=[0.0, 1.0])]
    with pytest.raises(ValueError, match="returned"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, lambda texts: returned)


def test_fidelity_invalid_stored_embedding_raises():
    docs = [Document(text="a", embedding=[float("nan")])]
    with pytest.raises(ValueError, match="document index 0"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(docs, lambda t: [[1.0]])


def test_fidelity_accepts_numpy_batch_output():
    docs = [Document(text="a", embedding=[1.0, 0.0]), Document(text="b", embedding=[0.0, 1.0])]
    report = VectorStoreIntegrityChecker().assess_embedding_fidelity(
        docs, lambda texts: np.eye(2)[: len(texts)],
    )
    assert report.findings == []


@pytest.mark.parametrize("value", [-1.1, 1.1, float("nan"), True, "0.9"])
def test_fidelity_min_similarity_validation(value):
    with pytest.raises(ValueError, match="min_similarity"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(
            [], lambda t: [], min_similarity=value,
        )


@pytest.mark.parametrize("value", [0, -1, True, 1.5])
def test_fidelity_batch_size_validation(value):
    with pytest.raises(ValueError, match="batch_size"):
        VectorStoreIntegrityChecker().assess_embedding_fidelity(
            [], lambda t: [], batch_size=value,
        )


@pytest.mark.parametrize("budget", ["max_documents", "max_findings"])
def test_fidelity_respects_budgets(budget):
    docs = [Document(text=t, embedding=[1.0, 0.0]) for t in ["a", "b"]]
    calls: list[list[str]] = []

    def embed(texts):
        calls.append(list(texts))
        return [[0.0, 1.0] for _ in texts]

    with pytest.raises(ValueError, match=budget):
        VectorStoreIntegrityChecker(**{budget: 1}).assess_embedding_fidelity(docs, embed)
    if budget == "max_documents":
        assert calls == []
