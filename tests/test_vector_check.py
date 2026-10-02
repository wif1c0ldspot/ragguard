"""Tests for the vector store integrity checker."""

import pytest

from ragguard.scanner import Document, FindingType, resolve_document_id
from ragguard.vector_check import VectorStoreIntegrityChecker


def test_detects_embedding_poisoning():
    checker = VectorStoreIntegrityChecker(similarity_threshold=0.95)
    findings = checker.check_embedding_consistency([
        Document(id="a", text="Quarterly revenue grew by 12 percent.", embedding=[1.0, 0.0, 0.0]),
        Document(id="b", text="Totally unrelated payload text.", embedding=[1.0, 0.0001, 0.0]),
    ])

    assert len(findings) == 1
    assert findings[0].finding_type == FindingType.EMBEDDING_POISONING
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
