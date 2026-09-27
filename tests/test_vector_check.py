"""Tests for the vector store integrity checker."""

from ragguard.scanner import Document, FindingType
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
    assert findings[0].severity.value == "critical"
    assert findings[0].owasp_mapping.startswith("LLM08")


def test_documents_without_embeddings_are_skipped():
    checker = VectorStoreIntegrityChecker()
    assert checker.check_embedding_consistency([
        Document(id="a", text="no embedding"),
        Document(id="b", text="also none"),
    ]) == []
