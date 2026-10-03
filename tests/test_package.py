"""Package-level exports: the base install must work without the vector extra."""

import sys

import pytest

import ragguard


def test_vector_exports_resolve_lazily() -> None:
    from ragguard.vector_check import VectorAssessment, VectorStoreIntegrityChecker

    assert ragguard.VectorStoreIntegrityChecker is VectorStoreIntegrityChecker
    assert ragguard.VectorAssessment is VectorAssessment


def test_missing_numpy_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "ragguard.vector_check", raising=False)
    monkeypatch.delattr(ragguard, "vector_check", raising=False)
    monkeypatch.setitem(sys.modules, "numpy", None)
    with pytest.raises(ImportError, match=r"ragguard\[vector\]"):
        ragguard.VectorStoreIntegrityChecker  # noqa: B018


def test_text_scanning_does_not_import_numpy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delitem(sys.modules, "ragguard.vector_check", raising=False)
    monkeypatch.setitem(sys.modules, "numpy", None)
    gate = ragguard.ContentBoundary()
    assert gate.require(ragguard.Document(text="Useful facts.")) == "Useful facts."


def test_unknown_attribute_raises_attribute_error() -> None:
    with pytest.raises(AttributeError, match="no_such_name"):
        ragguard.no_such_name  # type: ignore[attr-defined]  # noqa: B018


def test_all_exports_resolve() -> None:
    for name in ragguard.__all__:
        assert getattr(ragguard, name) is not None
