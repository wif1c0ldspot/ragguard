"""Public compatibility for the extracted scanner-independent domain types."""

import pickle

import pytest

import ragguard
from ragguard import domain, normalization, scanner


@pytest.mark.parametrize("name", ["Document", "Finding", "FindingType", "Severity", "ScanReport"])
def test_domain_types_preserve_public_identity_and_pickle_roundtrip(name):
    value = getattr(domain, name)
    assert getattr(scanner, name) is value
    assert getattr(ragguard, name) is value
    assert pickle.loads(pickle.dumps(value)) is value


def test_normalization_public_entrypoint_preserves_behavior():
    assert scanner.canonicalize is normalization.canonicalize
    assert scanner.canonicalize("&#x49;Ｇ\ufe0fnore\tPREVIOUS Instructions") == (
        "ignore previous instructions"
    )
    surfaces = normalization._surfaces("1gn0re previous instructions")
    assert surfaces.deobfuscated == "ignore previous instructions"
