"""Versioned risk crosswalks; a related risk is not a claim of prevention.

The legacy ``owasp_mapping`` string remains a 2025 label. These additive
annotations allow consumers to compare reports without reinterpreting history.
"""

from __future__ import annotations

# Source: https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/
_LLM_CROSSWALK: dict[str, tuple[str, str, str]] = {
    "LLM01": ("LLM01", "Prompt Injection", "Prompt Injection"),
    "LLM02": ("LLM02", "Sensitive Information Disclosure", "Sensitive Information Disclosure"),
    "LLM04": ("LLM05", "Data and Model Poisoning", "Data and Model Poisoning"),
    "LLM05": ("LLM10", "Improper Output Handling", "Improper Output Handling"),
    "LLM07": ("LLM08", "System Prompt Leakage", "Hidden Context Exposure"),
    "LLM08": ("LLM09", "Vector and Embedding Weaknesses", "Vector and Embedding Weaknesses"),
}


def owasp_mappings(legacy_mapping: str) -> list[dict[str, str]]:
    """Return known 2025 and 2026 related-risk references, not inferred coverage."""
    identifier = legacy_mapping.partition(":")[0]
    entry = _LLM_CROSSWALK.get(identifier)
    if entry is None:
        return []
    new_identifier, old_title, new_title = entry
    return [
        {"framework": "OWASP LLM Top 10", "edition": "2025", "id": identifier,
         "title": old_title, "relationship": "related-risk"},
        {"framework": "OWASP LLM Top 10", "edition": "2026", "id": new_identifier,
         "title": new_title, "relationship": "related-risk"},
    ]
