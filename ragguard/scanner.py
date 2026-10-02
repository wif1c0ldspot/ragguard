"""Core scanning engine for RAG pipeline security assessment.

The scanner is deliberately dependency-light: detection is heuristic and
explainable rather than model-based, so every finding traces back to a named
pattern family.

Detection runs on two surfaces:

* **canonical** — text is HTML-entity decoded, NFKC normalised, zero-width and
  bidi control characters are stripped, whitespace is collapsed and the result
  is lowercased before matching. This defeats the cheap obfuscation tricks
  (``&#x49;gnore``, ``ig\u200bnore``, ``IGNORE   PREVIOUS``).
* **raw** — matched against the original text, for families whose *signal is the
  obfuscation itself* (encoded payloads, dangerous markup).

OWASP mappings follow the **OWASP Top 10 for LLM Applications 2025**.
"""

from __future__ import annotations

import hashlib
import html
import math
import re
import unicodedata
import warnings
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from enum import Enum
from typing import Any

RULESET_VERSION = "2026.09.1"

# --- OWASP Top 10 for LLM Applications (2025) categories used by the scanner ---

LLM01_PROMPT_INJECTION = "LLM01: Prompt Injection"
LLM02_SENSITIVE_INFO = "LLM02: Sensitive Information Disclosure"
LLM04_POISONING = "LLM04: Data and Model Poisoning"
LLM05_IMPROPER_OUTPUT = "LLM05: Improper Output Handling"
LLM07_SYSTEM_PROMPT = "LLM07: System Prompt Leakage"
LLM08_VECTOR_WEAKNESSES = "LLM08: Vector and Embedding Weaknesses"


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingType(str, Enum):
    """Types of RAG pipeline vulnerabilities detected."""
    PROMPT_INJECTION_IN_DOCUMENT = "prompt_injection_in_document"
    METADATA_INJECTION = "metadata_injection"
    CHUNK_SPLIT_ATTACK = "chunk_split_attack"
    EMBEDDING_POISONING = "embedding_poisoning"
    CROSS_USER_CONTAMINATION = "cross_user_contamination"
    CANONICAL_INJECTION = "canonical_injection"


@dataclass
class Finding:
    """A single security finding from a RAG pipeline scan."""
    finding_type: FindingType
    severity: Severity
    document_id: str
    description: str
    evidence: str
    remediation: str
    owasp_mapping: str = ""
    family: str = ""
    document_index: int | None = None
    metadata_path: str | None = None
    related_document_ids: tuple[str, ...] = ()
    confidence: str = "heuristic"
    related_document_indices: tuple[int, ...] = ()


@dataclass(frozen=True)
class PatternFamily:
    """A named, explainable detection rule.

    ``family`` is what shows up in findings and reports; ``surface`` selects
    whether the rule matches the canonicalised text (default) or the raw text.
    """
    family: str
    pattern: re.Pattern[str]
    severity: Severity
    owasp: str
    remediation: str
    surface: str = "canonical"


# --- Canonicalisation -------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff]")
_WHITESPACE_RE = re.compile(r"\s+")


def canonicalize(text: str) -> str:
    """Normalise text so obfuscated payloads match plain-text rules.

    Decodes HTML entities, applies NFKC normalisation, strips zero-width and
    bidi control characters, collapses all whitespace to single spaces and
    lowercases the result.
    """
    decoded = html.unescape(text)
    normalised = unicodedata.normalize("NFKC", decoded)
    stripped = _ZERO_WIDTH_RE.sub("", normalised)
    return _WHITESPACE_RE.sub(" ", stripped).lower()


# --- Prompt injection families ---------------------------------------------

_INSTRUCTION_VERBS = r"(?:ignore|disregard|forget|override|bypass|skip)"
_INSTRUCTION_QUALIFIERS = (
    r"(?:(?:all|any|the|these|those|your|my|our|its|previous|prior|preceding|"
    r"above|earlier|initial|original|system|developer|hidden|new|following)\s+){0,6}"
)
_INSTRUCTION_NOUNS = (
    r"(?:instructions?|prompts?|rules?|guidelines?|guidance|directives?|context|"
    r"constraints?|safeguards?|polic(?:y|ies)|commands?)"
)

INJECTION_FAMILIES: tuple[PatternFamily, ...] = (
    PatternFamily(
        family="instruction_override",
        pattern=re.compile(
            rf"\b{_INSTRUCTION_VERBS}\s+{_INSTRUCTION_QUALIFIERS}{_INSTRUCTION_NOUNS}\b"
        ),
        severity=Severity.CRITICAL,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reject or quarantine the document. Treat retrieved text as data, never as "
            "instructions, and apply instruction-hierarchy controls at prompt assembly."
        ),
    ),
    PatternFamily(
        family="persona_override",
        pattern=re.compile(
            r"\byou\s+(?:are|will\s+be|must\s+be)\s+now\s+(?:a\s+|an\s+|the\s+)?"
            r"(?:(?:different|unrestricted|unfiltered|uncensored|jailbroken|evil|malicious|"
            r"rogue|new)\s+)?(?:model|assistant|entity|ai|persona|version)\b"
            r"|\b(?:act|behave|respond|pretend|roleplay|simulate)\s+as\s+(?:an?\s+|the\s+)?"
            r"(?:unrestricted|unfiltered|uncensored|unbounded|jailbroken|evil|malicious|"
            r"rogue|hacker|dan|root|admin|administrator|superuser)\b"
            r"|\bdo\s+anything\s+now\b"
        ),
        severity=Severity.CRITICAL,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reject or quarantine the document. Pin the assistant persona in the system "
            "prompt and refuse documents that attempt to redefine it."
        ),
    ),
    PatternFamily(
        family="system_prompt_extraction",
        pattern=re.compile(
            r"\brepeat\s+(?:your|the)\s+(?:system\s+|initial\s+|original\s+)?"
            r"(?:prompt|instructions)\b"
            r"|\bwhat\s+(?:were|are|was)\s+(?:your|the)\s+"
            r"(?:instructions?|system\s+prompt|initial\s+prompt)\b"
            r"|\b(?:print|show|reveal|output|disclose|leak|dump|expose|tell\s+me)\s+"
            r"(?:me\s+)?(?:your|the)\s+(?:system\s+|initial\s+|original\s+|hidden\s+)*"
            r"(?:prompt|instructions|rules)\b"
        ),
        severity=Severity.HIGH,
        owasp=LLM07_SYSTEM_PROMPT,
        remediation=(
            "Keep secrets, credentials and authorisation logic out of the system prompt; "
            "treat it as publicly visible and enforce policy in application code."
        ),
    ),
    PatternFamily(
        family="delimiter_injection",
        pattern=re.compile(
            r"<\s*/?\s*(?:script|iframe|object|embed|svg|form|meta|link|base)\b[^>]*>"
            r"|\bjavascript\s*:|\bdata\s*:\s*text/html", re.IGNORECASE
        ),
        severity=Severity.HIGH,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Strip or escape markup during ingestion and render retrieved content as inert text."
        ),
        surface="raw",
    ),
    PatternFamily(
        family="encoding_obfuscation",
        pattern=re.compile(
            r"(?:&#x?[0-9a-fA-F]{2,6};){2,}"          # runs of HTML entities
            r"|(?:%[0-9a-fA-F]{2}){3,}"               # runs of percent-encoding
            r"|[\x80\x90\x9b\x9d]"                    # C1 / invisible control bytes
        ),
        severity=Severity.MEDIUM,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Canonicalise (entity-decode + NFKC) before scanning, and reject documents whose "
            "payload only appears after decoding."
        ),
        surface="raw",
    ),
    PatternFamily(
        family="jailbreak_mode",
        pattern=re.compile(
            r"\b(?:enable|activate|enter|switch\s+to|behave\s+as\s+if\s+in)\s+"
            r"(?:developer|debug|maintenance|sudo|god)\s+mode\b"
        ),
        severity=Severity.HIGH,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Review mode-switch instructions in context before allowing them into prompts."
        ),
    ),
    PatternFamily(
        family="data_exfiltration",
        pattern=re.compile(
            r"\boutput\s+(?:all|everything|the\s+entire)\s+"
            r"(?:text|content|data|conversation|context|history)\b"
            r"|\b(?:base64|hex|rot13)\s+(?:this|the\s+following|above|it)\b"
            r"|\b(?:exfiltrate|send|post|upload)\s+(?:it|them|the\s+data|all\s+data)\s+to\b"
        ),
        severity=Severity.HIGH,
        owasp=LLM02_SENSITIVE_INFO,
        remediation=(
            "Redact or tokenise sensitive fields before they enter the context window and "
            "filter retrieval by caller entitlements."
        ),
    ),
)

# --- Metadata injection families -------------------------------------------

METADATA_FAMILIES: tuple[PatternFamily, ...] = (
    PatternFamily(
        family="metadata_key_value_payload",
        pattern=re.compile(r"\b[A-Z_]{4,}\s*=\s*[\"'][^\"'<>\n]{10,}", re.I),
        severity=Severity.HIGH,
        owasp=LLM01_PROMPT_INJECTION,
        remediation="Strip instruction-bearing fields from metadata before ingestion.",
    ),
    PatternFamily(
        family="metadata_tool_call",
        pattern=re.compile(
            r"[\"']?\b(?:FUNCTION|ACTION|TOOL)\b[\"']?\s*[:=]\s*[\"']?"
            r"(?:write_\w*|exec|invoke|rm_\w*|curl|wget|https?|POST|GET)\b",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reject documents whose metadata names callable tools; allow-list metadata keys."
        ),
    ),
    PatternFamily(
        family="metadata_code_execution",
        pattern=re.compile(
            r"\b(?:eval|exec|compile|subprocess|os\.system|spawn|require)\s*[\(.]",
            re.IGNORECASE,
        ),
        severity=Severity.CRITICAL,
        owasp=LLM01_PROMPT_INJECTION,
        remediation="Strip all executable fields from metadata; metadata must be data, not code.",
    ),
    PatternFamily(
        family="metadata_exfiltration_command",
        pattern=re.compile(r"\b(?:curl|wget|nc|ncat)\s+[\"']?https?://", re.IGNORECASE),
        severity=Severity.HIGH,
        owasp=LLM02_SENSITIVE_INFO,
        remediation=(
            "Strip outbound-request fields from metadata; egress should never come from metadata."
        ),
    ),
    PatternFamily(
        family="metadata_credential_leak",
        pattern=re.compile(
            r"\bsk-[a-zA-Z0-9]{20,}|\bapi[-_]?key\s*[:=]\s*\S{10,}", re.IGNORECASE
        ),
        severity=Severity.CRITICAL,
        owasp=LLM02_SENSITIVE_INFO,
        remediation="Redact credentials at ingestion and rotate anything that reached the index.",
    ),
)

# --- Chunk-splitting / structural families ---------------------------------

SPLIT_FAMILIES: tuple[PatternFamily, ...] = (
    PatternFamily(
        family="split_marker_open",
        pattern=re.compile(r"(?<=[.!?])\s*(?:begin|start|first\s+part|step\s+1)\b", re.I),
        severity=Severity.MEDIUM,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reassemble split documents before scanning; scan the parent document, not chunks."
        ),
    ),
    PatternFamily(
        family="split_marker_close",
        pattern=re.compile(r"(?<=[.!?])\s*(?:end|stop|finish|last\s+part|step\s+\d+)\b", re.I),
        severity=Severity.MEDIUM,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reassemble split documents before scanning; scan the parent document, not chunks."
        ),
    ),
    PatternFamily(
        family="structural_dangerous_tag",
        pattern=re.compile(
            r"<\s*/?\s*(?:script|iframe|object|embed|svg|form|base)\b[^>]*>"
            r"|\bon[a-z]+\s*=\s*[\"']?[a-z]+", re.IGNORECASE,
        ),
        severity=Severity.MEDIUM,
        owasp=LLM05_IMPROPER_OUTPUT,
        remediation=(
            "Strip executable markup at ingestion; retrieved text should never be rendered as HTML."
        ),
    ),
    PatternFamily(
        family="structural_sql_keyword",
        pattern=re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[\s\S]{0,40}?\bFROM\b", re.I),
        severity=Severity.LOW,
        owasp=LLM05_IMPROPER_OUTPUT,
        remediation=(
            "Parameterise any query built from retrieved text; never concatenate document "
            "content into SQL."
        ),
    ),
)

_ACTION_ENUMERATION_RE = re.compile(r"\binstruction\s*:")


def resolve_document_id(doc: Document) -> str:
    """Canonical identifier for a document: explicit id, else a content hash.

    Use this wherever findings are correlated back to documents — the scanner
    uses it internally, and callers that re-derive ids by hand (e.g. slicing
    ``doc.text``) will silently fail to match findings.
    """
    return doc.id or RAGScanner._hash_content(doc.text)



_CREDENTIAL_KEY_RE = re.compile(
    r"^(?:api[-_]?key|access[-_]?token|secret|password|authorization|credential)$", re.I
)
_SECRET_RE = re.compile(
    r"\bsk-[a-zA-Z0-9_-]{20,}|\b(?:api[-_]?key|access[-_]?token|secret|password|"
    r"authorization)\s*[:=]\s*[\"']?[^\s\"',}]+", re.I
)


def _redact_metadata_path(path: str) -> str:
    """Keep safe JSON Pointer segments, concealing secret keys and their descendants."""
    safe: list[str] = []
    sensitive_ancestor = False
    for segment in path.split("/")[1:]:
        decoded = segment.replace("~1", "/").replace("~0", "~")
        canonical = canonicalize(decoded)
        secret_segment = bool(_SECRET_RE.search(canonical))
        safe.append("[REDACTED]" if sensitive_ancestor or secret_segment else segment)
        sensitive_ancestor = sensitive_ancestor or bool(_CREDENTIAL_KEY_RE.fullmatch(canonical))
    return "/" + "/".join(safe) if safe else ""


def _metadata_leaves(value: Any, path: str = "", *, key: str = "", depth: int = 0,
                     ancestors: frozenset[int] = frozenset()) -> Iterator[tuple[str, str, str]]:
    """Yield validated JSON-like leaves and escaped JSON Pointer paths.

    Reject cycles, unsupported values and excessive nesting without invoking
    arbitrary objects' string representations. Container keys are also scanned.
    """
    if depth > 64 or id(value) in ancestors:
        raise ValueError("metadata must be acyclic and at most 64 levels deep")
    if isinstance(value, dict):
        if key:
            yield path, key, ""
        for child_key, child in value.items():
            if not isinstance(child_key, str):
                raise TypeError("metadata keys must be strings")
            escaped = child_key.replace("~", "~0").replace("/", "~1")
            yield from _metadata_leaves(
                child, f"{path}/{escaped}", key=child_key, depth=depth + 1,
                ancestors=ancestors | {id(value)},
            )
    elif isinstance(value, list):
        if key:
            yield path, key, ""
        for index, child in enumerate(value):
            yield from _metadata_leaves(
                child, f"{path}/{index}", depth=depth + 1, ancestors=ancestors | {id(value)}
            )
    elif isinstance(value, str):
        yield path, key, value
    elif value is None or isinstance(value, (bool, int, float)):
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("metadata numbers must be finite")
        yield path, key, "" if value is None else str(value)
    else:
        raise TypeError("metadata values must be JSON-like scalars, lists or dictionaries")


class RAGScanner:
    """Stateless heuristic scanner, safe to reuse across concurrent scans.

    ``enabled_families=None`` enables all rules; an empty iterable disables all.
    Legacy embedding/chunk parameters remain readable but do not affect detection.
    Evidence is redacted by default; it is still untrusted document content.
    """

    def __init__(
        self,
        *,
        chunk_size: int | None = None,
        chunk_overlap: int | None = None,
        embedding_dim: int | None = None,
        similarity_threshold: float | None = None,
        enabled_families: Iterable[str] | None = None,
        redact_evidence: bool = True,
    ):
        legacy = (chunk_size, chunk_overlap, embedding_dim, similarity_threshold)
        if any(value is not None for value in legacy):
            warnings.warn(
                "Scanner chunk/embedding parameters are unused and deprecated; "
                "configure chunking upstream and vector checks separately.",
                DeprecationWarning, stacklevel=2,
            )
        self.chunk_size = 500 if chunk_size is None else chunk_size
        self.chunk_overlap = 50 if chunk_overlap is None else chunk_overlap
        self.embedding_dim = 1536 if embedding_dim is None else embedding_dim
        self.similarity_threshold = 0.95 if similarity_threshold is None else similarity_threshold
        known = {rule.family for rule in INJECTION_FAMILIES + METADATA_FAMILIES + SPLIT_FAMILIES}
        known.add("canonical_override_plus_action")
        selected = known if enabled_families is None else set(enabled_families)
        if selected - known:
            raise ValueError(f"Unknown rule families: {sorted(selected - known)}")
        self.enabled_families = frozenset(selected)
        self.redact_evidence = redact_evidence

    def scan_documents(
        self,
        documents: list[Document],
        *,
        check_prompt_injection: bool = True,
        check_metadata: bool = True,
        check_chunk_splitting: bool = True,
    ) -> ScanReport:
        """Scan documents; ``document_index`` identifies each occurrence in this call."""
        findings: list[Finding] = []
        for index, doc in enumerate(documents):
            doc_id = resolve_document_id(doc)
            if check_prompt_injection:
                findings.extend(self._scan_rules(
                    doc.text, INJECTION_FAMILIES, FindingType.PROMPT_INJECTION_IN_DOCUMENT,
                    doc_id, index,
                ))
                canonical = canonicalize(doc.text)
                if ("canonical_override_plus_action" in self.enabled_families
                        and "instruction_override" in self.enabled_families
                        and INJECTION_FAMILIES[0].pattern.search(canonical)
                        and _ACTION_ENUMERATION_RE.search(canonical)):
                    findings.append(Finding(
                        finding_type=FindingType.CANONICAL_INJECTION,
                        severity=Severity.CRITICAL, document_id=doc_id,
                        description="Instruction override combined with an enumerated action",
                        evidence="instruction:",
                        remediation=(
                            "Treat retrieved content as data and review instruction overrides."
                        ),
                        owasp_mapping=LLM01_PROMPT_INJECTION,
                        family="canonical_override_plus_action", document_index=index,
                    ))
            if check_metadata:
                if doc.metadata is not None and not isinstance(doc.metadata, dict):
                    raise TypeError("Document.metadata must be a dictionary or None")
                for path, key, value in _metadata_leaves(doc.metadata):
                    # Preserve field structure rather than scanning Python repr(dict).
                    candidate = f"{key}: {value}" if key else value
                    rules = INJECTION_FAMILIES + METADATA_FAMILIES
                    matches = self._scan_rules(
                        candidate, rules, FindingType.METADATA_INJECTION, doc_id, index, path,
                    )
                    sensitive = any(
                        _CREDENTIAL_KEY_RE.fullmatch(
                            canonicalize(part.replace("~1", "/").replace("~0", "~"))
                        ) for part in path.split("/")[1:]
                    )
                    if sensitive and value and "metadata_credential_leak" in self.enabled_families:
                        if not any(f.family == "metadata_credential_leak" for f in matches):
                            rule = METADATA_FAMILIES[-1]
                            matches.append(Finding(
                                FindingType.METADATA_INJECTION, rule.severity, doc_id,
                                "Credential-bearing metadata field", value[:120], rule.remediation,
                                rule.owasp, rule.family, index, path,
                            ))
                    if self.redact_evidence:
                        for finding in matches:
                            finding.metadata_path = _redact_metadata_path(path)
                            if sensitive:
                                finding.evidence = "[REDACTED credential-bearing metadata]"
                    findings.extend(matches)
            if check_chunk_splitting:
                findings.extend(self._scan_rules(
                    doc.text, SPLIT_FAMILIES, FindingType.CHUNK_SPLIT_ATTACK,
                    doc_id, index, raw=True,
                ))
        summary: dict[str, int] = {}
        for finding in findings:
            summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
        return ScanReport(len(documents), findings, summary)

    def _scan_rules(
        self, text: str, rules: tuple[PatternFamily, ...], kind: FindingType,
        doc_id: str, index: int, path: str | None = None, *, raw: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []
        canonical = canonicalize(text)
        for rule in rules:
            if rule.family not in self.enabled_families:
                continue
            haystack = text if raw or rule.surface == "raw" else canonical
            match = rule.pattern.search(haystack)
            if match:
                evidence = self._evidence(text, match.group(0))
                if self.redact_evidence:
                    evidence = _SECRET_RE.sub("[REDACTED]", evidence)
                    if rule.family == "metadata_credential_leak":
                        evidence = "[REDACTED credential]"
                findings.append(Finding(
                    kind, rule.severity, doc_id,
                    f"Potential risk ({rule.family}); heuristic match requires context",
                    evidence[:120], rule.remediation, rule.owasp, rule.family, index, path,
                ))
        return findings

    @staticmethod
    def _evidence(raw: str, matched: str) -> str:
        """Return the matched phrase in its original casing where possible."""
        needle = matched.strip()
        if not needle:
            return ""
        idx = raw.lower().find(needle.lower())
        return raw[idx:idx + len(needle)] if idx >= 0 else needle

    @staticmethod
    def _hash_content(content: str) -> str:
        return hashlib.sha256(content.encode()).hexdigest()[:12]


@dataclass
class Document:
    """A document in the RAG pipeline."""
    text: str
    metadata: dict[str, Any] | None = None
    id: str | None = None
    source: str | None = None
    embedding: list[float] | None = None


@dataclass
class ScanReport:
    """Aggregated scan results."""
    total_documents: int
    findings: list[Finding]
    severity_summary: dict[str, int]

    @property
    def is_clean(self) -> bool:
        return len(self.findings) == 0

    @property
    def has_blocking_findings(self) -> bool:
        """True when any finding is critical or high severity."""
        return any(
            f.severity in (Severity.CRITICAL, Severity.HIGH) for f in self.findings
        )

    def summary(self) -> str:
        lines = [
            "RAG Security Scan Report",
            "=" * 40,
            f"Documents scanned: {self.total_documents}",
            f"Total findings: {len(self.findings)}",
        ]
        for sev, count in sorted(self.severity_summary.items()):
            lines.append(f"  {sev.upper()}: {count}")
        return "\n".join(lines)
