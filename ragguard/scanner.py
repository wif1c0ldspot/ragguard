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
import re
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any

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

_ZERO_WIDTH_RE = re.compile(r"[\u200b-\u200f\u2028-\u202f\u2060-\u2064\ufeff]")
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
            r"|\bjavascript\s*:|\bdata\s*:\s*text/html"
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
            r"\b(?:developer|debug|maintenance|sudo|god)\s+mode\b"
            r"|\bd\s*a\s*r\s*k\s*(?:w\s*e\s*b|n\s*e\s*t)\b"
            r"|\bshadow\s*(?:net|web|zone)\b"
        ),
        severity=Severity.HIGH,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reject the document; jailbreak framings have no legitimate place in a corpus."
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
        pattern=re.compile(r"\b[A-Z_]{4,}\s*=\s*[\"'][^\"'<>\n]{10,}"),
        severity=Severity.HIGH,
        owasp=LLM01_PROMPT_INJECTION,
        remediation="Strip instruction-bearing fields from metadata before ingestion.",
    ),
    PatternFamily(
        family="metadata_tool_call",
        pattern=re.compile(
            r"[\"']?\b(?:FUNCTION|ACTION|TOOL)\b[\"']?\s*[:=]\s*[\"']?"
            r"(?:write_|exec|invoke|rm_|curl|wget|http|POST|GET)\b",
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
        pattern=re.compile(r"(?<=[.!?])\s*(?:begin|start|first\s+part|step\s+1)\b"),
        severity=Severity.MEDIUM,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reassemble split documents before scanning; scan the parent document, not chunks."
        ),
    ),
    PatternFamily(
        family="split_marker_close",
        pattern=re.compile(r"(?<=[.!?])\s*(?:end|stop|finish|last\s+part|step\s+\d+)\b"),
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
            r"|\bon[a-z]+\s*=\s*[\"']?[a-z]+",
        ),
        severity=Severity.MEDIUM,
        owasp=LLM05_IMPROPER_OUTPUT,
        remediation=(
            "Strip executable markup at ingestion; retrieved text should never be rendered as HTML."
        ),
    ),
    PatternFamily(
        family="structural_sql_keyword",
        pattern=re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[\s\S]{0,40}?\bFROM\b"),
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
    return doc.id or RAGScanner._hash_content(doc.text[:100])



class RAGScanner:
    """Main scanner class for RAG pipeline security assessment."""

    def __init__(
        self,
        *,
        chunk_size: int = 500,
        chunk_overlap: int = 50,
        embedding_dim: int = 1536,
        similarity_threshold: float = 0.95,
    ):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap
        self.embedding_dim = embedding_dim
        self.similarity_threshold = similarity_threshold
        self._findings: list[Finding] = []

    def scan_documents(
        self,
        documents: list[Document],
        *,
        check_prompt_injection: bool = True,
        check_metadata: bool = True,
        check_chunk_splitting: bool = True,
    ) -> ScanReport:
        """Scan a collection of documents for RAG pipeline security issues."""
        self._findings = []

        for doc in documents:
            doc_id = resolve_document_id(doc)

            if check_prompt_injection:
                self._scan_prompt_injection(doc, doc_id)

            if check_metadata:
                self._scan_metadata(doc, doc_id)

            if check_chunk_splitting:
                self._scan_chunk_splitting(doc, doc_id)

            self._scan_canonical_injection(doc, doc_id)

        return ScanReport(
            total_documents=len(documents),
            findings=self._findings,
            severity_summary=self._severity_summary(),
        )

    def _scan_prompt_injection(self, doc: Document, doc_id: str) -> None:
        canonical = canonicalize(doc.text)
        for rule in INJECTION_FAMILIES:
            haystack = doc.text if rule.surface == "raw" else canonical
            match = rule.pattern.search(haystack)
            if match:
                self._findings.append(Finding(
                    finding_type=FindingType.PROMPT_INJECTION_IN_DOCUMENT,
                    severity=rule.severity,
                    document_id=doc_id,
                    description=f"Prompt injection detected in document body ({rule.family})",
                    evidence=self._evidence(doc.text, match.group(0)),
                    remediation=rule.remediation,
                    owasp_mapping=rule.owasp,
                    family=rule.family,
                ))

    def _scan_metadata(self, doc: Document, doc_id: str) -> None:
        metadata_str = str(doc.metadata or {})
        for rule in METADATA_FAMILIES:
            match = rule.pattern.search(metadata_str)
            if match:
                self._findings.append(Finding(
                    finding_type=FindingType.METADATA_INJECTION,
                    severity=rule.severity,
                    document_id=doc_id,
                    description=f"Malicious payload in document metadata ({rule.family})",
                    evidence=match.group(0)[:100],
                    remediation=rule.remediation,
                    owasp_mapping=rule.owasp,
                    family=rule.family,
                ))

    def _scan_chunk_splitting(self, doc: Document, doc_id: str) -> None:
        for rule in SPLIT_FAMILIES:
            match = rule.pattern.search(doc.text)
            if match:
                self._findings.append(Finding(
                    finding_type=FindingType.CHUNK_SPLIT_ATTACK,
                    severity=rule.severity,
                    document_id=doc_id,
                    description=f"Structural risk in document ({rule.family})",
                    evidence=match.group(0)[:100],
                    remediation=rule.remediation,
                    owasp_mapping=rule.owasp,
                    family=rule.family,
                ))

    def _scan_canonical_injection(self, doc: Document, doc_id: str) -> None:
        """Detect payloads combining an instruction override with an enumerated action.

        Runs on canonicalised text, so entity-encoded, zero-width-split and
        whitespace-padded variants are caught (e.g. ``&#x49;gnore previous
        instructions``).
        """
        canonical = canonicalize(doc.text)
        has_override = INJECTION_FAMILIES[0].pattern.search(canonical) is not None
        if has_override and _ACTION_ENUMERATION_RE.search(canonical):
            self._findings.append(Finding(
                finding_type=FindingType.CANONICAL_INJECTION,
                severity=Severity.CRITICAL,
                document_id=doc_id,
                description=(
                    "Canonical injection bypass: instruction override combined with an "
                    "enumerated action in the same document"
                ),
                evidence=self._evidence(doc.text, "instruction:"),
                remediation=(
                    "Apply input canonicalisation (entity decode + NFKC + zero-width strip) and "
                    "reject documents whose payload only surfaces after normalisation."
                ),
                owasp_mapping=LLM01_PROMPT_INJECTION,
                family="canonical_override_plus_action",
            ))

    @staticmethod
    def _evidence(raw: str, matched: str) -> str:
        """Return the matched phrase in its original casing where possible."""
        needle = matched.strip()
        if not needle:
            return ""
        idx = raw.lower().find(needle)
        if idx >= 0:
            return raw[idx:idx + len(needle)][:120]
        return needle[:120]

    def _severity_summary(self) -> dict[str, int]:
        summary: dict[str, int] = {}
        for f in self._findings:
            key = f.severity.value
            summary[key] = summary.get(key, 0) + 1
        return summary

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
