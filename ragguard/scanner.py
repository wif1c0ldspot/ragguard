"""Core scanning engine for RAG pipeline security assessment.

The scanner is deliberately dependency-light: detection is heuristic and
explainable rather than model-based, so every finding traces back to a named
pattern family.

Each text is prepared once into several surfaces, and every rule matches the
surface(s) its family declares:

* **canonical** — text is HTML-entity decoded, NFKC normalised, zero-width and
  bidi control characters are stripped, whitespace is collapsed and the result
  is lowercased before matching. This defeats the cheap obfuscation tricks
  (``&#x49;gnore``, ``ig​nore``, ``IGNORE   PREVIOUS``).
* **deobfuscated** — the canonical text after a confusables skeleton
  (Cyrillic/Greek look-alikes to Latin), collapsing of letter-spaced runs
  (``i g n o r e``) and leetspeak folding (``1gn0re``). Canonical-surface rules
  match canonical *or* deobfuscated text; deobfuscated-only evidence is marked
  ``[deobfuscated]``.
* **raw** — matched against the original text, for families whose *signal is the
  obfuscation itself* (encoded payloads, dangerous markup).
* **decoded** — bounded, single-level decoding of base64 and hex runs found in
  the raw text, re-scanned with the injection families. Evidence is marked
  ``[base64-decoded]`` or ``[hex-decoded]``.

OWASP mappings follow the **OWASP Top 10 for LLM Applications 2025**.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import math
import re
import unicodedata
import warnings
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, replace
from enum import Enum
from itertools import islice
from typing import Any

RULESET_VERSION = "2026.10.2"

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


@dataclass(frozen=True, kw_only=True)
class Finding:
    """A single, immutable security finding from a RAG pipeline scan.

    Construct with keywords; use :func:`dataclasses.replace` to derive variants.
    """
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
    Canonical-surface rules additionally match the deobfuscated surface.
    """
    family: str
    pattern: re.Pattern[str]
    severity: Severity
    owasp: str
    remediation: str
    surface: str = "canonical"


# --- Canonicalisation -------------------------------------------------------

_ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠-⁤﻿]")
_WHITESPACE_RE = re.compile(r"\s+")


def _pre_canonical(text: str) -> str:
    """Canonical text before whitespace collapsing (keeps word separation intact)."""
    decoded = html.unescape(text)
    normalised = unicodedata.normalize("NFKC", decoded)
    return _ZERO_WIDTH_RE.sub("", normalised).lower()


def canonicalize(text: str) -> str:
    """Normalise text so obfuscated payloads match plain-text rules.

    Decodes HTML entities, applies NFKC normalisation, strips zero-width and
    bidi control characters, collapses all whitespace to single spaces and
    lowercases the result.
    """
    return _WHITESPACE_RE.sub(" ", _pre_canonical(text))


# --- Deobfuscation ------------------------------------------------------------

# Curated confusables skeleton in the spirit of Unicode TS #39: lowercase
# Cyrillic, Greek and Latin-extension look-alikes folded to ASCII. Fullwidth and
# mathematical alphanumerics are already folded by NFKC during canonicalisation.
_CONFUSABLES = str.maketrans({
    # Cyrillic
    "а": "a", "в": "b", "е": "e", "ё": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ї": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ԛ": "q", "ԝ": "w", "к": "k", "ո": "n", "ս": "u", "т": "t", "м": "m", "н": "h",
    # Greek
    "α": "a", "β": "b", "γ": "y", "ε": "e", "ζ": "z", "η": "n", "ι": "i", "κ": "k",
    "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w", "ϲ": "c",
    "ϳ": "j", "ς": "c",
    # Latin extensions and IPA
    "ɡ": "g", "ı": "i", "ȷ": "j", "ɑ": "a", "ɩ": "i", "ɪ": "i", "ʏ": "y", "ɴ": "n",
    "ʀ": "r", "ꜱ": "s", "ᴏ": "o", "ᴄ": "c", "ᴅ": "d", "ᴇ": "e", "ᴜ": "u", "ᴠ": "v",
    "ᴡ": "w", "ᴢ": "z", "ʜ": "h", "ʟ": "l", "ᴍ": "m", "ᴛ": "t", "ᴋ": "k", "ᴘ": "p",
})
# Runs of >=4 single letters joined by one consistent single separator.
_SPACED_LETTERS_RE = re.compile(r"(?<![a-z0-9])[a-z]([ .\-])[a-z](?:\1[a-z]){2,}(?![a-z0-9])")
_SPACED_SEPARATORS_RE = re.compile(r"[ .\-]")
# Tokens holding at least one leetspeak character; folded only if they hold letters.
_LEET_TOKEN_RE = re.compile(r"(?<![a-z0-9@$])[a-z@$]*[0-9@$][a-z0-9@$]*")
_LEET_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
})
_ASCII_LETTER_RE = re.compile(r"[a-z]")


def _fold_leet(match: re.Match[str]) -> str:
    token = match.group(0)
    return token.translate(_LEET_MAP) if _ASCII_LETTER_RE.search(token) else token


def _deobfuscate(pre_canonical: str) -> str:
    """Confusables skeleton, letter-spacing collapse and leetspeak folding."""
    skeleton = pre_canonical.translate(_CONFUSABLES)
    collapsed = _SPACED_LETTERS_RE.sub(
        lambda m: _SPACED_SEPARATORS_RE.sub("", m.group(0)), skeleton
    )
    return _LEET_TOKEN_RE.sub(_fold_leet, collapsed)


@dataclass(frozen=True)
class _Surfaces:
    """All match surfaces of one text, computed once per text."""
    raw: str
    canonical: str
    deobfuscated: str | None  # None when identical to ``canonical``


def _surfaces(text: str) -> _Surfaces:
    pre = _pre_canonical(text)
    canonical = _WHITESPACE_RE.sub(" ", pre)
    deobfuscated = _WHITESPACE_RE.sub(" ", _deobfuscate(pre))
    return _Surfaces(text, canonical, None if deobfuscated == canonical else deobfuscated)


# --- Encoded payload decoding -----------------------------------------------

_MAX_DECODED_SEGMENTS = 8
_MAX_DECODED_BYTES = 16 * 1024
_MAX_DECODE_ATTEMPTS = 64
_MIN_PRINTABLE_RATIO = 0.8
_BASE64_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/=_-])"
)
_HEX_RUN_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_NON_PRINTABLE_RE = re.compile(r"[^\t\n\r\x20-\x7e -￼\U00010000-\U0010ffff]")
_BASE64_LABEL = "[base64-decoded] "
_HEX_LABEL = "[hex-decoded] "
_DEOBFUSCATED_LABEL = "[deobfuscated] "


def _printable_text(data: bytes) -> str | None:
    """Decode UTF-8 and accept it only if mostly printable."""
    if not data:
        return None
    text = data.decode("utf-8", errors="replace")
    _, non_printable = _NON_PRINTABLE_RE.subn("", text)
    return text if 1 - non_printable / len(text) >= _MIN_PRINTABLE_RATIO else None


def _decode_base64(run: str, budget: int) -> bytes | None:
    if len(run) < 24:
        return None
    limit = (budget * 4 // 3) // 4 * 4
    if len(run) > limit:
        run = run[:limit].rstrip("=")
        run = run[:len(run) // 4 * 4]
    elif len(run) % 4:
        run += "=" * (-len(run) % 4)
    try:
        return base64.b64decode(run, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError):
        return None


def _decode_hex(run: str, budget: int) -> bytes | None:
    run = run[:budget * 2]
    try:
        return bytes.fromhex(run)
    except ValueError:
        return None


def _decoded_segments(text: str) -> list[tuple[str, _Surfaces]]:
    """Bounded, single-level decoding of hex and base64 runs; never raises."""
    segments: list[tuple[str, _Surfaces]] = []
    budget = _MAX_DECODED_BYTES
    attempts = 0
    try:
        for label, regex in ((_HEX_LABEL, _HEX_RUN_RE), (_BASE64_LABEL, _BASE64_RUN_RE)):
            for match in regex.finditer(text):
                if (len(segments) >= _MAX_DECODED_SEGMENTS or budget <= 0
                        or attempts >= _MAX_DECODE_ATTEMPTS):
                    return segments
                run = match.group(0)
                if label == _BASE64_LABEL and _HEX_RUN_RE.fullmatch(run):
                    continue  # already handled as hex
                attempts += 1
                data = (_decode_hex(run, budget) if label == _HEX_LABEL
                        else _decode_base64(run, budget))
                decoded = _printable_text(data) if data else None
                if data is None or decoded is None:
                    continue
                budget -= len(data)
                segments.append((label, _surfaces(decoded)))
    except (ValueError, TypeError, MemoryError, RecursionError):
        return segments
    return segments


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

# A template placeholder an assistant might fill with conversation data.
_URL_PLACEHOLDER = (
    r"(?:\{\{\s*[^{}\s]{1,64}\s*\}\}"                 # {{conversation}}
    r"|\$\{[^{}\s]{1,64}\}"                           # ${secret}
    r"|\{[A-Za-z_][\w.\-]{0,63}\}"                    # {token}
    r"|<[A-Za-z_][\w.\- ]{0,63}>"                     # <user_data>
    r"|\[[A-Za-z_][\w.\- ]{0,63}\]"                   # [DATA]
    r"|%7b(?:%7b)?[A-Za-z_][\w.\-]{0,63}%7d)"         # URL-encoded braces
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
    PatternFamily(
        # Images render (and fetch) without a click, so any placeholder in the URL
        # counts; plain links only when the placeholder sits in the query string,
        # so documentation links with path parameters (``/users/{id}``) stay clean.
        family="markdown_exfiltration",
        pattern=re.compile(
            r"!\[[^\]\n]{0,256}\]\(\s*<?https?://[^\s()]{0,2048}?" + _URL_PLACEHOLDER
            + r"|\[[^\]\n]{0,256}\]\(\s*<?https?://[^\s()?]{0,2048}\?[^\s()]{0,2048}?"
            + _URL_PLACEHOLDER
            + r"|<img\b[^>]{0,512}?\bsrc\s*=\s*[\"']?https?://[^\s\"'>]{0,2048}?"
            + _URL_PLACEHOLDER,
            re.IGNORECASE,
        ),
        severity=Severity.HIGH,
        owasp=LLM02_SENSITIVE_INFO,
        remediation=(
            "Disable remote image rendering in model output, or allow-list URL domains for "
            "links and images; never let the model fill URL parameters with context data."
        ),
        surface="raw",
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

_DOM_EVENT_HANDLERS = (
    r"on(?:click|dblclick|contextmenu|error|load|unload|beforeunload|abort|"
    r"mouse(?:over|out|down|up|enter|leave|move)|pointer(?:down|up|over|out|enter|leave|move)|"
    r"touch(?:start|end|move)|focus(?:in|out)?|blur|change|submit|reset|select|"
    r"key(?:down|up|press)|input|invalid|animation(?:start|end|iteration)|transition(?:start|end)|"
    r"toggle|drag(?:start|end|over|enter|leave)?|drop|copy|cut|paste|wheel|scroll|resize|"
    r"hashchange|popstate|message|play|pause|begin|show)"
)

SPLIT_FAMILIES: tuple[PatternFamily, ...] = (
    PatternFamily(
        family="split_marker_open",
        pattern=re.compile(r"(?<=[.!?])\s*(?:begin|start|first\s+part|step\s+1)\b", re.I),
        severity=Severity.INFO,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reassemble split documents before scanning; scan the parent document, not chunks."
        ),
    ),
    PatternFamily(
        family="split_marker_close",
        pattern=re.compile(r"(?<=[.!?])\s*(?:end|stop|finish|last\s+part|step\s+\d+)\b", re.I),
        severity=Severity.INFO,
        owasp=LLM01_PROMPT_INJECTION,
        remediation=(
            "Reassemble split documents before scanning; scan the parent document, not chunks."
        ),
    ),
    PatternFamily(
        family="structural_dangerous_tag",
        pattern=re.compile(
            r"<\s*/?\s*(?:script|iframe|object|embed|svg|form|base)\b[^>]*>"
            rf"|\b{_DOM_EVENT_HANDLERS}\s*=", re.IGNORECASE,
        ),
        severity=Severity.LOW,
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

_INJECTION_FAMILY_NAMES = frozenset(rule.family for rule in INJECTION_FAMILIES)
_INSTRUCTION_OVERRIDE = next(r for r in INJECTION_FAMILIES if r.family == "instruction_override")
_ACTION_ENUMERATION_RE = re.compile(r"\binstruction\s*:")
_SPLIT_PAYLOAD_REMEDIATION = (
    "Scan parent documents before chunking, or scan chunk boundaries with overlap; "
    "quarantine both chunks until the reassembled text has been reviewed."
)
# Upper bound on matches inspected per family and surface, as a multiple of the
# requested ``max_matches_per_family`` (bounds evidence de-duplication work).
_MATCH_SCAN_FACTOR = 16


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


def _positive_int(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _build_report(total: int, findings: list[Finding]) -> ScanReport:
    summary: dict[str, int] = {}
    for finding in findings:
        summary[finding.severity.value] = summary.get(finding.severity.value, 0) + 1
    return ScanReport(total, findings, summary)


class RAGScanner:
    """Stateless heuristic scanner, safe to reuse across concurrent scans.

    ``enabled_families=None`` enables all rules; an empty iterable disables all.
    ``max_matches_per_family`` caps findings per family for each scanned text
    (document body or metadata leaf); identical evidence is reported once.
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
        max_matches_per_family: int = 1,
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
        known.update(("canonical_override_plus_action", "split_payload"))
        selected = known if enabled_families is None else set(enabled_families)
        if selected - known:
            raise ValueError(f"Unknown rule families: {sorted(selected - known)}")
        self.enabled_families = frozenset(selected)
        self.redact_evidence = redact_evidence
        self.max_matches_per_family = _positive_int(
            "max_matches_per_family", max_matches_per_family
        )

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
            findings.extend(self._scan_document(
                doc, index, _surfaces(doc.text),
                check_prompt_injection=check_prompt_injection,
                check_metadata=check_metadata,
                check_chunk_splitting=check_chunk_splitting,
            ))
        return _build_report(len(documents), findings)

    def scan_chunks(self, chunks: list[Document], *, window_chars: int = 256) -> ScanReport:
        """Scan ordered chunks of one source, including payloads split across boundaries.

        Every chunk is scanned as by :meth:`scan_documents`. Additionally, the
        boundary window (last ``window_chars`` of chunk *i* and first
        ``window_chars`` of chunk *i+1*) is matched both with a separator and
        directly concatenated, covering word and character splits. Windows and
        chunks use the same bounded decoding as document scans. A family that
        fires in a window but in neither chunk alone is
        reported as ``split_payload`` on chunk *i*, with both chunks related.
        """
        window_chars = _positive_int("window_chars", window_chars)
        surfaces = [_surfaces(chunk.text) for chunk in chunks]
        findings: list[Finding] = []
        for index, chunk in enumerate(chunks):
            findings.extend(self._scan_document(chunk, index, surfaces[index]))
        if "split_payload" in self.enabled_families:
            rules = [r for r in INJECTION_FAMILIES if r.family in self.enabled_families]
            for index in range(len(chunks) - 1):
                findings.extend(self._scan_boundary(
                    chunks, index, surfaces[index], surfaces[index + 1], rules, window_chars,
                ))
        return _build_report(len(chunks), findings)

    def _scan_boundary(
        self, chunks: list[Document], index: int, left: _Surfaces, right: _Surfaces,
        rules: list[PatternFamily], window_chars: int,
    ) -> list[Finding]:
        tail, head = chunks[index].text[-window_chars:], chunks[index + 1].text[:window_chars]
        # Match on the newline-joined window; locate evidence on a space-joined copy
        # so phrases spanning the boundary keep their original casing.
        window = replace(_surfaces(tail + "\n" + head), raw=tail + " " + head)
        joined = tail + head
        sources = [("", window), ("", _surfaces(joined))]
        sources.extend(_decoded_segments(tail + "\n" + head))
        sources.extend(_decoded_segments(joined))
        sides = [("", left), ("", right)]
        sides.extend(_decoded_segments(left.raw))
        sides.extend(_decoded_segments(right.raw))

        def first_hit(
            rule: PatternFamily, candidates: list[tuple[str, _Surfaces]],
        ) -> tuple[str, str] | None:
            for source_label, source in candidates:
                hit = next(self._iter_evidence(rule, source), None)
                if hit is not None:
                    label, body = hit
                    return source_label + label, body
            return None

        findings: list[Finding] = []
        ids = (resolve_document_id(chunks[index]), resolve_document_id(chunks[index + 1]))
        for rule in rules:
            hit = first_hit(rule, sources)
            if hit is None:
                continue
            if first_hit(rule, sides) is not None:
                continue
            label, body = hit
            findings.append(Finding(
                finding_type=FindingType.CHUNK_SPLIT_ATTACK,
                severity=rule.severity,
                document_id=ids[0],
                description=(
                    f"Injection pattern ({rule.family}) spans the boundary between chunks "
                    f"{index} and {index + 1}; neither chunk matches on its own"
                ),
                evidence=self._finalize_evidence(rule, label, body.replace("\n", " ")),
                remediation=_SPLIT_PAYLOAD_REMEDIATION,
                owasp_mapping=LLM01_PROMPT_INJECTION,
                family="split_payload",
                document_index=index,
                related_document_ids=ids,
                related_document_indices=(index, index + 1),
            ))
        return findings

    def _scan_document(
        self, doc: Document, index: int, surfaces: _Surfaces, *,
        check_prompt_injection: bool = True,
        check_metadata: bool = True,
        check_chunk_splitting: bool = True,
    ) -> list[Finding]:
        findings: list[Finding] = []
        doc_id = resolve_document_id(doc)
        if check_prompt_injection:
            findings.extend(self._scan_rules(
                doc.text, INJECTION_FAMILIES, FindingType.PROMPT_INJECTION_IN_DOCUMENT,
                doc_id, index, surfaces=surfaces, decode=True,
            ))
            override_surfaces = [surfaces.canonical]
            if surfaces.deobfuscated is not None:
                override_surfaces.append(surfaces.deobfuscated)
            if ("canonical_override_plus_action" in self.enabled_families
                    and "instruction_override" in self.enabled_families
                    and any(_INSTRUCTION_OVERRIDE.pattern.search(surface)
                            and _ACTION_ENUMERATION_RE.search(surface)
                            for surface in override_surfaces)):
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
            findings.extend(self._scan_metadata(doc, doc_id, index))
        if check_chunk_splitting:
            findings.extend(self._scan_rules(
                doc.text, SPLIT_FAMILIES, FindingType.CHUNK_SPLIT_ATTACK,
                doc_id, index, raw=True, surfaces=surfaces,
            ))
        return findings

    def _scan_metadata(self, doc: Document, doc_id: str, index: int) -> list[Finding]:
        if doc.metadata is not None and not isinstance(doc.metadata, dict):
            raise TypeError("Document.metadata must be a dictionary or None")
        findings: list[Finding] = []
        rules = INJECTION_FAMILIES + METADATA_FAMILIES
        for path, key, value in _metadata_leaves(doc.metadata):
            # Preserve field structure rather than scanning Python repr(dict).
            candidate = f"{key}: {value}" if key else value
            matches = self._scan_rules(
                candidate, rules, FindingType.METADATA_INJECTION, doc_id, index, path,
                decode=True,
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
                        finding_type=FindingType.METADATA_INJECTION, severity=rule.severity,
                        document_id=doc_id, description="Credential-bearing metadata field",
                        evidence=value[:120], remediation=rule.remediation,
                        owasp_mapping=rule.owasp, family=rule.family,
                        document_index=index, metadata_path=path,
                    ))
            if self.redact_evidence:
                redacted_path = _redact_metadata_path(path)
                matches = [
                    replace(
                        finding, metadata_path=redacted_path,
                        evidence=("[REDACTED credential-bearing metadata]" if sensitive
                                  else finding.evidence),
                    )
                    for finding in matches
                ]
            findings.extend(matches)
        return findings

    def _scan_rules(
        self, text: str, rules: tuple[PatternFamily, ...], kind: FindingType,
        doc_id: str, index: int, path: str | None = None, *, raw: bool = False,
        surfaces: _Surfaces | None = None, decode: bool = False,
    ) -> list[Finding]:
        """Match ``rules`` against one text's surfaces, up to the per-family cap.

        ``surfaces`` lets callers reuse surfaces already computed for ``text``;
        ``decode`` additionally re-scans decoded base64/hex runs with the
        injection families.
        """
        if surfaces is None:
            surfaces = _surfaces(text)
        findings: list[Finding] = []
        segments: list[tuple[str, _Surfaces]] | None = None
        for rule in rules:
            if rule.family not in self.enabled_families:
                continue
            evidences: list[str] = []
            sources: list[tuple[str, _Surfaces]] = [("", surfaces)]
            if decode and not raw and rule.family in _INJECTION_FAMILY_NAMES:
                if segments is None:
                    segments = _decoded_segments(text)
                sources.extend(segments)
            for source_label, source in sources:
                for label, body in self._iter_evidence(rule, source, raw=raw):
                    evidence = self._finalize_evidence(rule, source_label + label, body)
                    if evidence not in evidences:
                        evidences.append(evidence)
                    if len(evidences) >= self.max_matches_per_family:
                        break
                if len(evidences) >= self.max_matches_per_family:
                    break
            findings.extend(
                Finding(
                    finding_type=kind, severity=rule.severity, document_id=doc_id,
                    description=(
                        f"Potential risk ({rule.family}); heuristic match requires context"
                    ),
                    evidence=evidence, remediation=rule.remediation,
                    owasp_mapping=rule.owasp, family=rule.family,
                    document_index=index, metadata_path=path,
                )
                for evidence in evidences
            )
        return findings

    def _iter_evidence(
        self, rule: PatternFamily, surfaces: _Surfaces, *, raw: bool = False,
    ) -> Iterator[tuple[str, str]]:
        """Yield ``(label, evidence)`` for a rule's matches, canonical before deobfuscated."""
        cap = self.max_matches_per_family * _MATCH_SCAN_FACTOR
        if raw or rule.surface == "raw":
            for match in islice(rule.pattern.finditer(surfaces.raw), cap):
                yield "", surfaces.raw[match.start():match.end()].strip()
            return
        seen: set[str] = set()
        for match in islice(rule.pattern.finditer(surfaces.canonical), cap):
            seen.add(match.group(0).strip())
            yield "", self._evidence(surfaces.raw, match.group(0))
        if surfaces.deobfuscated is None:
            return
        for match in islice(rule.pattern.finditer(surfaces.deobfuscated), cap):
            matched = match.group(0).strip()
            if matched not in seen:
                yield _DEOBFUSCATED_LABEL, matched

    def _finalize_evidence(self, rule: PatternFamily, label: str, body: str) -> str:
        """Redact (before truncating) and prefix evidence with its surface label."""
        if self.redact_evidence:
            body = _SECRET_RE.sub("[REDACTED]", body)
            if rule.family == "metadata_credential_leak":
                body = "[REDACTED credential]"
        return label + body[:120]

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
