"""Optional provider-neutral semantic detectors; no model or network client is bundled."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Protocol

from ragguard.scanner import (
    LLM01_PROMPT_INJECTION,
    Document,
    Finding,
    FindingType,
    Severity,
    resolve_document_id,
)


@dataclass(frozen=True)
class DetectorInput:
    """One immutable occurrence; metadata, provenance and embeddings are excluded."""

    text: str
    document_index: int
    document_id: str


@dataclass(frozen=True)
class SemanticDetection:
    """An adapter's prompt-injection assessment, not verified ground truth."""

    severity: Severity = Severity.HIGH
    score: float | None = None


@dataclass(frozen=True)
class DetectorResult:
    """Typed output and optional adapter-reported usage (not independently verified)."""

    detections: tuple[SemanticDetection, ...] = ()
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class SemanticDetector(Protocol):
    """Adapters must enforce their own transport timeout and retry/cost budgets."""

    def detect(self, document: DetectorInput) -> DetectorResult: ...


@dataclass(frozen=True)
class DetectorConfig:
    """Reject oversized inputs; never silently truncate detector coverage.

    max_elapsed_seconds is checked after a synchronous call returns. It cannot
    cancel that call and is not a hard timeout.
    """

    max_documents: int = 100
    max_chars_per_document: int = 20_000
    max_total_chars: int = 200_000
    max_detections_per_document: int = 16
    max_elapsed_seconds: float | None = None

    def __post_init__(self) -> None:
        for name in ("max_documents", "max_chars_per_document", "max_total_chars",
                     "max_detections_per_document"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        if self.max_elapsed_seconds is not None:
            _number("max_elapsed_seconds", self.max_elapsed_seconds, positive=True)


@dataclass(frozen=True)
class DetectorRun:
    """Observed latency and unverified adapter usage for one occurrence."""

    document_index: int
    elapsed_seconds: float
    status: str
    detections: int = 0
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_usd: float | None = None


class DetectorError(RuntimeError):
    """No policy decision is returned on a detector failure.

    runs contains completed calls and, for a failed call, its observed latency.
    Exception messages deliberately exclude provider responses and input text.
    """

    def __init__(self, message: str, runs: tuple[DetectorRun, ...] = ()):
        super().__init__(message)
        self.runs = runs


def _number(name: str, value: object, *, positive: bool = False) -> None:
    try:
        valid = (not isinstance(value, bool) and isinstance(value, (int, float))
                 and math.isfinite(value) and (value > 0 if positive else value >= 0))
    except OverflowError:
        valid = False
    if not valid:
        sign = "positive" if positive else "nonnegative"
        raise ValueError(f"{name} must be a finite {sign} number")


def _validate_result(result: DetectorResult, config: DetectorConfig) -> None:
    if not isinstance(result, DetectorResult) or not isinstance(result.detections, tuple):
        raise ValueError("detector must return DetectorResult with a tuple of detections")
    if len(result.detections) > config.max_detections_per_document:
        raise ValueError("detector output budget exceeded")
    for detection in result.detections:
        if (not isinstance(detection, SemanticDetection)
                or not isinstance(detection.severity, Severity)):
            raise ValueError("invalid semantic detection")
        if detection.score is not None:
            _number("score", detection.score)
            if detection.score > 1:
                raise ValueError("score must be at most one")
    for value in (result.input_tokens, result.output_tokens):
        if value is not None and (type(value) is not int or value < 0):
            raise ValueError("token usage must be a nonnegative integer")
    if result.cost_usd is not None:
        _number("cost_usd", result.cost_usd)


def run_detector(
    detector: SemanticDetector, documents: list[Document], config: DetectorConfig,
) -> tuple[list[Finding], tuple[DetectorRun, ...]]:
    """Validate all inputs before any adapter call; fail closed on every error."""
    if (len(documents) > config.max_documents
            or any(len(doc.text) > config.max_chars_per_document for doc in documents)
            or sum(len(doc.text) for doc in documents) > config.max_total_chars):
        raise DetectorError("Semantic detector input budget exceeded")
    findings: list[Finding] = []
    runs: list[DetectorRun] = []
    for index, document in enumerate(documents):
        started = time.perf_counter()
        try:
            request = DetectorInput(document.text, index, resolve_document_id(document))
            result = detector.detect(request)
            elapsed = time.perf_counter() - started
            _validate_result(result, config)
            if config.max_elapsed_seconds is not None and elapsed > config.max_elapsed_seconds:
                raise ValueError("semantic detector elapsed-time budget exceeded")
        except Exception as exc:
            elapsed = time.perf_counter() - started
            runs.append(DetectorRun(index, elapsed, "error"))
            raise DetectorError(
                f"Semantic detector failed at document index {index}", tuple(runs),
            ) from exc
        runs.append(DetectorRun(index, elapsed, "ok", len(result.detections),
                                result.input_tokens, result.output_tokens, result.cost_usd))
        for detection in result.detections:
            findings.append(Finding(
                finding_type=FindingType.PROMPT_INJECTION_IN_DOCUMENT,
                severity=detection.severity,
                document_id=resolve_document_id(document), document_index=index,
                family="semantic_prompt_injection", confidence="model-assessed",
                description="Configured semantic detector flagged possible prompt injection",
                evidence=("[semantic detector]" if detection.score is None
                          else f"[semantic detector] score={detection.score:.6g}"),
                remediation="Review source context and the detector assessment before use.",
                owasp_mapping=LLM01_PROMPT_INJECTION,
            ))
    return findings, tuple(runs)
