"""Optional offline Prompt Guard 2 adapter; importing this module needs no ML SDK.

Model card: https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M
Weights are gated by the publisher. Provision a reviewed, pinned snapshot yourself;
this adapter never downloads weights or accepts a model license on your behalf.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import math
import re
from bisect import bisect_left
from dataclasses import asdict, dataclass
from typing import Any

from ragguard.detectors import (
    DetectorInput,
    DetectorProvenance,
    DetectorResult,
    SemanticDetection,
)

MODEL_ID = "meta-llama/Llama-Prompt-Guard-2-22M"


def _digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _probability(value: object) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value) and 0 <= value <= 1)


@dataclass(frozen=True)
class ScoreCalibration:
    """Empirical operating point, not a guarantee on future or shifted inputs.

    Scores must come from this pinned model on a separate labeled calibration set.
    Keep an independent evaluation set for reporting quality after selection.
    """

    model_revision: str
    dataset_sha256: str
    threshold: float
    false_positive_rate: float
    recall: float
    benign_samples: int
    attack_samples: int

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.model_revision):
            raise ValueError("model_revision must be an immutable 40-character commit SHA")
        if not re.fullmatch(r"[0-9a-f]{64}", self.dataset_sha256):
            raise ValueError("dataset_sha256 must identify the calibration dataset")
        if not all(_probability(value) for value in (
            self.threshold, self.false_positive_rate, self.recall,
        )):
            raise ValueError("calibration probabilities must be finite and within [0, 1]")
        if any(type(count) is not int or count < 1
               for count in (self.benign_samples, self.attack_samples)):
            raise ValueError("calibration requires both benign and attack samples")


def calibrate_threshold(
    samples: list[tuple[float, bool]], *, model_revision: str, dataset_sha256: str,
    max_false_positive_rate: float = 0.01,
) -> ScoreCalibration:
    """Choose maximum empirical recall under the specified observed FPR ceiling.

    Ties use the larger threshold. Equality to threshold is classified malicious.
    This helper consumes measured scores; it does not run or evaluate a model.
    """
    if not samples or not _probability(max_false_positive_rate):
        raise ValueError("invalid calibration samples or false-positive ceiling")
    if any(not _probability(score) or type(label) is not bool for score, label in samples):
        raise ValueError("calibration requires finite scores and boolean labels")
    benign = sum(not label for _, label in samples)
    attacks = len(samples) - benign
    if not benign or not attacks:
        raise ValueError("calibration requires both benign and attack samples")
    candidates = {0.0, 1.0, *(float(score) for score, _ in samples)}
    # Include thresholds immediately above observed scores to exclude ties.
    candidates.update(math.nextafter(score, 1.0) for score, _ in samples if score < 1)
    benign_scores = sorted(score for score, label in samples if not label)
    attack_scores = sorted(score for score, label in samples if label)
    feasible = []
    for threshold in candidates:
        fpr = (benign - bisect_left(benign_scores, threshold)) / benign
        recall = (attacks - bisect_left(attack_scores, threshold)) / attacks
        if fpr <= max_false_positive_rate:
            feasible.append((recall, threshold, fpr))
    if not feasible:
        raise ValueError("no threshold satisfies the false-positive ceiling")
    recall, threshold, fpr = max(feasible)
    return ScoreCalibration(model_revision, dataset_sha256, threshold, fpr, recall, benign, attacks)


@dataclass(frozen=True)
class LocalDetectorConfig:
    model_revision: str
    calibration: ScoreCalibration | None = None
    max_input_chars: int = 20_000
    max_tokens: int = 512

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{40}", self.model_revision):
            raise ValueError("model_revision must be an immutable 40-character commit SHA")
        if self.calibration is not None and (
            not isinstance(self.calibration, ScoreCalibration)
            or self.calibration.model_revision != self.model_revision
        ):
            raise ValueError("calibration must match the pinned model revision")
        if type(self.max_input_chars) is not int or self.max_input_chars < 1:
            raise ValueError("max_input_chars must be positive")
        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 512:
            raise ValueError("Prompt Guard 2 supports at most 512 tokens")


class LocalPromptInjectionDetector:
    """CPU inference over the complete text, using only an existing HF cache.

    Lazy loading keeps base installations standard-library only. Install torch,
    transformers and sentencepiece separately in the model runtime. Set up this
    object inside a ProcessDetector factory when a killable deadline is needed.
    """

    def __init__(self, config: LocalDetectorConfig) -> None:
        self._config = config
        self._runtime: tuple[Any, Any, Any] | None = None

    @property
    def config(self) -> LocalDetectorConfig:
        """Read-only configuration keeps cached weights bound to their revision."""
        return self._config

    @property
    def provenance(self) -> DetectorProvenance:
        calibration = self.config.calibration
        if calibration is None:
            raise ValueError("detection requires an explicit measured calibration record")
        return DetectorProvenance(
            adapter="transformers-prompt-guard-2-cpu", model_id=MODEL_ID,
            model_revision=calibration.model_revision,
            config_sha256=_digest(asdict(self.config)),
            calibration_sha256=_digest(asdict(calibration)),
        )

    def _load(self) -> tuple[Any, Any, Any]:
        if self._runtime is None:
            try:
                torch = importlib.import_module("torch")
                transformers = importlib.import_module("transformers")
            except ImportError as exc:
                raise RuntimeError(
                    "Local detector requires torch, transformers and sentencepiece",
                ) from exc
            options = dict(revision=self.config.model_revision,
                           local_files_only=True, trust_remote_code=False)
            tokenizer = transformers.AutoTokenizer.from_pretrained(MODEL_ID, **options)
            model = transformers.AutoModelForSequenceClassification.from_pretrained(
                MODEL_ID, use_safetensors=True, **options,
            ).to("cpu").eval()
            labels = {int(key): label for key, label in model.config.id2label.items()}
            if labels != {0: "BENIGN", 1: "MALICIOUS"}:
                raise ValueError("unexpected classifier label mapping")
            self._runtime = torch, tokenizer, model
        return self._runtime

    def score(self, text: str) -> tuple[float, int]:
        """Return a measured malicious score and token count for calibration/evaluation.

        Works without calibration; this does not produce a policy decision.
        Oversized inputs raise instead of truncating or excluding their suffix.
        """
        if type(text) is not str or len(text) > self.config.max_input_chars:
            raise ValueError("local detector input budget exceeded")
        torch, tokenizer, model = self._load()
        encoded = tokenizer(text, truncation=False, return_tensors="pt")
        tokens = int(encoded["input_ids"].shape[-1])
        if tokens > self.config.max_tokens:
            raise ValueError("local detector token budget exceeded; refusing partial scanning")
        with torch.inference_mode():
            logits = model(**encoded).logits
            if tuple(logits.shape) != (1, 2):
                raise ValueError("unexpected classifier output shape")
            score = float(torch.softmax(logits, dim=-1)[0, 1].item())
        if not _probability(score):
            raise ValueError("invalid classifier score")
        return score, tokens

    def detect(self, document: DetectorInput) -> DetectorResult:
        if self.config.calibration is None:
            raise ValueError("detection requires an explicit measured calibration record")
        score, tokens = self.score(document.text)
        detections = ((SemanticDetection(score=score),)
                      if score >= self.config.calibration.threshold else ())
        return DetectorResult(detections, input_tokens=tokens, output_tokens=0,
                              provenance=self.provenance)
