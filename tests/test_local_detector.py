"""Offline adapter contracts with fake tensors; no weights or model metrics are claimed."""

from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from ragguard.detectors import DetectorInput
from ragguard.local_detector import (
    LocalDetectorConfig,
    LocalPromptInjectionDetector,
    ScoreCalibration,
    calibrate_threshold,
)

REVISION = "a" * 40
DATASET = "b" * 64


def calibration(threshold=0.7):
    return ScoreCalibration(REVISION, DATASET, threshold, 0, 1, 10, 10)


class Probabilities:
    def __init__(self, score):
        self.value = score

    def __getitem__(self, index):
        assert index == (0, 1)
        return self

    def item(self):
        return self.value


def detector(score=0.8, tokens=10):
    adapter = LocalPromptInjectionDetector(LocalDetectorConfig(REVISION, calibration()))
    calls = []

    def tokenize(text, **kwargs):
        calls.append((text, kwargs))
        return {"input_ids": SimpleNamespace(shape=(1, tokens))}

    def model(**kwargs):
        calls.append("inference")
        return SimpleNamespace(logits=SimpleNamespace(shape=(1, 2)))

    adapter._runtime = (
        SimpleNamespace(inference_mode=nullcontext,
                        softmax=lambda *args, **kwargs: Probabilities(score)), tokenize, model,
    )
    return adapter, calls


def test_threshold_is_selected_from_labeled_scores_and_ties_are_explicit():
    record = calibrate_threshold(
        [(0.1, False), (0.2, False), (0.8, True), (0.9, True)],
        model_revision=REVISION, dataset_sha256=DATASET, max_false_positive_rate=0,
    )
    assert record.threshold == 0.8
    assert record.false_positive_rate == 0
    assert record.recall == 1
    assert (record.benign_samples, record.attack_samples) == (2, 2)


def test_calibration_rejects_one_class_or_unattainable_fpr():
    for samples in [[(0.2, False)], [(1.0, False), (0.9, True)]]:
        with pytest.raises(ValueError):
            calibrate_threshold(samples, model_revision=REVISION, dataset_sha256=DATASET,
                                max_false_positive_rate=0)


@pytest.mark.parametrize("score, held", [(0.69, False), (0.7, True), (0.9, True)])
def test_exact_threshold_provenance_and_untruncated_input(score, held):
    adapter, calls = detector(score)
    result = adapter.detect(DetectorInput("entire text", 0, "id"))
    assert bool(result.detections) is held
    assert calls[0] == ("entire text", {"truncation": False, "return_tensors": "pt"})
    assert result.input_tokens == 10
    assert result.provenance.model_revision == REVISION
    assert len(result.provenance.config_sha256) == 64
    assert len(result.provenance.calibration_sha256) == 64


def test_oversized_tokens_fail_before_model_inference():
    adapter, calls = detector(tokens=513)
    with pytest.raises(ValueError, match="refusing partial scanning"):
        adapter.detect(DetectorInput("text", 0, "id"))
    assert "inference" not in calls


def test_scoring_is_available_without_calibration_but_decisions_are_not():
    fake, _ = detector()
    adapter = LocalPromptInjectionDetector(LocalDetectorConfig(REVISION))
    adapter._runtime = fake._runtime
    assert adapter.score("text") == (0.8, 10)
    with pytest.raises(ValueError, match="calibration"):
        adapter.detect(DetectorInput("text", 0, "id"))


def test_loaded_model_configuration_cannot_be_reassigned():
    adapter, _ = detector()
    with pytest.raises(AttributeError):
        adapter.config = LocalDetectorConfig("c" * 40)


@pytest.mark.parametrize("revision", ["main", "v1", "", "z" * 40])
def test_floating_or_invalid_model_revisions_are_rejected(revision):
    with pytest.raises(ValueError, match="commit SHA"):
        LocalDetectorConfig(revision)


def test_loading_is_offline_pinned_and_disallows_remote_code(monkeypatch):
    loads = []

    class Model:
        config = SimpleNamespace(id2label={0: "BENIGN", 1: "MALICIOUS"})

        def to(self, device):
            assert device == "cpu"
            return self

        def eval(self):
            return self

    def load(model_id, **kwargs):
        loads.append((model_id, kwargs))
        return Model()

    modules = {
        "torch": object(),
        "transformers": SimpleNamespace(
            AutoTokenizer=SimpleNamespace(from_pretrained=load),
            AutoModelForSequenceClassification=SimpleNamespace(from_pretrained=load),
        ),
    }
    monkeypatch.setattr("ragguard.local_detector.importlib.import_module", modules.__getitem__)
    adapter = LocalPromptInjectionDetector(LocalDetectorConfig(REVISION, calibration()))
    adapter._load()
    assert len(loads) == 2
    for _, options in loads:
        assert options["revision"] == REVISION
        assert options["local_files_only"] is True
        assert options["trust_remote_code"] is False
    assert loads[1][1]["use_safetensors"] is True


@pytest.mark.parametrize("score", [float("nan"), float("inf"), -0.1, 1.1])
def test_invalid_runtime_scores_fail_closed(score):
    adapter, _ = detector(score)
    with pytest.raises(ValueError, match="invalid classifier score"):
        adapter.detect(DetectorInput("text", 0, "id"))


def test_character_budget_is_checked_before_loading_optional_dependencies(monkeypatch):
    def never_load():
        raise AssertionError("loading should not occur")

    adapter = LocalPromptInjectionDetector(LocalDetectorConfig(
        REVISION, calibration(), max_input_chars=3,
    ))
    monkeypatch.setattr(adapter, "_load", never_load)
    with pytest.raises(ValueError, match="input budget"):
        adapter.detect(DetectorInput("too long", 0, "id"))
