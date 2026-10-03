"""Real spawn/termination tests with synthetic adapters, not model quality tests."""

import multiprocessing
import signal
import time
from functools import partial
from pathlib import Path

import pytest

from ragguard.detectors import DetectorError, DetectorInput, DetectorResult, SemanticDetection
from ragguard.process_detector import ProcessDetector


class Clean:
    def detect(self, document):
        return DetectorResult((SemanticDetection(score=0.9),), input_tokens=3)


class Broken:
    def detect(self, document):
        raise RuntimeError("private input and provider credential")


class Hanging:
    def __init__(self, marker):
        self.marker = marker

    def detect(self, document):
        # Exercise terminate -> kill escalation on POSIX. Windows termination
        # forcibly ends the process regardless of this Python signal handler.
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        Path(self.marker).write_text("started")
        while True:
            time.sleep(1)


def test_spawn_round_trips_typed_result():
    result = ProcessDetector(Clean, timeout_seconds=15).detect(DetectorInput("text", 0, "id"))
    assert result.input_tokens == 3
    assert result.detections[0].score == 0.9


def test_process_error_does_not_echo_payload_and_leaves_no_child():
    before = {child.pid for child in multiprocessing.active_children()}
    with pytest.raises(DetectorError, match="process failed") as error:
        ProcessDetector(Broken, timeout_seconds=15).detect(DetectorInput("private", 0, "id"))
    assert "credential" not in str(error.value)
    assert {child.pid for child in multiprocessing.active_children()} == before


def test_hanging_detector_is_terminated_and_reaped(tmp_path):
    marker = tmp_path / "started"
    before = {child.pid for child in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(DetectorError, match="deadline exceeded"):
        ProcessDetector(partial(Hanging, str(marker)), timeout_seconds=5).detect(
            DetectorInput("private", 0, "id"),
        )
    assert marker.exists(), "test must exercise a running detector, not only spawn timeout"
    assert time.monotonic() - started < 9
    assert {child.pid for child in multiprocessing.active_children()} == before


@pytest.mark.parametrize("options", [{"timeout_seconds": 0}, {"cleanup_seconds": True},
                                    {"max_response_bytes": 1}])
def test_invalid_process_budgets(options):
    with pytest.raises(ValueError):
        ProcessDetector(Clean, **options)


class Alternate(Clean):
    pass


def partial_output_worker(result_path, factory, document, max_response_bytes):
    # Simulate a worker that writes only part of its result then stalls forever.
    Path(result_path).write_bytes(b'{')
    Path(document.text).write_text("partial output written")
    while True:
        time.sleep(1)


def test_partial_output_cannot_bypass_deadline(monkeypatch, tmp_path):
    before = {child.pid for child in multiprocessing.active_children()}
    monkeypatch.setattr("ragguard.process_detector._execute", partial_output_worker)
    marker = tmp_path / "partial-output"
    started = time.monotonic()
    with pytest.raises(DetectorError, match="deadline exceeded"):
        ProcessDetector(Clean, timeout_seconds=3, cleanup_seconds=0.2).detect(
            DetectorInput(str(marker), 0, "id"),
        )
    assert marker.exists()
    assert time.monotonic() - started < 5
    assert {child.pid for child in multiprocessing.active_children()} == before


def test_boundary_fingerprint_binds_process_factory_and_limits():
    from ragguard import ContentBoundary, RAGPipelineGuard

    def fingerprint(factory, timeout):
        boundary = ContentBoundary(RAGPipelineGuard(
            detector=ProcessDetector(factory, timeout_seconds=timeout),
        ))
        return boundary._policy_sha256()

    assert len({fingerprint(Clean, 1), fingerprint(Clean, 30), fingerprint(Alternate, 1)}) == 3


class ProvenanceDetector:
    def detect(self, document):
        from ragguard.detectors import DetectorProvenance

        return DetectorResult(provenance=DetectorProvenance(
            "test", "model", "a" * 40, "b" * 64, "c" * 64,
        ))


def test_process_provenance_must_match_declared_identity():
    from ragguard.detectors import DetectorProvenance

    with pytest.raises(DetectorError, match="provenance mismatch"):
        ProcessDetector(ProvenanceDetector, timeout_seconds=15).detect(
            DetectorInput("text", 0, "id"),
        )
    expected = DetectorProvenance("test", "model", "a" * 40, "b" * 64, "c" * 64)
    result = ProcessDetector(ProvenanceDetector, timeout_seconds=15, provenance=expected).detect(
        DetectorInput("text", 0, "id"),
    )
    assert result.provenance == expected


class Configured(Clean):
    def __init__(self, config):
        self.config = config


def test_partial_factory_configuration_changes_are_reflected_in_binding():
    from ragguard import ContentBoundary, RAGPipelineGuard

    config = {"threshold": 0.5}
    adapter = ProcessDetector(partial(Configured, config))
    boundary = ContentBoundary(RAGPipelineGuard(detector=adapter))
    before = boundary._policy_sha256()
    config["threshold"] = 0.9
    assert boundary._policy_sha256() != before
    with pytest.raises(AttributeError):
        adapter.factory = Alternate
