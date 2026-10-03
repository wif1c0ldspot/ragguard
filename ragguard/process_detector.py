"""Killable synchronous detector calls using portable multiprocessing spawn.

Adapters/factories must be trusted, picklable top-level objects. This isolates a
stalled call; it is not a sandbox and does not contain subprocesses an adapter
starts itself. Use OS/container controls for untrusted executable code. Spawn
requires the application's normal ``if __name__ == '__main__'`` entry-point guard.
"""

from __future__ import annotations

import functools
import json
import multiprocessing
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from ragguard.detectors import (
    DetectorConfig,
    DetectorError,
    DetectorInput,
    DetectorProvenance,
    DetectorResult,
    SemanticDetection,
    SemanticDetector,
    _number,
    _validate_result,
)
from ragguard.scanner import Severity


def _execute(
    result_path: str, factory: Callable[[], SemanticDetector], document: DetectorInput,
    max_response_bytes: int,
) -> None:
    try:
        result = factory().detect(document)
        _validate_result(result, DetectorConfig())
        payload = json.dumps(asdict(result), allow_nan=False).encode("utf-8")
        if len(payload) > max_response_bytes:
            raise ValueError("output budget exceeded")
    except BaseException:
        # No provider errors, tracebacks or document text cross this channel.
        payload = b'{"error":"detector_failed"}'
    Path(result_path).write_bytes(payload)


def _configuration_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _configuration_value(asdict(value))
    if isinstance(value, tuple):
        return [_configuration_value(item) for item in value]
    if isinstance(value, list):
        return [_configuration_value(item) for item in value]
    if isinstance(value, dict) and all(type(key) is str for key in value):
        return {key: _configuration_value(item) for key, item in value.items()}
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise ValueError("factory configuration requires an explicit factory_id")


def _factory_configuration(factory: Callable[[], SemanticDetector]) -> dict[str, Any]:
    if isinstance(factory, functools.partial):
        return {"factory": _factory_configuration(factory.func),
                "args": _configuration_value(factory.args),
                "kwargs": _configuration_value(factory.keywords)}
    module = getattr(factory, "__module__", None)
    name = getattr(factory, "__qualname__", None)
    if not isinstance(module, str) or not isinstance(name, str) or "<locals>" in name:
        raise ValueError("factory requires an explicit factory_id")
    return {"callable": f"{module}.{name}"}


class ProcessDetector:
    """One fresh process per call; deadline includes model loading and inference.

    Results use a private temporary file, read only after process exit. Waiting for
    complete process exit avoids blocking indefinitely on a partial pipe frame.
    Cleanup may add up to two grace periods after the request deadline. Caller
    must bound concurrency separately. This is not a sandbox or a code signature.

    The factory identity and serializable partial arguments are bound to boundary
    fingerprints. Supply a reviewed factory_id for opaque callable configuration.
    A model returning provenance must have matching provenance declared here.
    """

    def __init__(
        self, factory: Callable[[], SemanticDetector], *, timeout_seconds: float = 30,
        cleanup_seconds: float = 1, max_response_bytes: int = 65_536,
        factory_id: str | None = None, provenance: DetectorProvenance | None = None,
    ) -> None:
        if not callable(factory):
            raise ValueError("detector factory must be callable")
        _number("timeout_seconds", timeout_seconds, positive=True)
        _number("cleanup_seconds", cleanup_seconds, positive=True)
        if type(max_response_bytes) is not int or not 1024 <= max_response_bytes <= 1_000_000:
            raise ValueError("max_response_bytes must be within [1024, 1000000]")
        if factory_id is not None and (
            type(factory_id) is not str or not factory_id.strip() or len(factory_id) > 256
        ):
            raise ValueError("factory_id must be a nonempty bounded identity")
        identity = ({"declared_id": factory_id} if factory_id is not None
                    else _factory_configuration(factory))
        json.dumps(identity, sort_keys=True, allow_nan=False)
        self._factory_id = factory_id
        _validate_result(DetectorResult(provenance=provenance), DetectorConfig())
        self._factory = factory
        self.timeout_seconds = timeout_seconds
        self.cleanup_seconds = cleanup_seconds
        self.max_response_bytes = max_response_bytes
        self.provenance = provenance

    @property
    def factory(self) -> Callable[[], SemanticDetector]:
        return self._factory

    @property
    def configuration(self) -> dict[str, Any]:
        identity = ({"declared_id": self._factory_id} if self._factory_id is not None
                    else _factory_configuration(self.factory))
        return {"factory": identity,
                "timeout_seconds": self.timeout_seconds, "cleanup_seconds": self.cleanup_seconds,
                "max_response_bytes": self.max_response_bytes,
                "provenance": asdict(self.provenance) if self.provenance is not None else None}

    def detect(self, document: DetectorInput) -> DetectorResult:
        context = multiprocessing.get_context("spawn")
        with tempfile.TemporaryDirectory(prefix="ragguard-detector-") as directory:
            result_path = str(Path(directory) / "result.json")
            process = context.Process(target=_execute, args=(
                result_path, self.factory, document, self.max_response_bytes,
            ), daemon=True)
            started = time.monotonic()
            launched = False
            try:
                process.start()
                launched = True
                remaining = self.timeout_seconds - (time.monotonic() - started)
                if remaining <= 0:
                    raise DetectorError("Semantic detector process deadline exceeded")
                process.join(remaining)
                if process.is_alive():
                    raise DetectorError("Semantic detector process deadline exceeded")
                if process.exitcode != 0:
                    raise DetectorError("Semantic detector process failed")
                with open(result_path, "rb") as response:
                    raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise DetectorError("Semantic detector process output budget exceeded")
                payload = json.loads(raw)
                if not isinstance(payload, dict) or "error" in payload:
                    raise DetectorError("Semantic detector process failed")
                provenance = payload.get("provenance")
                result = DetectorResult(
                    detections=tuple(SemanticDetection(Severity(item["severity"]), item["score"])
                                     for item in payload["detections"]),
                    input_tokens=payload["input_tokens"], output_tokens=payload["output_tokens"],
                    cost_usd=payload["cost_usd"],
                    provenance=DetectorProvenance(**provenance) if provenance is not None else None,
                )
                _validate_result(result, DetectorConfig())
                if result.provenance != self.provenance:
                    raise DetectorError("Semantic detector process provenance mismatch")
                if time.monotonic() - started > self.timeout_seconds:
                    raise DetectorError("Semantic detector process deadline exceeded")
                return result
            except DetectorError:
                raise
            except Exception:
                raise DetectorError("Semantic detector process failed") from None
            finally:
                if launched:
                    if process.is_alive():
                        process.terminate()
                    process.join(self.cleanup_seconds)
                    if process.is_alive():
                        process.kill()
                        process.join(self.cleanup_seconds)
                    if process.is_alive():
                        raise DetectorError("Semantic detector process cleanup failed")
                    process.close()
