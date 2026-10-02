"""Persistent, fail-closed JSON Lines bridge for agent harness plugins.

Run ``python -m ragguard.worker``. Stdout contains protocol messages only;
responses never include scanned text, metadata, or finding evidence.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from typing import Any, BinaryIO, NoReturn, TextIO

from ragguard.boundary import Boundary, ContentBoundary
from ragguard.pipeline import REPORT_SCHEMA_VERSION, RAGPipelineGuard
from ragguard.scanner import RULESET_VERSION, Document, RAGScanner

PROTOCOL_VERSION = 1


def _invalid_constant(value: str) -> Any:
    raise ValueError("non-finite JSON constant")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _request_id(request: Any) -> str | None:
    if isinstance(request, dict):
        value = request.get("id")
        if isinstance(value, str) and value.strip() and len(value) <= 128:
            return value
    return None


def _error(request_id: str | None) -> dict[str, Any]:
    return {
        "protocol": PROTOCOL_VERSION, "id": request_id, "ok": False,
        "release": False, "error": "request_failed",
    }


def process_request(
    request: Any, boundary: ContentBoundary, *, max_documents: int = 64,
) -> dict[str, Any]:
    """Validate a complete request before scanning; all errors withhold content."""
    request_id = _request_id(request)
    try:
        if not isinstance(request, dict) or set(request) != {"protocol", "id", "documents"}:
            raise ValueError("invalid request fields")
        if type(request["protocol"]) is not int or request["protocol"] != PROTOCOL_VERSION:
            raise ValueError("invalid protocol")
        if request_id is None:
            raise ValueError("invalid request id")
        documents = request["documents"]
        if not isinstance(documents, list) or not 1 <= len(documents) <= max_documents:
            raise ValueError("invalid documents")
        for document in documents:
            if not isinstance(document, dict) or not {"text"} <= set(document) <= {
                "text", "metadata",
            }:
                raise ValueError("invalid document fields")
            if not isinstance(document["text"], str):
                raise ValueError("invalid text")
            if len(document["text"]) > boundary.max_text_chars:
                raise ValueError("text exceeds limit")
            if "metadata" in document and not isinstance(document["metadata"], dict):
                raise ValueError("invalid metadata")
        results = [
            boundary.check(
                Document(text=document["text"], metadata=document.get("metadata")),
                boundary=Boundary.TOOL_OUTPUT,
            )
            for document in documents
        ]
        decisions = {result.decision for result in results}
        decision = "reject" if "reject" in decisions else (
            "review" if "review" in decisions else "accept"
        )
        return {
            "protocol": PROTOCOL_VERSION, "id": request_id, "ok": True,
            "release": all(result.released for result in results), "decision": decision,
            "families": sorted({family for result in results for family in result.families}),
            "ruleset_version": RULESET_VERSION, "schema_version": REPORT_SCHEMA_VERSION,
        }
    except Exception:
        return _error(request_id)


def serve(
    source: BinaryIO, sink: TextIO, boundary: ContentBoundary, *,
    max_documents: int = 64, max_frame_bytes: int = 1_048_576,
) -> int:
    """Process bounded frames. An oversized frame terminates the worker."""
    def emit(message: dict[str, Any]) -> None:
        sink.write(json.dumps(message, ensure_ascii=True, allow_nan=False) + "\n")
        sink.flush()

    emit({"protocol": PROTOCOL_VERSION, "type": "ready", "ruleset_version": RULESET_VERSION})
    while True:
        frame = source.readline(max_frame_bytes + 1)
        if not frame:
            return 0
        if len(frame) > max_frame_bytes:
            emit(_error(None))
            return 1
        try:
            request = json.loads(
                frame.decode("utf-8", errors="strict"),
                parse_constant=_invalid_constant, object_pairs_hook=_unique_object,
                parse_float=_finite_float,
            )
        except (ValueError, RecursionError):
            emit(_error(None))
            continue
        emit(process_request(request, boundary, max_documents=max_documents))


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's normal error includes attacker-controlled argument values.
        self.exit(2, "ragguard worker: invalid configuration\n")


def _positive_integer(value: str) -> int:
    result = int(value)
    if result < 1:
        raise ValueError("must be positive")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--mode", choices=("enforce", "monitor"), default="enforce")
    parser.add_argument("--max-text-chars", type=_positive_integer, default=200_000)
    parser.add_argument("--max-documents", type=_positive_integer, default=64)
    parser.add_argument("--max-frame-bytes", type=_positive_integer, default=1_048_576)
    parser.add_argument("--enabled-family", action="append")
    args = parser.parse_args(argv)
    try:
        scanner = RAGScanner(enabled_families=args.enabled_family)
        boundary = ContentBoundary(
            RAGPipelineGuard(scanner=scanner, auto_reject=args.mode == "enforce"),
            allow_review=args.mode == "monitor", max_text_chars=args.max_text_chars,
        )
        return serve(
            sys.stdin.buffer, sys.stdout, boundary,
            max_documents=args.max_documents, max_frame_bytes=args.max_frame_bytes,
        )
    except Exception:
        sys.stderr.write("ragguard worker: worker failed\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
