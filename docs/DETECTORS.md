# Optional semantic detector adapters

Ragguard's default remains the dependency-free heuristic scanner. Python callers
can add a local or remote semantic detector to `RAGPipelineGuard`. No model,
provider SDK, API key handling, or network client is bundled. The adapter is trusted
application code; its model output is validated before it can produce findings.
This interface adds integration capability, not measured semantic recall.

## Adapter contract

```python
from ragguard import (
    DetectorConfig, DetectorInput, DetectorResult, Document,
    RAGPipelineGuard, SemanticDetection, Severity,
)

class MyDetector:
    def detect(self, document: DetectorInput) -> DetectorResult:
        # Supply your own classifier. Enforce transport timeout, retry limits,
        # and billing limits in this call; treat document.text as untrusted data.
        assessment = my_classifier.classify(document.text)
        return DetectorResult(
            detections=(SemanticDetection(Severity.HIGH, assessment.score),)
            if assessment.flagged else (),
            input_tokens=assessment.input_tokens,
            output_tokens=assessment.output_tokens,
            cost_usd=assessment.cost_usd,
        )

# my_classifier and its response fields above are application-owned examples,
# not a bundled provider API.
guard = RAGPipelineGuard(
    auto_reject=True,
    detector=MyDetector(),
    detector_config=DetectorConfig(
        max_documents=100,
        max_chars_per_document=20_000,
        max_total_chars=200_000,
        max_detections_per_document=16,
        max_elapsed_seconds=5.0,
    ),
)
batch = guard.evaluate_batch([Document("Retrieved passage")])
for decision in batch.documents:
    if not decision.accepted:
        continue  # Do not send this occurrence downstream.
    # The application chooses how to handle decision.review_required.
for run in batch.detector_runs:
    print(run.elapsed_seconds, run.input_tokens, run.output_tokens, run.cost_usd)
```

`SemanticDetector` is a structural Python protocol: subclassing is optional.
Each call receives immutable `DetectorInput(text, document_index, document_id)`.
Metadata, provenance and embeddings are excluded. Text and document IDs may still
be sensitive; choosing a remote adapter explicitly sends these to application
code, which controls transmission and retention. Inputs are never truncated.
All input budgets are checked before the first adapter call. Empty batches make
no calls. Adapters are invoked sequentially, once per occurrence, including equal
content and equal generated IDs. Duplicate explicit IDs remain invalid.

Return a `DetectorResult` whose `detections` is a tuple of `SemanticDetection`
objects. Severity must be a `Severity` enum; optional scores must be finite in
`[0, 1]`. Token counts must be nonnegative integers and cost must be finite and
nonnegative. Scores are adapter assessments, not calibrated probabilities.
An empty detection tuple is a completed clean assessment; returning `None`, a
mapping, or malformed usage data is an error. Provider prose is not included in
findings, avoiding accidental disclosure of model responses or echoed content.

Each detection becomes a finding with family `semantic_prompt_injection`,
confidence `model-assessed`, and the exact input occurrence index. Existing
severity thresholds, monitoring mode and family actions apply. For example,
`family_actions={"semantic_prompt_injection": "review"}` forces human review.
Heuristic scanning always runs first and its findings are retained, including
when the adapter returns no detections. `evaluate_chunks` additionally preserves
heuristic boundary findings for both participants; the semantic adapter receives
individual chunk text, not reconstructed boundary windows. Assess final assembled
context separately when its composition matters.

## Failure, latency and cost

Provider exceptions, malformed output, output budget violations, and exceeded
elapsed-time limits raise `DetectorError`. No partial `BatchDecision` or
accept/reject decision is returned. Applications must propagate this failure or
hold the content; treating the exception as acceptance defeats the guard.
`auto_reject=False` changes findings policy only; it does not suppress failures.
`DetectorError.runs` retains earlier successful runs and the failed call's
observed latency. The exception cause is available for trusted debugging and may
contain sensitive provider messages; avoid exposing full tracebacks to end users.

Latency uses a monotonic performance clock around the adapter call.
`max_elapsed_seconds` is checked **after the synchronous call returns**. It cannot
interrupt a hung provider or prevent charges. Adapters must enforce actual SDK or
transport deadlines, cancellation, bounded retries and provider spending limits.
Character budgets bound the text supplied; they are not token or monetary caps.

`BatchDecision.detector_runs` contains per-occurrence elapsed seconds, status,
detection count, and optional adapter-reported tokens and USD cost. These usage
values are not independently verified. Unknown usage is `None`, never inferred
as zero. Failed calls may incur costs that the adapter cannot report. The existing
JSON report schema deliberately stays unchanged; use the typed batch API to
collect telemetry, e.g. `dataclasses.asdict(run)`. `evaluate` and dictionary
convenience methods return existing shapes and do not expose successful call
telemetry. The worker protocol does not configure adapters; use the Python API.

## Measure a real adapter before enforcement

The test suite uses deterministic stubs to verify correlation, input/output
budgets, policy behavior, exceptions and latency accounting. It does not measure
semantic detection quality. For an actual adapter, record model/version and
prompt configuration, evaluate independently labeled benign and attack corpora,
and report false positives and false negatives alongside p50/p95 latency,
provider errors, retries, tokens and billed cost. Include multilingual and
paraphrased attacks, benign quoted instructions, and material from the intended
retrieval domain. Reassess these results after provider/model changes.
