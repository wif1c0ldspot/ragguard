# Optional semantic detector adapters

Ragguard's default remains the dependency-free heuristic scanner. Python callers
can add a local or remote semantic detector to `RAGPipelineGuard`. No model weights,
provider SDK, API key handling, or network client is bundled. An optional offline
Prompt Guard 2 implementation is available; see below. The adapter is trusted
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
as zero. Failed calls may incur costs that the adapter cannot report. Report schema 1.2 serializes this telemetry in batch `detector_runs`,
including optional `DetectorProvenance` (adapter, model ID/revision, configuration
and calibration SHA-256). Unknown provenance remains null. Single-document
`evaluate` and `ingest` do not retain run telemetry; use `evaluate_batch` when
you need it. The worker protocol does not configure adapters; use the Python API.

## Measure a real adapter before enforcement

The test suite uses deterministic stubs to verify correlation, input/output
budgets, policy behavior, exceptions and latency accounting. It does not measure
semantic detection quality. For an actual adapter, record model/version and
prompt configuration, evaluate independently labeled benign and attack corpora,
and report false positives and false negatives alongside p50/p95 latency,
provider errors, retries, tokens and billed cost. Include multilingual and
paraphrased attacks, benign quoted instructions, and material from the intended
retrieval domain. Reassess these results after provider/model changes.


## Offline model inference and empirical calibration

`LocalPromptInjectionDetector` implements the official
[Prompt Guard 2 22M classifier](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-22M).
The publisher controls weight access and licensing. Provision a reviewed snapshot
in your Hugging Face cache, install compatible `torch`, `transformers` and
`sentencepiece` in that model runtime, and record their exact versions. The
adapter uses CPU inference, safetensors, `trust_remote_code=False` and
`local_files_only=True`; it never downloads code or weights or accepts terms.
The default ragguard installation still needs only the standard library.

```python
from ragguard import (
    LocalDetectorConfig, LocalPromptInjectionDetector, calibrate_threshold,
)

# Use actual immutable revision and dataset digest values from your records.
scorer = LocalPromptInjectionDetector(LocalDetectorConfig(model_revision=revision))
scores = [(scorer.score(text)[0], is_attack) for text, is_attack in calibration_examples]
calibration = calibrate_threshold(
    scores, model_revision=revision, dataset_sha256=calibration_dataset_sha256,
    max_false_positive_rate=0.01,
)
adapter = LocalPromptInjectionDetector(LocalDetectorConfig(
    model_revision=revision, calibration=calibration,
))
```

The example variables are application-supplied, not a bundled dataset or a
pre-calibrated threshold. `score` allows data collection without a threshold;
`detect` refuses to run without a calibration record for the same revision.
Both benign and attack examples are required. Selection maximizes empirical
recall under the observed false-positive ceiling; ties prefer the higher
threshold. A 1% observed ceiling is not a guarantee of 1% production FPR. Evaluate
an independent set, confidence intervals and domain/language shifts afterwards.

Inputs exceeding character or 512-token budgets are refused, never truncated.
Long documents need explicitly designed windowing or another detector; a
prefix-only score must not be represented as full-document coverage. Missing
weights/dependencies, unexpected label mappings, invalid outputs and budget
failures propagate through the fail-closed detector contract.

Contract tests emulate the runtime to check token limits, label validation,
calibration and provenance. They do not measure this model's detection quality.

## Killable deadlines

`ProcessDetector` wraps a trusted top-level factory in a fresh spawned process.
Use a normal main guard so importing the application does not start new workers:

```python
from functools import partial
from ragguard import ProcessDetector, RAGPipelineGuard, LocalPromptInjectionDetector

if __name__ == "__main__":
    detector = ProcessDetector(
        partial(LocalPromptInjectionDetector, config), timeout_seconds=30,
        provenance=LocalPromptInjectionDetector(config).provenance,
    )
    guard = RAGPipelineGuard(auto_reject=True, detector=detector)
```

The deadline includes process startup and model loading. Cleanup terminates,
then kills if necessary, and may add two bounded cleanup grace periods. A fresh
process for each occurrence is deliberately simple but has cold-start overhead.
It is not an OS sandbox and does not contain arbitrary subprocess descendants;
only use trusted factories. Bound concurrent calls in the application. A timeout
withholds the result; it cannot reverse remote requests already sent or charges
already incurred. The original `max_elapsed_seconds` setting remains a post-call
budget check, not an interrupt mechanism.
