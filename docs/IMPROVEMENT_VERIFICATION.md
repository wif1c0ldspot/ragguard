# Correctness and evaluation improvements

This work separates three claims: completion of configured checks, classifier
accuracy on named datasets, and prevention of downstream attacker goals. They
are not interchangeable. A complete scan can miss an attack; an incomplete scan
must not look clean. A detected document does not prove an agent was protected.

## Architecture follow-up

The 0.4.0a2 follow-up separates shared domain types and normalization from scanning,
preserving public import identities. Scalar metadata text consumes the declared budget;
identical normalized vectors no longer fail exact fidelity checks; cross-owner assessment
computes only eligible pairs. Detector tracebacks suppress provider messages.

Evaluation errors and incomplete scans remain unknown rather than true positives;
quality gates reject them and reject invalid/nonfinite threshold configuration.
Paired outcome schema 2 requires identical generation settings and a shared input digest.
Historical schema 1 artifacts remain unchanged and require their historical comparator.

Release builds now smoke-test the exact final wheel and npm archive before copying
files for publication. The maintained optional ML dependency set resolves in CI;
historical package pins remain explicit provenance, not the recommended installation.

## Correctness contracts

Report schema 1.3 retains `scan_complete` on document, batch and exported reports,
`incomplete_reasons` on documents, versioned `owasp_mappings` on findings, and
`detector_runs` with optional model/configuration provenance on batches and each document, including single-document convenience APIs. Consumers
of strict older schemas must upgrade. Worker protocol framing remains version 1;
its handshake now announces report schema 1.3.

Decoder segment, byte and attempt exhaustion produces a `scan_incomplete`
finding. Metadata traversal has node and character budgets. The normal guard
rejects incomplete inputs in enforcement mode and returns review in monitoring
mode; family overrides cannot silently accept them. `ContentBoundary` withholds
incomplete scans even with `allow_review=True`. Resource exceptions propagate.
Completeness means configured work finished, not every possible threat was tested.

The scanner regression suite covers resource failures, exhausted budgets, Unicode
format characters, malformed markup, and overlapping independent/cross-chunk
matches. Boundary tests check that release decisions survive serialization and
worker monitoring mode without turning partial work into accepted content.

## Accuracy and benchmarking

The bundled synthetic corpus remains a regression corpus, including its known
misses. External evaluation commands, source hashes and results live in
[`evals/`](../evals/README.md). NotInject measures benign trigger-word handling.
InjecAgent base/enhanced variants are separate classifier evaluations. Its
obvious enhanced prefix can make aggregate recall misleading.

Reports include confusion counts and confidence intervals. These intervals do
not establish independence of correlated prompts or generalization to production.
Threshold selection must use calibration/dev data and keep final evaluation
sources and attack families separate. Never relabel a holdout as independent
once it has informed detector changes.

The optional local Prompt Guard 2 adapter is implementation-complete but model
quality is not established by contract tests. It requires locally provisioned,
licensed weights at a fixed commit and explicit measured threshold calibration.
It refuses text exceeding the token budget rather than classifying a prefix.
No weights, provider credentials, or paid model calls are bundled.

## Integration controls

`Boundary` names now include memory reads/writes, tool descriptions and final
context. They identify where the caller is enforcing the same checks; merely
choosing a boundary name does not add authorization or persistent storage.
Boundary results bind the exact checked text with SHA-256. A digest is neither a
signature nor proof that the source is trustworthy.

Executable examples demonstrate distinct responsibilities:

- `examples/retrieval_pipeline.py`: trusted collection authorization before
  retrieval; all model-visible titles/chunks rendered and scanned together.
- `examples/guarded_memory.py`: owner/source restrictions, bounded entries,
  expiry, content binding, and current checks on read as well as write.
- `examples/agent_controls.py`: a fixed action, exact destination authorization,
  tool-description change detection, argument validation and concurrent call
  budgets. No external side effects run in the demonstration.

Production applications still own authenticated principals, trusted policy
storage, tool execution isolation, network controls, retries and logging.

## Remaining experiments

No production false-positive rate, multilingual robustness, adaptive attack
success rate, or general agent-utility guarantee is claimed. The follow-up
measurements below are bounded research results. Run licensed pinned
model inference, calibrate on domain-matched examples, and then measure an
independent evaluation split. Evaluate actual attacker-goal success and normal
task completion together in a model-backed harness before enabling new semantic
rules by default.

Retrieval poisoning can manipulate factual answers without overt instructions.
Compare clean and poisoned retrieval/generation runs, recording retrieved-source
exposure, answer correctness, citation support and attacker-goal completion.
Multimodal coverage requires evaluating parsing/OCR and model behavior together;
this text library does not inspect image pixels, audio, or hidden document layers.

## Taxonomy and research references

Existing `owasp_mapping` strings remain the 2025 labels; additive mappings record
both editions without rewriting historical identifiers. They express related
risks, not a certification or a claim that ragguard covers an entire category.

- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/):
  prompt injection, poisoning, consumption, hidden context and retrieval risks.
- [OWASP Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/):
  goal hijacking, tool misuse, privilege abuse and memory poisoning require
  application controls beyond text classification.
- [Confundo, USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/hu-haoyang):
  practical preprocessing and variable queries matter in RAG poisoning evaluation.
- [Adaptive attacks, NAACL Findings 2025](https://arxiv.org/abs/2503.00061):
  evaluate attacks adapted to the deployed defense rather than relying on static
  corpus scores alone.


## Verification record (2026-10-03)

- 690 Python tests passed on Python 3.10, 3.11 and 3.12; the 3.12 coverage run
  reports 94% statement coverage, including 99% scanner and 100% policy coverage.
  Subprocess execution is verified by behavior tests; coverage is not a security
  guarantee. The 3.10 NumPy performance test emitted numerical runtime warnings
  while passing; no vector-check implementation changed in this work.
- Wheel and source distribution built successfully; installed-wheel checks passed
  outside the source tree with no NumPy, Torch, or Transformers dependencies.
- 60 TypeScript integration tests and TypeScript type checking passed. Ruff,
  mypy, schema validation and both existing synthetic evaluation gates passed.
- The original decoder resource failure now propagates; saturation now emits
  incomplete coverage and withholds content; both crossing chunks are rejected
  despite an unrelated same-family match in one chunk.
- Repeated malformed tags at 128 KB improved from about 1.144 s to 0.022 s on
  the review machine. A partial detector response now obeys a 0.2 s deadline
  (observed about 0.206 s, including cleanup) instead of waiting about 1.096 s.
  These measurements are local observations, not deployment latency guarantees.
- Pinned external results: NotInject 0/339 flagged; InjecAgent base 68/1,054
  detected; enhanced 1,054/1,054 detected because of its recognizable wrapper.
  Default external recall did not improve from the scanner correctness changes.
- Dev-selected severity policy flags 53/357 base holdout attacks versus 34/357
  under the default policy. The extra 19 are existing SQL advisory findings
  promoted to review; blocks remain 34. Benign holdout 0/93 is source-confounded
  and drawn from one trigger group, not a production false-positive estimate.
- The exposed transformation corpus detects 9/24 attack cases and flags 4/24
  benign cases. It is a gap-finding regression exercise, not an adaptive attack
  success claim. At this initial stage, model-backed protection and task utility
  were unmeasured; the follow-up experiments below record the subsequent runs.


## Follow-up: actual local classifier measurements

The full external corpus was scored offline with the pinned Apache-2.0 ProtectAI
DeBERTa v2 checkpoint: 2,447 inputs, zero model errors, zero incomplete rule scans.
Development thresholds were fixed before holdout inference at a 5% empirical
false-positive ceiling. On the base holdout, the model detected 0/357 and rules
or combined policy detected 34/357. On enhanced holdout, the model detected
88/357 and rules or combined policy detected 357/357. All policies flagged 0/93
benign holdout examples. This checkpoint added no measured recall at that ceiling;
semantic detection remains disabled by default.

These are source-confounded public datasets with unknown model-training overlap,
not deployment performance. The earlier verification record describes the state
before this actual-model follow-up. See [model reproduction](MODEL_EVALUATION.md)
and [full raw score report](../evals/reports/semantic-protectai.json) for exact
weights, calibration, runtime versions, token counts, latencies and denominators.


## Follow-up: paired local generation probe

Six predetermined synthetic development scenarios were run with a pinned
Qwen2.5-0.5B-Instruct generator, once with clean and attacked references under
baseline and protected conditions. There were 22 actual generated responses, two
protected-context blocks and zero execution errors. No tools, retrieval ranking
or external side effects were involved.

Under the frozen whole-answer judge, exact attacker-target matches were 1/6 in
both arms; clean answer matches were 5/6 in both. Attacked legitimate-answer
matches fell from 4/6 to 2/6 because the boundary blocked two direct attacks that
the baseline model had already resisted. Both factual-poisoning cases were
accepted and conveyed in both arms. The exact judge counts only one as a target
match because the other output includes units; target-match rate is not a harmful
answer rate. No prevention or generalization gain is claimed.

See [the design, raw outputs and reproduction](RAG_GENERATION_PROBE.md). The
judge and cases were not changed after seeing results. Further evaluation needs
representative tasks, validated outcome judgments and adaptive attacks before
any deployment-security claim.


## Release verification

The follow-up tree passed 715 tests on each of Python 3.10, 3.11 and 3.12,
60 TypeScript tests, TypeScript checking, Ruff, mypy and both frozen synthetic
regression gates. The final isolated Python 3.12 coverage run passed at 94%.
An earlier concurrent coverage run exhausted a test worker startup allowance;
the isolated rerun passed without changing production deadlines or test assertions.
Model binaries and download caches are ignored and excluded from release source.
