# ragguard — architecture

Start with the [one-pager](ARCHITECTURE_ONE_PAGER.md). The
[harness guide](HARNESS_INTEGRATIONS.md) describes supported integration boundaries
and distinguishes tested library behavior from proposed framework wiring.

## Responsibilities and data flow

`scanner.py` owns `Document`, `Finding`, `ScanReport`, normalization and named rules.
It holds no findings between calls. Body text is prepared once into match surfaces
(below); metadata is traversed as JSON-like fields with JSON Pointer locations and
each leaf is scanned with the injection and metadata families; structural rules
inspect raw content. The composite override/action rule is gated by the
prompt-injection switch and enabled-family selection. `scan_chunks()` additionally
scans the boundary between adjacent chunks of one source. Legacy chunk and
embedding settings are deprecated because this scanner does not chunk or embed.

`pipeline.py` applies one immutable `IngestionPolicy` snapshot to single and batch
scans and returns typed decisions: `evaluate()` → `DocumentDecision`,
`evaluate_batch()` → `BatchDecision`. `ingest()` and `batch_ingest()` are dictionary
wrappers whose output matches the bundled report schema. `load_schema()` reads the
JSON Schemas shipped as package data.

`boundary.py` makes the decision enforceable for harnesses: `ContentBoundary`
defaults to an enforcing guard and withholds both review and reject results.
`require` returns permitted text or raises `ContentBlockedError`; `arequire` uses the
same logic through a worker thread. Validation errors propagate. It never executes
retrieval, tools, model calls or storage writes. The caller must authorize access,
render content and enforce the result at every relevant path.

`worker.py` exposes `ContentBoundary` to non-Python hosts as a persistent JSON Lines
process (see [Worker bridge](#worker-bridge)).

`vector_check.py` is a separate assessment API, never implicitly invoked by
`RAGPipelineGuard`, and the only module that needs numpy (the `vector` extra; the
package imports it lazily). It validates a common finite numeric vector space,
normalizes vectors once, compares bounded pairs and returns heuristic anomalies,
plus an optional re-embedding check. It does not connect to a vector store or
verify entitlements.

## Identity and findings

An explicit source ID is preferred. The fallback fingerprint is the first 12 hex
characters of SHA-256 of the complete text. This is a compact content label, not
an authorization identifier or a guaranteed unique key. Metadata is intentionally
not part of the text fingerprint. `document_index` disambiguates occurrences in
one scan, so equal content with different metadata cannot mix batch decisions.
Duplicate explicit IDs in one pipeline batch raise an error.

`Finding` is a frozen, keyword-only dataclass. Findings carry a family,
potential-impact severity, confidence (`heuristic`, or `verified-by-reembedding`
for the fidelity check), OWASP category, remediation, evidence, document ID and
occurrence index. Metadata findings include a field path. Pair and cross-chunk
findings retain related document IDs and indices. Evidence redacts recognized
credential patterns by default; this is not a universal secret detector. Explicit
raw-evidence mode requires protected handling by callers.

## Match surfaces

Each text is prepared once; every family declares the surface it matches.

| Surface | Preparation | Used by | Evidence prefix |
|---|---|---|---|
| canonical | HTML-entity decode, NFKC, strip zero-width/bidi controls, collapse whitespace, lowercase | most injection and metadata families | — |
| deobfuscated | canonical, plus a curated confusables skeleton (Cyrillic/Greek/Latin-extension look-alikes → ASCII), collapse of letter-spaced runs of four or more letters, leetspeak folding | every canonical-surface family | `[deobfuscated]` |
| raw | original text | `delimiter_injection`, `encoding_obfuscation`, `markdown_exfiltration`, structural families | — |
| decoded | one level of base64 (standard and URL-safe) or hex decoding of long runs in the raw text; output must be at least 80% printable | injection families only, in bodies and metadata | `[base64-decoded]`, `[hex-decoded]` |

Decoding is bounded per text: at most 8 decoded segments, 16 KiB of decoded bytes
and 64 decode attempts. It never raises; malformed runs are skipped. Rules whose
signal is the obfuscation itself (encoded entity runs, markup) stay on the raw
surface so canonicalization cannot erase that signal. Matching HTML ignores case.
Metadata keys/values are inspected without invoking arbitrary object reprs;
unsupported values, cycles and nesting beyond 64 levels are rejected.

`max_matches_per_family` (default 1) caps findings per family per scanned text;
identical evidence is reported once, and the number of matches inspected is
bounded to 16× the cap so de-duplication work stays linear.

### Cross-chunk scanning

`scan_chunks(chunks, window_chars=256)` scans each chunk exactly as
`scan_documents` does, then builds a window from the last `window_chars` of chunk
*i* and the first `window_chars` of chunk *i + 1*. An injection family that matches
the window but neither chunk on its own is reported as `split_payload` on chunk *i*
with the matched family's severity and both chunks in `related_document_ids`.
Payloads spread over non-adjacent chunks, or assembled from different sources at
retrieval time, need a scan of the final assembled context.

## Rule and decision policy

`RAGScanner(enabled_families=...)` selects an explicit set; unknown names fail.
Check switches control body, metadata and structural surfaces independently.
Disabling body injection does not disable injection checks in enabled metadata.
All switches off disables the composite rule too. Each matched rule has its own
finding; counts describe rule hits, not unique successful attacks.

`IngestionPolicy` separates detection from action. For each finding:

1. A `family_actions` entry for its family decides (accept/review/reject).
2. Otherwise, a finding ranked below `review_floor` (default `medium`; order
   info < low < medium < high < critical) is **advisory** and yields accept.
3. Otherwise, a severity in `blocking_severities` (critical/high by default)
   yields reject, and anything else yields review.

The document decision is the strongest action. With `auto_reject=False`
(monitoring), reject becomes review. `families` lists every family that fired;
`advisory_families` lists those whose findings were all advisory, so audits keep
the evidence even though the decision ignored it. `blocking_severities` may not
rank below the floor, so a blocking severity can never silently become advisory.
`review_floor="info"` reproduces the 0.1.x policy, where every finding triggered
review. Assess false positives on the intended corpus before enabling rejection or
adding exceptions.

### Reports and schemas

Reports carry `schema_version` (`REPORT_SCHEMA_VERSION`, currently `1.1`) and
`ruleset_version` (`RULESET_VERSION`, currently `2026.10.1`). Schema 1.1 adds
`advisory_families` to every per-document result. Two Draft 2020-12 schemas ship
in `ragguard/schemas/`: `report` (ingest, batch and exported reports) and
`worker-protocol` (worker frames). `tests/test_schemas.py` validates real outputs
against both, so a shape change without a schema change fails CI.

## Vector integrity tradeoffs

`assess_embedding_consistency` reports pairs with cosine similarity above the
threshold (0.95 by default) and lexical similarity below 0.8 as
`embedding_poisoning_cos_high_text_low` (medium). Lexical similarity is the
maximum of word-set Jaccard and character 3-gram Jaccard over the first 20,000
characters of each text. Legitimate paraphrases and translations can trigger it;
it suggests review, not tampering attribution.

`assess_embedding_fidelity(documents, embed_fn)` is the reliable tampering
signal. It re-embeds each stored text in batches through a caller-supplied
`embed_fn` and reports `embedding_text_mismatch` (high) when the cosine between
the stored and re-embedded vectors is below `min_similarity` (0.9). It is only
meaningful if `embed_fn` uses the same embedding model and version as the stored
vectors; a model change makes every document diverge. Re-embedded vectors are
validated like stored ones.

`assess_cross_user_proximity` compares documents owned by different users, skips
near-identical text, and emits medium `cross_user_embedding_proximity` findings;
neither a finding nor a clean result establishes isolation. The legacy
`check_embedding_consistency` and `check_cross_user_contamination` names remain
for compatibility.

Assessment results include total/assessed document counts, missing-embedding
indices and compared-pair counts. Malformed, nonfinite, zero-norm or
inconsistent-dimensional embeddings raise `ValueError`, including singleton inputs.
Defaults bound documents (2,000), comparisons (2,000,000), dimensions (16,384) and
findings (10,000). Exceeding a budget raises; results are never silently truncated.
Similarities are computed with matrix products over row tiles of `block_size`
(default 256): compute is O(n²d), auxiliary memory O(block_size × n), and no n×n
matrix is allocated. At 2,000 × 768 this is roughly 70× faster than the earlier
per-pair loop. These budgets are safeguards, not a production performance SLA.

## Worker bridge

`python -m ragguard.worker` reads one JSON request per line on stdin and writes
one response per line on stdout. On startup it writes a single handshake:

```json
{"protocol": 1, "type": "ready", "ruleset_version": "2026.10.1", "schema_version": "1.1", "package_version": "0.2.0"}
```

`package_version` is the installed distribution version, or `0+unknown` when run
from an uninstalled source tree. Every response repeats `ruleset_version` and
`schema_version`; clients pin them to the handshake and treat drift as failure.

The bridge maintains these invariants (covered by the Python and TypeScript test
suites):

- Responses contain only decisions, release flags, family names and versions —
  never scanned text, metadata or evidence. Stdout carries protocol frames only.
- Requests are validated completely before scanning: exact fields, protocol
  version, document count, text size and metadata type. Duplicate JSON keys and
  non-finite numbers are rejected. Any error yields `ok: false, release: false`.
- An oversized frame terminates the worker; the client then holds every pending
  check. Timeouts, malformed replies, worker exits and cancellation never fall
  back to the raw content.
- Parallel requests stay correlated by ID; a cancelled call cannot consume
  another call's reply, and a failed process is retired before a replacement
  starts. Unloading the client terminates the owned process.
- Review is withheld by default; releasing review results requires explicit
  monitor mode.

## Evaluation loop

`evals/` holds a synthetic, labelled corpus (160 attacks in 14 categories, 156
benign documents in 12 categories, about 30% of each category in holdout) and
`evals/run.py`, which runs `RAGPipelineGuard(auto_reject=True).ingest` over each
entry and reports detection, block and false-positive rates per split, category
and family, plus latency. CI runs it with `--check evals/thresholds.json` and fails
on any regression.

Rules are tuned against the dev split only; holdout is for reporting. Any change
to a family bumps `RULESET_VERSION` and re-baselines `evals/README.md` and
`evals/thresholds.json`. Current results on all entries: 35.0% attack detection,
5.1% benign false-positive rate. Paraphrase, multilingual and data-exfiltration
categories are at 0%; these are the motivation for an optional model-based
detector tier rather than broader regexes.

## Harness contract and limits

Scan the exact text being released, including any rendered metadata. Scan parents
before chunking, or use `scan_chunks`, and rescan final retrieved assemblies when
concatenation could construct new instructions. Buffer streamed results until
checked. Do not put held text in model-visible errors, history, memory or retry
paths. Tool-output checks cannot undo actions: authorization, approvals and
argument validation precede execution.

The project remains an English-centric heuristic library. It does not establish
semantic intent, sandbox execution, control network egress, inspect images, enforce
ACLs or guarantee absence of injection. Broad rules can still flag benign material.
Store-specific entitlement tests are deployment work.

## Verification

Run `uv sync --frozen`, `uv run --frozen pytest --cov=ragguard`,
`uv run --frozen ruff check .`, `uv run --frozen mypy ragguard` and
`uv run --frozen python evals/run.py --check evals/thresholds.json`. Run both
examples, then `uv build` and smoke-test the installed wheel outside the source
tree. CI does this on Python 3.10/3.11/3.12, checks that the installed wheel
imports and loads both schemas without numpy, and that the vector checker's
`ImportError` names the `vector` extra. Regression coverage includes concurrent
scans, identity collisions, policy parity, review-floor behavior, redaction,
metadata/Unicode/obfuscation variants, cross-chunk payloads, invalid vectors,
budgets, schema conformance and held content not reaching model input.
