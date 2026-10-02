# Changelog

All notable changes to ragguard. Format: keep-a-changelog; versions follow the package version in
`pyproject.toml`.

## [Unreleased]

## [0.2.0] — 2026-10-02

Ruleset `2026.10.1`, report schema `1.1`, worker protocol `1`.

### Breaking

- **`Finding` is frozen and keyword-only.** Positional construction and attribute
  mutation now raise; build findings with keywords and derive variants with
  `dataclasses.replace()`.
- **numpy is an optional extra.** The base install has no runtime dependencies.
  `VectorStoreIntegrityChecker` and `VectorAssessment` need `ragguard[vector]`
  (`pip install ".[vector]"` from a checkout); without numpy, importing them raises an
  `ImportError` that names the extra.
- **Default review floor is `medium`.** Low and info findings are advisory: they are
  still reported, listed in the new `advisory_families` field, and yield `accept`
  unless `family_actions` names the family. Pass `review_floor="info"` to restore the
  0.1.x behaviour, where every finding triggered at least review.
- **Severity changes.** `split_marker_open` and `split_marker_close` are now `info`
  (were medium); `structural_dangerous_tag` is now `low` (was medium) and its
  event-handler match is narrowed to real DOM handler names (`onclick`, `onerror`,
  `onload` …) instead of any `on*=` attribute. `embedding_poisoning_cos_high_text_low`
  is now `medium` (was high), because paraphrases and translations trigger it.
- **Report schema 1.1.** Every per-document result (`ingest`, `batch_ingest`,
  `DocumentDecision.to_dict()`) adds `advisory_families`; `schema_version` is `"1.1"`.
- **Worker handshake keys.** The ready message now carries `schema_version` and
  `package_version` alongside `protocol`, `type` and `ruleset_version`. Clients that
  required exactly three keys must be updated; the bundled TypeScript client requires
  exactly these five.
- **Fallback document IDs hash the full text.** Persisted fallback IDs from 0.1.1 must
  be migrated or replaced with explicit source IDs.

### Added

- **Deobfuscation surface.** Canonical-surface families also match a deobfuscated
  copy of the text: Cyrillic/Greek/Latin-extension look-alikes folded to ASCII,
  letter-spaced runs collapsed (`i g n o r e`), leetspeak folded (`1gn0re`). Evidence
  found only there is prefixed `[deobfuscated]`.
- **Encoded payload re-scan.** Base64 and hex runs are decoded one level (bounded to
  8 segments, 16 KiB of decoded bytes and 64 attempts; non-printable output is
  discarded) and re-scanned with the injection families, in document bodies and
  metadata. Evidence is prefixed `[base64-decoded]` or `[hex-decoded]`.
- **`markdown_exfiltration` family** (high, LLM02): markdown images, `<img>` tags and
  query-string links whose URL carries a template placeholder such as
  `{{conversation}}`, `${secret}` or `[DATA]`.
- **`RAGScanner.scan_chunks(chunks, window_chars=256)`** scans ordered chunks and the
  window across each boundary; an injection family that fires only across the
  boundary is reported as `split_payload` with both chunks related.
- **`RAGScanner(max_matches_per_family=1)`** caps findings per family per scanned
  text; identical evidence is reported once.
- **Typed decisions.** `RAGPipelineGuard.evaluate()` and `evaluate_batch()` return
  frozen `DocumentDecision` / `BatchDecision` objects; `ingest()` and `batch_ingest()`
  remain dictionary wrappers over the same policy. `RAGPipelineGuard(review_floor=...)`
  and `IngestionPolicy.review_floor`; `BoundaryResult.advisory_families`.
- **JSON Schemas as package data.** `load_schema("report")` and
  `load_schema("worker-protocol")` (Draft 2020-12); `REPORT_SCHEMA_VERSION` and
  `RULESET_VERSION` are exported.
- **Re-embedding verification.** `VectorStoreIntegrityChecker.assess_embedding_fidelity(
  documents, embed_fn, min_similarity=0.9, batch_size=64)` re-embeds stored text and
  reports `embedding_text_mismatch` (high, LLM08) when the stored vector diverges. It
  requires the same embedding model/version that produced the stored vectors.
- `VectorStoreIntegrityChecker(block_size=256)` controls the similarity tile size.
- **Evaluation corpus and CI gate.** `evals/` contains a synthetic corpus (160 attacks,
  156 benign, dev/holdout splits), `evals/run.py` and `evals/thresholds.json`; CI fails
  on regressions. Baseline: 35.0% attack detection and 5.1% benign false-positive rate
  (ruleset `2026.09.1`: 25.0% / 9.0%).
- **TypeScript worker client** validates the five-key handshake, exposes the announced
  versions as `workerInfo`, and fails closed when a response's ruleset or schema
  version differs from the handshake.
- `ContentBoundary`, typed decision summaries, sync/async release methods, and
  `ContentBlockedError` for framework-neutral harness enforcement. Review content is
  held by default; monitoring release requires an explicit option.
- `python -m ragguard.worker`, a persistent, fail-closed JSON Lines worker, and a
  DeepSeek Harness Cordis bundle pinned to tools `0.1.7-rc.2`, with a bounded
  subprocess client, post-execution result policy, real-registry integration tests and
  installation documentation.
- Regression tests, a harness-boundary demonstration, a corrected Python CI matrix,
  an installed-wheel check that the base install imports without numpy, the
  architecture one-pager and integration recipes.

### Changed

- **Vector similarity is tiled and vectorised**: about 70× faster on 2,000 documents
  of 768 dimensions, with O(block_size × n) auxiliary memory. Budgets, ordering and
  coverage reporting are unchanged.
- Lexical similarity for vector checks is the maximum of word-set Jaccard and
  character 3-gram Jaccard over the first 20,000 characters, so punctuation and
  inflection variants are no longer reported.
- Scanner findings are local to each call, with occurrence indices for reliable batch
  correlation.
- Single and batch ingestion share a configurable policy. Monitoring mode consistently
  returns review instead of rejecting batch entries. Duplicate explicit IDs in a batch
  are rejected. Finding/report metadata is versioned.
- Structured metadata scanning, case-insensitive markup checks, preserved Unicode
  whitespace, redacted credential evidence, and configurable detector families.
- Vector checks validate inputs, enforce resource budgets, retain pair evidence and
  expose assessment coverage. Cross-user proximity is medium/advisory and excludes
  near-duplicate text; it no longer claims proven contamination.
- Unused scanner and vector options issue deprecation warnings when supplied.
- DeepSeek result extraction checks split text blocks and composed context;
  downstream decisions are snapshotted before asynchronous verification. Worker
  deadlines and cancellation include process-retirement waits.

### Fixed

- `structural_dangerous_tag` no longer fires on ordinary attributes that merely start
  with `on` (for example `one=`, `only=`), and split markers no longer send tutorials
  and numbered steps to review under the default policy.

## [0.1.1] — 2026-09-27

### Fixed

- **Detection gap in instruction override.** `instruction_override` required a qualifier between the
  verb and the noun, so canonical payloads such as `Ignore instructions and do bad things.` and
  `Ignore all previous instructions…` produced **zero findings**. The family is now
  qualifier-optional, allows up to six intervening qualifiers, and covers
  `ignore | disregard | forget | override | bypass | skip` against
  instructions / prompts / rules / guidelines / guidance / directives / context / constraints /
  safeguards / policies / commands.
- **`batch_ingest` reported every document as clean.** Documents without an explicit `id` never
  matched findings that the scanner had keyed by content hash. Document identity now goes through
  `resolve_document_id()` in one place, and per-document results include the families that fired.
- **OWASP mappings were wrong.** Prompt injection was mapped to LLM07 "Training Data Poisoning"
  (poisoning is LLM04/LLM03; LLM07 is System Prompt Leakage in the 2025 list) and chunk-splitting to
  LLM06 "Insecure Output Handling" (LLM05 in 2025). Mappings now follow the **OWASP LLM Top 10
  2025**, and rule families that warrant a different category (system-prompt extraction → LLM07,
  credential/exfiltration → LLM02, structural → LLM05, vector checks → LLM08) carry their own.
- **`from ragguard import RAGPipelineGuard` failed.** The package `__init__` was a docstring only,
  so the README quickstart raised `ImportError`. The public API is now exported (and covered by
  tests).
- **False positives from structural rules.** Any HTML tag was reported as a chunk-splitting attack,
  and any mention of `SELECT` was flagged. Tag detection is narrowed to executable markup
  (`script`, `iframe`, `object`, `embed`, `svg`, `form`, `base`, inline `on*` handlers), SQL needs
  a statement shape (`SELECT … FROM`), and both are now covered by false-positive guards.
- **Entity-encoded payloads were not decodable.** Evidence and matching now run over canonicalised
  text (HTML-entity decode + NFKC + zero-width strip + whitespace collapse), so `&#x49;gnore
  previous instructions` and zero-width-split payloads match their plain-text families.
- **Lint and type gates were red.** Unused imports and long lines failed `ruff`, and mypy could not
  parse numpy's stubs; both now pass clean (mypy targets 3.12 for stub parsing, documented in
  `pyproject.toml`).
- **Documentation claimed results that did not exist.** The README listed nine passing tests and
  three test names (`test_pipeline_guard_*`, `test_report_export`) that were never written. Docs are
  regenerated from the real suite, and those tests now exist.
- **Packaging.** `numpy` was imported but undeclared; PyPI-invalid install instructions were
  removed (the `ragguard` name on PyPI belongs to another author); project URLs pointed at a
  non-existent repository; `LICENSE` was referenced by a badge but absent (MIT added).
  Dependencies are now numpy + a dev group, instead of five unused runtime dependencies.

### Added

- `PatternFamily` rule model — every rule carries a name, severity, OWASP category and remediation,
  and every finding reports which family fired.
- `canonicalize()` (public) and `resolve_document_id()` (public).
- `ScanReport.has_blocking_findings`; `RAGPipelineGuard.ingest()` returns `review_required` and a
  richer finding payload.
- 27 new tests (33 total): override variants, canonicalisation, false-positive guards, pipeline
  accept/review/reject, batch correlation with and without ids, vector-store negatives.
- `CHANGELOG.md`, `LICENSE`, `docs/ARCHITECTURE.md` rewrite covering the detection model, OWASP
  mapping table, limitations and extension points.

## [0.1.0] — 2026-05-11

### Added

- Initial scanner: prompt injection, metadata injection, chunk-splitting markers, canonical bypass,
  embedding poisoning and cross-user contamination.
- `RAGScanner`, `RAGPipelineGuard`, `VectorStoreIntegrityChecker`, seven attack demonstrations.
