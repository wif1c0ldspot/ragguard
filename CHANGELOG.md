# Changelog

All notable changes to ragguard. Format: keep-a-changelog; versions follow the package version in
`pyproject.toml`.

## [Unreleased]

### Changed

- DeepSeek result extraction checks split text blocks and composed context;
  downstream decisions are snapshotted before asynchronous verification. Worker
  deadlines and cancellation now include process-retirement waits.

- Scanner findings are local to each call, with occurrence indices for reliable
  batch correlation. Generated IDs now hash the entire text; persisted fallback
  IDs from 0.1.1 must be migrated or replaced with explicit source IDs.
- Single and batch ingestion share a configurable policy. Monitoring mode now
  consistently returns review instead of rejecting batch entries. Duplicate
  explicit IDs in a batch are rejected. Finding/report metadata is versioned.
- Structured metadata scanning, case-insensitive markup checks, preserved Unicode
  whitespace, redacted credential evidence, and configurable detector families.
- Vector checks validate inputs, enforce resource budgets, retain pair evidence
  and expose assessment coverage. Cross-user proximity is medium/advisory and
  excludes near-duplicate text; it no longer claims proven contamination.
- Unused scanner and vector options issue deprecation warnings when supplied.

### Added

- DeepSeek Harness Cordis bundle pinned to tools `0.1.7-rc.2`, with a persistent
  Python worker, bounded subprocess client, post-execution result policy,
  real-registry integration tests and installation documentation.
- `ContentBoundary`, typed decision summaries, sync/async release methods, and
  `ContentBlockedError` for framework-neutral harness enforcement. Review content
  is held by default; monitoring release requires an explicit option.
- Regression tests, a harness-boundary demonstration, corrected Python CI matrix,
  architecture one-pager, integration recipes and implementation plan.

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
