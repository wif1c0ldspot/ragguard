# Reliability and harness integration plan

This implementation follows the September 2026 architecture review. Work is split
between scanner, pipeline and vector subagents; the parent owns integration, CI,
documentation and combined verification. Existing public dictionary/list APIs are
retained where practical, with deliberate behavioral corrections documented.

## Implementation scope

1. **Scanner correctness:** per-call findings; full-text fingerprints and per-input
   occurrence indices; structured metadata scanning and redacted evidence;
   Unicode/case fixes; detector switches; configurable families and regression tests.
2. **Decision contract:** one policy for single/batch ingestion; explicit
   accept/review/reject decisions; configurable family actions; duplicate-ID
   validation; provenance and versioned report serialization.
3. **Vector assurance:** input validation; bounded pair comparisons; consistent
   IDs and pair evidence; coverage reporting; proximity described as a heuristic,
   without claiming a confirmed authorization violation.
4. **Harness boundary:** a dependency-free adapter that scans material before
   prompt assembly, withholds blocked/review content by default, supports sync and
   async callers, and exposes a typed exception to stop unsafe continuation.
5. **Verification and communication:** real Python CI matrix, frozen dependencies,
   expanded regression suite, build/install checks, executable harness example,
   architecture one-pager and official-source integration guidance.

## Acceptance criteria

- Overlapping scans cannot erase or mix findings.
- Equal text and shared prefixes do not mix per-input decisions.
- Single/batch monitoring and enforcement have equivalent semantics.
- Reviewed metadata, markup and Unicode counterexamples are covered by tests.
- Invalid embeddings fail explicitly; budgets never silently truncate analysis.
- Vector proximity is advisory, with both document identities and coverage counts.
- A rejected or held tool result cannot reach the example's model-input collector.
- Lint, typing, tests, demos and installed-wheel smoke checks pass.

## Follow-on work requiring deployment data

Calibrate family policy against representative benign and attack corpora, reporting
precision/recall, false-positive rate and latency by family. The regression fixtures
in this change are not a held-out detection benchmark. Add embedding-model/version
provenance and actual retrieval entitlement probes when a store and identity model
are selected. Native framework adapters and production load tests should follow
pinned framework versions and real workload requirements. No cloud deployment,
model API call, new framework dependency or universal security guarantee is part
of this change.

## Verification completed

- Three implementation subagents handled scanner, policy and vector changes;
  a second subagent review found and corrected scan/release mutation, malformed
  boolean configuration, content repr exposure and metadata-path redaction issues.
- Combined suite: **155 tests passed**, **99% statement coverage**, on Python 3.12.13.
- Ruff, mypy and diff whitespace checks passed.
- Both demonstrations passed; attack demos now assert key expected results and
  explicitly identify the template-shaped heuristic miss.
- Source distribution and wheel built. The installed wheel was imported outside
  the repository and passed release/block and vector-coverage smoke checks, using
  the already-validated locked NumPy dependency.
- Python 3.10/3.11 runs and native framework execution were not performed locally;
  the corrected CI matrix and documented deployment checks cover that follow-up.

Local filesystem constraints required a temporary virtual environment linked to
the dependency cache, local coverage storage and mypy with caching disabled. The
partial workspace environment was removed. These workarounds affect verification
setup, not the library's runtime contract.
