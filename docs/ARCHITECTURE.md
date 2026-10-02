# ragguard — architecture

Start with the [one-pager](ARCHITECTURE_ONE_PAGER.md). The
[harness guide](HARNESS_INTEGRATIONS.md) describes supported integration boundaries
and distinguishes tested library behavior from proposed framework wiring.

## Responsibilities and data flow

`scanner.py` owns `Document`, `Finding`, `ScanReport`, normalization and named rules.
It holds no findings between calls. Body rules select raw or canonical text;
metadata is traversed as JSON-like fields with JSON Pointer locations; structural
rules inspect raw content. The composite override/action rule is gated by the
prompt-injection switch and enabled-family selection. Legacy chunk and embedding
settings are deprecated because this scanner does not chunk or embed documents.

`pipeline.py` applies one immutable policy snapshot to both single and batch scans.
Severity-based blocking can be overridden per family. Monitoring changes rejection
into review. An accept override retains findings for audit. The caller decides
whether a review flag should pause processing. JSON output includes schema/ruleset
versions and structured finding evidence.

`boundary.py` makes that pause explicit for harnesses: `ContentBoundary` defaults
to an enforcing guard and withholds both review and reject results. `require`
returns permitted text or raises `ContentBlockedError`; `arequire` uses the same
logic through a worker thread. Validation errors propagate. It never executes
retrieval, tools, model calls or storage writes. The caller must authorize access,
render content and enforce the result at every relevant path.

`vector_check.py` is a separate assessment API, never implicitly invoked by
`RAGPipelineGuard`. It validates a common finite numeric vector space, normalizes
vectors once, compares bounded pairs and returns heuristic anomalies. It neither
connects to a vector store nor verifies entitlements or embedding provenance.

## Identity and findings

An explicit source ID is preferred. The fallback fingerprint is the first 12 hex
characters of SHA-256 of the complete text. This is a compact content label, not
an authorization identifier or a guaranteed unique key. Metadata is intentionally
not part of the text fingerprint. `document_index` disambiguates occurrences in
one scan, so equal content with different metadata cannot mix batch decisions.
Duplicate explicit IDs in one pipeline batch raise an error.

Findings carry a family, potential-impact severity, heuristic confidence, OWASP
category, remediation, evidence, document ID and occurrence index. Metadata
findings include a field path. Pair assessments retain related document IDs.
Evidence redacts recognized credential patterns by default; this is not a universal
secret detector. Explicit raw-evidence mode requires protected handling by callers.

## Normalization and rule policy

Canonicalization decodes HTML entities, applies NFKC, strips selected invisible
formatting controls, preserves real whitespace boundaries, collapses whitespace
and lowercases. It is not a general decoder or semantic analysis engine. Rules
whose signal is raw encoding or markup inspect raw text. Matching HTML ignores
case. Metadata keys/values are inspected without invoking arbitrary object reprs;
unsupported values, cycles and excessive nesting are rejected.

`RAGScanner(enabled_families=...)` selects an explicit set; unknown names fail.
Check switches control body, metadata and structural surfaces independently.
Disabling body injection does not disable injection checks in enabled metadata.
All switches off disables the composite rule too. Each matched rule has its own
finding; counts describe rule hits, not unique successful attacks.

`IngestionPolicy` separates detection from action. Default enforcing policy rejects
critical/high findings and marks other findings for review. Default monitoring
policy reports review without rejection. `family_actions` provides narrow
accept/review/reject overrides while preserving evidence. Assess false positives
on the intended corpus before enabling rejection or adding exceptions.

## Vector integrity tradeoffs

`assess_embedding_consistency` reports high cosine similarity with low word-set
Jaccard similarity. This can occur for legitimate paraphrases. It suggests review,
not tampering attribution. `assess_cross_user_proximity` compares different users,
skips near-identical text, and emits medium proximity findings; neither a finding
nor a clean result establishes isolation. The legacy
`check_cross_user_contamination` name remains for compatibility.

Assessment results include total/assessed document counts, missing-embedding
indices and compared-pair counts. Malformed, nonfinite, zero-length/zero-norm or
inconsistent-dimensional embeddings raise `ValueError`, including singleton inputs.
Defaults bound documents (2,000), comparisons (2,000,000), dimensions (16,384) and
findings (10,000). Exceeding a budget raises; results are never silently truncated.
Normalized storage is O(nd), pair compute is O(n²d), and no n×n similarity matrix
is allocated. These budgets are safeguards, not a production performance SLA.

## Harness contract and limits

Scan the exact text being released, including any rendered metadata. Scan parents
before chunking and final retrieved assemblies when concatenation could construct
new instructions. Buffer streamed results until checked. Do not put held text in
model-visible errors, history, memory or retry paths. Tool-output checks cannot
undo actions: authorization, approvals and argument validation precede execution.

The project remains an English-centric heuristic library. It does not establish
semantic intent, sandbox execution, control network egress, inspect images, enforce
ACLs or guarantee absence of injection. Broad rules can still flag benign material.
Real benchmark calibration and store-specific entitlement tests are follow-on work.

## Verification

Run `uv sync --frozen`, `uv run --frozen pytest --cov=ragguard`,
`uv run --frozen ruff check .`, and `uv run --frozen mypy ragguard`.
Run both examples, then `uv build` and smoke-test the installed wheel outside the
source tree. CI binds the interpreter to its Python 3.10/3.11/3.12 matrix and checks
the actual version before executing tests. Regression coverage includes concurrent
scans, identity collisions, policy parity, redaction, metadata/Unicode variants,
invalid vectors, budgets, and held content not reaching model input. These fixtures
are not a representative held-out security benchmark.
