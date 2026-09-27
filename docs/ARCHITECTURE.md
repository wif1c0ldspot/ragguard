# ragguard — Architecture

## Scope

ragguard covers the parts of a RAG pipeline that generic LLM-security tooling misses: what enters
the corpus, and how the vector store behaves once documents are in it. It is a **scanner**, not a
firewall — it produces findings, severities, remediation text and a pass/review/reject decision for
a caller to act on.

Three modules do the work:

| Module | Class / API | Responsibility |
|--------|-------------|----------------|
| `ragguard/scanner.py` | `RAGScanner`, `canonicalize()`, `resolve_document_id()` | Document-body, metadata and structural scanning; finding model |
| `ragguard/vector_check.py` | `VectorStoreIntegrityChecker` | Embedding-space attacks: poisoning, cross-user contamination |
| `ragguard/pipeline.py` | `RAGPipelineGuard` | Ingestion-time middleware: accept / review / reject, batch decisions, JSON export |

## Pipeline position

```
                    ┌─────────────────────────────────────────────┐
                    │           RAG Pipeline (caller)             │
                    │   Document Ingestion → Vector Store → Query │
                    └──────┬──────────────┬──────────────┬────────┘
                           │              │              │
                    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
                    │  Ingestion  │ │  Vector   │ │ Reporting │
                    │   Scanner   │ │ Integrity │ │  / Gate   │
                    └──────┬──────┘ └─────┬─────┘ └─────┬─────┘
                           │              │              │
                    ┌──────▼──────────────▼──────────────▼──────┐
                    │            RAGPipelineGuard                │
                    │  (ingestion middleware / CI gate)          │
                    └──────┬──────────────┬──────────────┬──────┘
                           │              │              │
                    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
                    │ Injection   │ │ Metadata  │ │Structural │
                    │   (7)       │ │   (5)     │ │   (4)     │
                    └──────┬──────┘ └─────┬─────┘ └─────┬──────┘
                           │              │              │
                    ┌──────▼──────────────▼──────────────▼──────┐
                    │  ScanReport — findings, severity summary   │
                    │  OWASP LLM Top 10 mapping, remediation      │
                    └───────────────────────────────────────────┘
```

`VectorStoreIntegrityChecker` runs *after* ingestion, against documents that carry embeddings.

## Detection model

### 1. Canonicalisation

Every text-based rule matches against `canonicalize(text)`:

```
raw text
  → html.unescape()                 &#x49;gnore      ⇒ "Ignore"
  → unicodedata.normalize("NFKC")   full-width/ligatures ⇒ ASCII equivalents
  → strip zero-width + bidi         "ig\u200bnore"   ⇒ "ignore"
  → collapse whitespace             "IGNORE   PREV"  ⇒ "ignore prev"
  → lowercase
```

This is why an entity-encoded or zero-width-split payload is caught by the same family that catches
its plain-text form. Rules whose *signal is the obfuscation itself* (encoded payload runs, dangerous
markup) opt out with `surface="raw"` and match the original text.

### 2. Pattern families

A rule is a `PatternFamily` dataclass — name, compiled pattern, severity, OWASP category,
remediation text, surface. Detection is a linear scan over the families; **one finding per family
that fires**, each carrying its own severity and mapping rather than a fixed one per finding type.

| Surface | Group | Families | Severities |
|---------|-------|----------|-----------|
| canonical | `INJECTION_FAMILIES` | `instruction_override`, `persona_override`, `system_prompt_extraction`, `jailbreak_mode`, `data_exfiltration` | critical / high |
| raw | `INJECTION_FAMILIES` | `delimiter_injection`, `encoding_obfuscation` | high / medium |
| raw | `METADATA_FAMILIES` | `metadata_key_value_payload`, `metadata_tool_call`, `metadata_code_execution`, `metadata_exfiltration_command`, `metadata_credential_leak` | critical / high |
| raw | `SPLIT_FAMILIES` | `split_marker_open`, `split_marker_close`, `structural_dangerous_tag`, `structural_sql_keyword` | medium / low |

`instruction_override` is deliberately qualifier-optional and allows up to six intervening
qualifiers, so it matches `Ignore instructions…`, `Ignore all previous instructions…`,
`Disregard the above rules…` and `Skip any earlier guidance…` alike. Requiring a qualifier was the
cause of a real detection gap (see CHANGELOG 0.1.1).

### 3. Composite canonical check

`_scan_canonical_injection` fires `canonical_injection` (critical) when an instruction override and
an enumerated action (`instruction:`) appear in the same canonicalised document — the shape of a
payload that only assembles after normalisation. It is layered on top of the per-family findings
rather than replacing them.

### 4. Finding contract

```python
Finding(
    finding_type,      # FindingType enum
    severity,          # Severity enum: critical | high | medium | low | info
    document_id,       # explicit id, else sha256(text[:100])[:12]
    description,
    evidence,          # matched phrase, restored to original casing where locatable
    remediation,
    owasp_mapping,     # e.g. "LLM01: Prompt Injection"
    family,            # which rule fired — the audit handle
)
```

`ScanReport` exposes `is_clean`, `has_blocking_findings` (any critical/high) and `summary()`.

`resolve_document_id(doc)` is the single source of truth for document identity. Re-deriving ids by
hand (e.g. `doc.text[:50]`) silently fails to match findings — that bug made `batch_ingest` report
every document as clean in 0.1.0.

## Vector-store checker

`VectorStoreIntegrityChecker(similarity_threshold=0.95)`:

- **`check_embedding_consistency(documents)`** — normalises stored embeddings, computes the cosine
  matrix, and flags pairs above `similarity_threshold` whose *text* similarity (Jaccard over word
  sets) falls below `TEXT_SIMILARITY_CEILING` (0.8). High cosine + low text similarity is the cheap
  signature of an adversarially injected embedding sitting next to legitimate content; legitimate
  duplicates have near-identical text and are not flagged.
- **`check_cross_user_contamination(user_documents)`** — compares embeddings across per-user
  clusters; proximity above the threshold produces a critical `cross_user_contamination` finding
  naming both users. The real fix is partitioning the index per tenant, which is what the
  remediation text says.

Both are O(n²) over the supplied set by design: they run on a sampled or per-tenant slice, not over
a whole production index.

## OWASP mapping (LLM Top 10, 2025)

| Finding | Primary | Secondary |
|---------|---------|-----------|
| Prompt injection in body (`instruction_override`, `persona_override`, `jailbreak_mode`, `delimiter_injection`, `encoding_obfuscation`) | LLM01 Prompt Injection | LLM07 System Prompt Leakage where extraction is attempted |
| `system_prompt_extraction` | LLM07 System Prompt Leakage | LLM01 |
| `data_exfiltration`, `metadata_credential_leak`, `metadata_exfiltration_command` | LLM02 Sensitive Information Disclosure | LLM01 |
| Metadata injection (`metadata_tool_call`, `metadata_code_execution`, `metadata_key_value_payload`) | LLM01 Prompt Injection | LLM06 Excessive Agency (tool-call hijack) |
| Chunk-splitting markers | LLM01 Prompt Injection | LLM05 Improper Output Handling |
| Structural risks (`structural_dangerous_tag`, `structural_sql_keyword`) | LLM05 Improper Output Handling | — |
| Embedding poisoning | LLM08 Vector and Embedding Weaknesses | LLM04 Data and Model Poisoning |
| Cross-user contamination | LLM08 Vector and Embedding Weaknesses | LLM02 Sensitive Information Disclosure |

The `owasp_mapping` field on a finding carries the **primary** category; this table is the reference
for the secondary ones.

## Pipeline guard contract

```python
guard.ingest(text, metadata) -> {
    "accepted":        bool,     # False when auto_reject and a critical/high finding fired
    "document_id":     str,      # resolve_document_id()
    "review_required": bool,     # findings present but not blocking
    "findings":        [ {type, severity, family, description, evidence, remediation, owasp_mapping} ],
    "report":          str,      # human-readable summary
}

guard.batch_ingest([{id, text, metadata}]) -> {
    "total", "clean", "summary", "severity_summary",
    "documents": [ {id, accepted, findings_count, families} ],
}

guard.export_report(report, path)   # JSON: findings + severity summary + OWASP mappings
```

`auto_reject=False` (the default) reports without blocking — useful in CI and dry-run rollouts.

## Testing methodology

Each family is covered by a positive test, and the risky ones by a false-positive guard:

| Test group | What it locks down |
|-----------|--------------------|
| `test_scanner.py` — baseline | clean document stays clean; each finding type fires; severity summary |
| `test_scanner.py` — override variants | 5 instruction-override phrasings (no qualifier, intervening word, alternate verb/noun, whitespace padding) |
| `test_scanner.py` — obfuscation | entity-encoded payload still detected; `canonicalize()` output asserted |
| `test_scanner.py` — false-positive guards | benign HTML is not a chunk-split attack; a plain SQL mention is not critical; ordinary how-to language stays clean |
| `test_scanner.py` — contract | every finding carries family, OWASP mapping and evidence; family names unique |
| `test_pipeline.py` | reject/accept/review decisions; batch correlation **with and without explicit ids** (regression for the 0.1.0 bug); JSON export |
| `test_vector_check.py` | poisoning detected; legitimate duplicates and distinct embeddings not flagged; missing embeddings skipped |

Current status: **33 tests passing**, ruff clean, mypy clean.

```bash
uv run pytest
# .................................                                        [100%]
# 33 passed in 0.05s
uv run ruff check .
uv run mypy ragguard
uv run python examples/document_poisoning_demos.py
```

CI (`.github/workflows/test.yml`) runs lint, type check, tests and the demo smoke test on Python
3.10 / 3.11 / 3.12.

## Known limitations

- Heuristic phrase detection, not a semantic classifier — novel payloads that avoid these word
  shapes pass the scan.
- English word shapes; NFKC canonicalisation covers Latin-script lookalikes, not cross-script
  homoglyph attacks.
- Evidence strings come from normalised text when the raw form cannot be located.
- Chunk-splitting rules are markers; the correct fix is reassembling documents before scanning.
- Vector checks flag proximity, not proven exfiltration, and require a supplied embedding space.
- Some families are intentionally broad; tune by removing families rather than weakening regexes.

## Verification / reproduction

```bash
git clone https://github.com/wif1c0ldspot/ragguard.git && cd ragguard
uv sync
uv run pytest -q                                       # 33 passed
uv run ruff check .                                    # All checks passed
uv run mypy ragguard                                   # Success: no issues found
uv run python examples/document_poisoning_demos.py      # 7 sections, all complete
```

## Roadmap

- [x] CI workflow: lint, type check, tests, demo smoke test
- [ ] LangChain integration wrapper (optional extra)
- [ ] LlamaIndex integration wrapper (optional extra)
- [ ] Vector DB plugins (ChromaDB, pgvector) with tenant-partition checks
- [ ] YAML rule engine for custom families
- [ ] Benchmark suite against public attack datasets
- [ ] Layered deployment alongside garak / promptfoo

## Changelog

See [CHANGELOG.md](../CHANGELOG.md).

## License

MIT — see [LICENSE](../LICENSE).
