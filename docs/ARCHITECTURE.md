# ragguard — RAG Pipeline Security Scanner

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │           RAG Pipeline (User)               │
                    │                                             │
                    │   Document Ingestion → Vector Store → Query │
                    └──────┬──────────────┬──────────────┬────────┘
                           │              │              │
                    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
                    │  Ingestion  │ │ Retrieval  │ │   Query    │
                    │   Scanner   │ │  Integrity │ │   Guard    │
                    │             │ │  Checker   │ │            │
                    └──────┬──────┘ └─────┬──────┘ └─────┬──────┘
                           │              │              │
                    ┌──────▼──────────────▼──────────────▼──────┐
                    │            RAGPipelineGuard                │
                    │  (Middleware / Pre-commit Hook / CI Gate)  │
                    └──────┬──────────────┬──────────────┬──────┘
                           │              │              │
                    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
                    │  Prompt     │ │  Metadata │ │  Chunk    │
                    │  Injection  │ │  Injection│ │  Splitting│
                    │  Detector   │ │  Detector │ │  Detector │
                    └──────┬──────┘ └─────┬──────┘ └─────┬──────┘
                           │              │              │
                    ┌──────▼──────┐ ┌─────▼─────┐ ┌─────▼─────┐
                    │  Canonical  │ │  Embedding│ │  Cross    │
                    │  Bypass     │ │  Poisoning│ │  User     │
                    │  Detector   │ │  Detector │ │  Contam.  │
                    └──────┬──────┘ └─────┬──────┘ │ Detector  │
                           │              │         └───────────┘
                           └──────┬───────┘
                                  │
                    ┌─────────────▼─────────────┐
                    │     ScanReport Engine      │
                    │  - Severity scoring        │
                    │  - OWASP LLM mapping       │
                    │  - JSON / Markdown export   │
                    │  - Pipeline gate (pass/fail)│
                    └───────────────────────────┘
```

## Data Flow

```
1. DOCUMENT INGESTION
   Raw document → RAGPipelineGuard.ingest()
                                    │
   ┌────────────────────────────────┼─────────────────────────┐
   │                                │                         │
   ▼                                ▼                         ▼
   Content Scanner             Metadata Scanner        Structure Scanner
   ├─ Prompt injection         ├─ Tool call injection    ├─ Chunk boundaries
   ├─ Jailbreak patterns       ├─ Code execution         ├─ HTML/XML injection
   ├─ Canonical bypass         ├─ Exfiltration commands  ├─ SQL injection
   └─ Encoding tricks          └─ Hidden instructions    └─ Instruction fragments
                                    │
                                    ▼
   ┌────────────────────────────────┼─────────────────────────┐
   │                                │                         │
   ▼                                ▼                         ▼
   Report: {accepted: bool, findings: [...], severity_summary: {...}}
```

## Attack Surface Coverage

| Attack Vector | Stage | ragguard Module | OWASP Mapping |
|--------------|-------|-----------------|---------------|
| Direct prompt injection in text | Ingestion | `scanner.py` — pattern matching | LLM01 |
| Indirect injection via document content | Ingestion | `scanner.py` — regex + heuristic | LLM01, LLM07 |
| Metadata tool-call injection | Ingestion | `scanner.py` — metadata scan | LLM07 |
| Canonicalization bypass | Ingestion | `scanner.py` — normalized scan | LLM01 |
| Chunk-splitting boundary attacks | Pre-ingestion | `scanner.py` — structural markers | LLM06 |
| HTML/XML injection in documents | Ingestion | `scanner.py` — tag detection | LLM01 |
| Embedding poisoning | Vector store | `vector_check.py` — similarity analysis | LLM07 |
| Cross-user contamination | Vector store | `vector_check.py` — tenant isolation check | LLM01 |
| Retrieval manipulation | Query time | `vector_check.py` — consistency check | LLM06 |

## Component Details

### RAGScanner (scanner.py)
Core scanning engine. Uses pattern-based detection with 15+ compiled regex patterns organized by attack category:
- **Direct injection patterns**: Instruction override, system prompt extraction, role hijacking
- **Encoding patterns**: Hex/Unicode encoding, invisible control characters
- **Jailbreak patterns**: Developer mode, dark web references, DAN-style prompts
- **Exfiltration patterns**: Base64 encoding, bulk data output requests
- **Metadata patterns**: Tool invocation, code execution, system calls
- **Structural patterns**: Chunk boundary markers, HTML/XML tags, SQL syntax

### VectorStoreIntegrityChecker (vector_check.py)
Embedding-space analysis for vector database attacks:
- Cosine similarity analysis to detect near-duplicate embeddings with dissimilar content (poisoning signal)
- Cross-user contamination detection in shared vector stores
- Text similarity comparison (Jaccard) to distinguish legitimate duplicates from adversarial injections

### RAGPipelineGuard (pipeline.py)
Middleware integration layer:
- `ingest()` — single document scan with optional auto-reject
- `batch_ingest()` — bulk processing with per-document acceptance decisions
- `export_report()` — JSON export with full finding details and OWASP mappings

## Development Setup

```bash
# Clone and set up
git clone https://github.com/joelchua/ragguard.git
cd ragguard
uv sync

# Run tests
pytest --cov=ragguard

# Lint and type check
ruff check ragguard/
mypy ragguard/
```

## Testing Methodology

Each attack pattern is tested with:
1. **Positive test**: Confirmed malicious input triggers detection
2. **Negative test**: Benign input passes without false positives
3. **Edge cases**: Empty docs, metadata-only attacks, multi-encoding bypass

9/9 core tests passing as of v0.1.0.

## Roadmap

- [ ] LangChain integration wrapper
- [ ] LlamaIndex integration wrapper  
- [ ] Real-time streaming scan support
- [ ] Vector DB plugin for ChromaDB / pgvector
- [ ] CI/CD GitHub Action
- [ ] Custom pattern rule engine (YAML config)
- [ ] Benchmark suite against known attack datasets
- [ ] Integration with Garak / Promptfoo for layered defense

## License

MIT