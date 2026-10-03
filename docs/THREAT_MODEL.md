# Threat model and supported use

Ragguard is a local, heuristic inspection layer for untrusted RAG documents,
metadata, chunks and tool-result text. Its rules produce explainable findings;
policy converts findings into accept, review or reject decisions. It does not
establish that an accepted document is trustworthy.

## Assets and adversary

The host application protects private data, tenant boundaries, model instructions,
credentials and access to tools with side effects. An adversary may control a
retrieved document's body, title, metadata, adjacent chunk text, or a tool response.
They may split instructions across boundaries or use encodings and Unicode to
obscure them. They may also supply ordinary text that resembles an attack and
causes false positives.

The Python runtime, scanner code and configuration, authentication service,
authorization data, retrieval backend and integration code are trusted. Arbitrary
malicious code running in the same process is outside the scanner's isolation
boundary. A JSON-shaped payload is not a sandbox for executable objects or plugins.

## Application boundaries

1. Authenticate the request and derive identity from verified application state.
2. Apply trusted collection/tenant/document authorization inside retrieval before
   returning any candidates. Do not use attacker-provided metadata as an ACL.
3. Render all model-visible material, including titles and source metadata, and
   scan the final assembled context. Scan relevant ingestion and tool-result paths
   as well; an earlier scan does not cover a later rendering or mutation.
4. Withhold review and reject results under enforcement. Scanner errors must stop
   release; never fall back to the original unchecked text.
5. Pass the checked text unchanged to the intended context slot. Enforce tool
   permissions and side-effect approval separately from content screening.

The executable [retrieval example](../examples/retrieval_pipeline.py) demonstrates
these boundaries using a local collection store. Its principal is assumed to have
already been authenticated. It performs no network retrieval or model call and
makes no claim about model behavior. A production adapter must implement the
same authorization filter in its database/vector-store query.

`ContentBoundary` provides an enforcing text gate; the caller owns its placement.
The JSON Lines worker provides bounded process communication for non-Python hosts.
The DeepSeek plugin scans supported text surfaces and downstream policy decisions
with documented ordering constraints. Unsupported media and operational errors
are withheld. See the [harness guide](HARNESS_INTEGRATIONS.md) and
[plugin guide](../integrations/deepseek/README.md) for exact coverage and trusted
host callbacks.

## What this layer does not provide

- Authentication, row-level security, tenant isolation, provenance verification,
  signature validation or permission enforcement in a vector store.
- A model sandbox, prevention of already-executed tool side effects, output
  validation, network egress controls or a complete data-loss-prevention system.
- Semantic understanding of every attack, every language or every encoding.
  Benign quotations can match rules and novel attacks can pass them.
- General image, audio, video or OCR inspection. The text scanner cannot establish
  the safety of hidden instructions in those formats.
- Proof that vector anomalies are poisoning. Vector checks are heuristic
  assessments; re-embedding comparisons depend on trusted inputs and an
  appropriate embedding function.

The bundled evaluation corpus tests specific regressions and configured quality
gates. It is not a representative production benchmark or an assurance that all
prompt injections are detected. Validate against your own synthetic workload and
review false positives and false negatives before changing enforcement policy.

## Logging and operational limits

Findings, document IDs, evidence and released text can contain sensitive data.
Targeted redaction is not exhaustive. Prefer a minimal audit projection with the
decision, rule families, ruleset version and aggregate counts, as the example does.
Keep detailed investigations in protected storage with appropriate retention.

Bound input size, batch size and concurrent work at each application entry point.
Use the worker's frame, timeout and queue controls when crossing the process
boundary. Refuse oversized content rather than scanning a prefix and releasing an
unchecked suffix. Cancellation and dependency failures must remain fail-closed.

Report suspected weaknesses using [private vulnerability reporting](../SECURITY.md).
