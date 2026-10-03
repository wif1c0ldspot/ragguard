# Integrating ragguard with agentic harnesses

Integration design checked against official documentation on 2026-09-27 and
updated for ragguard 0.2.0. The
implemented `ContentBoundary` adapter and `examples/harness_boundary.py` have no
framework dependency. The DeepSeek Harness bundle below is implemented and tested against its real tool
registry. Other recipes describe where to call the adapter; they are not claims
of installed or end-to-end-tested native integrations.

## One shared boundary

```python
from ragguard.boundary import Boundary, ContentBoundary
from ragguard import Document

gate = ContentBoundary()  # enforcement; holds review as well as reject

def checked_tool_result(text: str, tool_call_id: str) -> str:
    return gate.require(
        Document(text=text, id=tool_call_id, source="retrieval-tool"),
        boundary=Boundary.TOOL_OUTPUT,
    )
```

An async tool can `await gate.arequire(document, boundary=Boundary.TOOL_OUTPUT)`.
`ContentBlockedError` contains a decision summary without the held text. Stop,
quarantine or route to human review; never catch the exception and return the
original payload. Validation and resource-limit errors also stop release. To
explicitly monitor rather than hold findings, combine
`RAGPipelineGuard(auto_reject=False)` with `ContentBoundary(guard, allow_review=True)`.
That setting intentionally allows flagged content through.

Low and info findings (split markers, structural SQL/markup hints) are advisory
under the default `review_floor="medium"`: they do not hold content, and
`BoundaryResult.advisory_families` lists them for logging. Use
`RAGPipelineGuard(review_floor="info")` to hold on every finding, or
`family_actions` to promote or demote individual families. When the harness needs
the decision without the release logic, `guard.evaluate(document)` returns a typed
`DocumentDecision`.

Apply authorization using trusted caller identity first. Scan the complete final
rendering, including metadata if it will be placed in context. For a retrieved
batch, keep occurrence identity and rescan the final assembly if concatenation
can create cross-chunk instructions; for ordered chunks of one source,
`RAGScanner().scan_chunks(chunks)` reports injections that span a chunk boundary
as `split_payload`. `RAGPipelineGuard.evaluate_chunks(chunks)` applies policy to
both participants and returns per-chunk decisions. Buffer tool-result streams until checked;
already-streamed text cannot be withdrawn. The adapter only returns document text,
not a rewritten metadata object or a permission grant.

## OpenAI Agents SDK and custom Responses loops

Wrap application-owned retrieval function tools so their return path calls
`checked_tool_result`. Tool guardrails are another attachment point for function
tool arguments/results; agent-level input/output guardrails do not cover every
intermediate tool boundary. In a custom Responses loop, check the result before
submitting the function output. Preserve call IDs in the host's native protocol.
For hosted tools whose results the application cannot intercept before model use,
this wrapper does not provide equivalent coverage; move retrieval into a controlled
function tool or enforce ingestion controls in the data source.

This is a proposed application integration based on the documented guardrail
boundaries, not an SDK extension shipped here. [Official guardrails guide](https://developers.openai.com/api/docs/guides/agents/guardrails-approvals).

## LangChain / LangGraph

LangChain `wrap_tool_call` middleware can inspect the handler result before
returning it; async applications need the corresponding async path. Check the
textual content while preserving tool-call IDs and message structure. Handle
`Command` returns and structured content explicitly rather than coercing every
result to a string. A LangGraph application can instead put the check in its own
retrieval node before updating model-visible state, with a route to review on hold.

The middleware hook is documented; the graph placement is our architecture
recommendation. [Official custom middleware guide](https://docs.langchain.com/oss/python/langchain/middleware/custom).

## LlamaIndex

Use a custom node postprocessor after retrieval and before synthesis. Render each
node exactly as synthesis will consume it, then call `gate.require`; preserve
node IDs and source metadata outside model context. Choose whether one held node
aborts the query or is removed with an auditable coverage decision. Also scan
parent documents before splitting at ingestion. Neither step replaces tenant ACLs.
[Official node postprocessor guide](https://developers.llamaindex.ai/python/framework/module_guides/querying/node_postprocessors/).

## CrewAI

Place the check in an application-owned custom tool's return path. Do not rely
only on validation of the final task answer: retrieved instructions may already
have affected tool use. Return only the checked text and keep failure handling in
the host. If results are cached, scan after cache retrieval too, or invalidate the
cache when policy/rules change. This wrapper design uses CrewAI's documented tool
extension point. [Official tools guide](https://docs.crewai.com/en/concepts/tools).

## Google ADK

An `after_tool_callback` can inspect and replace a tool response before it is
returned to the agent; an application can use it to withhold text via the same
boundary adapter. Preserve the tool's response schema when replacing content.
Use pre-tool authorization for side effects; an after-tool content check cannot
prevent the tool action that already occurred. [Official callback guide](https://adk.dev/callbacks/types-of-callbacks/).

## Codex, Claude Code, and MCP clients

The most portable design is to guard an application-owned MCP retrieval server:
authenticate, retrieve, scan, then return only permitted content. The actual MCP
server transport, authentication and protocol responses are not implemented here.
A separate optional “scan this” tool is advisory because an agent may omit it;
put enforcement inside the retrieval tool itself. This does not cover unrelated
shell/browser/file-reading paths in the harness. [Official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

Claude Code also documents `PostToolUse` output replacement via
`updatedToolOutput`, with `updatedMCPToolOutput` for MCP. A version-pinned hook can
scan then replace a held result with a neutral response of the required shape.
Merely adding a warning is not withholding. Post-tool checks do not undo side
effects; use pre-tool controls for those. This repository does not ship such a hook.
[Official Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

## Deployment checks

- Verify malicious and review-required results never enter model history, memory,
  retries or streamed output on every applicable route.
- Test scanner errors, timeouts, oversized payloads and unsupported result formats.
  Do not silently bypass the gate on an error.
- Enforce tenant authorization separately and test unauthorized retrieval directly.
- Log redacted decision summaries with host-owned run/tool IDs. Do not log raw text
  or assume scanner redaction covers every possible credential format.
- Pin framework versions, add contract tests for their concrete message shapes,
  and measure latency/false positives using representative data before deployment.
  `evals/run.py` shows the approach; run it against your own labelled corpus.
- Record `ruleset_version` and `schema_version` with each decision. Validate
  report output against `load_schema("report")` in contract tests.
- Non-Python hosts using `python -m ragguard.worker` should validate the ready
  handshake (`protocol`, `type`, `ruleset_version`, `schema_version`,
  `package_version`), check every response against it, and treat any mismatch as
  a failure that withholds content. `load_schema("worker-protocol")` describes
  every frame.

## DeepSeek Harness (implemented)

[`integrations/deepseek`](../integrations/deepseek/README.md) contains a Cordis
bundle for the pinned `@deepseek-ai/dsh-tools@0.1.7-rc.2` preview. It checks
`tools/post-execute` results through a persistent local Python worker, including
rendered content, canonical values, metadata and added contexts. Native block
decisions strip held payloads. The process bridge handles bounded framing,
concurrency, cancellation, restart and disposal without returning raw content
on operational failure. The client validates the worker's versioned handshake,
fails closed when a response's ruleset or schema version drifts from it, and
exposes the announced versions as `workerInfo`.

Install the Python package from this checkout and the npm bundle separately,
then configure an absolute interpreter path. See the bundle README for exact
build/install commands, scope/order requirements and tests. Tool finalizers and
trusted middleware can execute outside this hook; it is not a full context
firewall. No user profile is modified by building or testing the bundle.
