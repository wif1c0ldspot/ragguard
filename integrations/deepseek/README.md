# ragguard for DeepSeek Harness

A Cordis bundle that checks tool results locally using ragguard's Python scanner.
It targets **`@deepseek-ai/dsh-tools@0.1.7-rc.2`** and Cordis `~4.0.4`.
The harness preview APIs are version-sensitive: do not substitute the individual
packages' older npm `latest` versions. Node 22+ and Python 3.10+ are required.

## Architecture

```text
DeepSeek tool execution (including nested registry dispatch)
  → tools/post-execute policy
  → bounded extraction: rendered text + canonical value + metadata + contexts
  → persistent Python subprocess (JSON Lines over private stdio)
  → ContentBoundary → scanner + decision policy
  → accept original result OR block with neutral feedback
```

No model API key or network service is needed for scanning. The Python package
and this npm bundle are separate installations. The worker returns decisions,
family names and ruleset/schema versions; it never echoes documents or evidence.
The client does not forward worker stderr into harness logs.

The policy holds both `review` and `reject` by default. Text extraction checks
adjacent and whitespace-separated block projections, including composed added
context. It scans downstream
replacement content and additional contexts too, returning a detached snapshot
so later mutations cannot replace checked content. It conservatively blocks any
downstream canonical-value replacement because the host renders that value after
this hook. A block removes the original canonical value, metadata and deferred
contexts through the host's native block contract.

## Build and install from this repository

From the repository root, install this checkout's Python package (a previously
published ragguard version may not contain the worker):

```sh
uv venv .venv-dsh
uv pip install --python .venv-dsh/bin/python .
npm --prefix integrations/deepseek ci
npm --prefix integrations/deepseek run build
```

Before installing the bundle, edit `integrations/deepseek/cordis.patch.yml` so
`config.python` is the **absolute path** to `.venv-dsh/bin/python`. This avoids
relying on the CLI's working directory, activated shell or global Python.
Keep `mode: enforce`. Then, with the compatible harness CLI installed:

```sh
dsh plugin --profile guarded add ./integrations/deepseek
dsh --profile guarded --dump-config
```

Inspect the effective profile for a single `dsh-ragguard` instance in the same
scope as its tools service. Load this policy before other post-execute policies
whose replacement results it must inspect. A preceding middleware that does not
call `next`, or that replaces the decision after this policy returns, is outside
this policy's control. The `guarded` profile is an example; these commands have
not been run against your active profile.

For distribution, `cd integrations/deepseek && npm pack` builds a tarball
containing the Cordis patch and compiled JavaScript/types. Distribute a matching
Python wheel separately and configure its interpreter on the destination.

## Configuration

The supplied patch uses `python: python3` and `mode: enforce`. Supported options:

- `python`: executable path, passed directly to spawn without a shell.
- `mode`: `enforce` (default) or `monitor`. Monitor deliberately releases detected
  findings; worker failures, unsupported content and limits still block. This
  initial plugin does not expose a persistent monitoring dashboard or audit sink.
- `toolNames`: optional nonempty list of exact tool names. Omit to cover all tools
  reaching this hook. Excluded tools are deliberately uninspected.
- `enabledFamilies`: optional nonempty list of scanner family identifiers.
  Omit to enable all. Invalid identifiers cause worker startup failure and holds.
- `timeoutMs`: 10000; includes worker retirement waits and startup for each check.
- `maxPending`: 32 concurrent checks.
- `maxTextChars`: 200000 across extracted representations. Repeated projections
  count repeatedly; an oversized result is held, never silently truncated.
- `maxDocuments`: 64; `maxFrameBytes`: 2000000, including JSON framing.
- `maxDepth`: 32; `maxNodes`: 10000 for structured traversal.

Configuration rejects unknown keys, invalid limits and empty selection lists.
Cancellation or protocol failure retires the whole worker and holds all pending
checks. The next call starts a fresh worker after retirement. Plugin disposal
removes its hook and terminates the owned subprocess, escalating if needed.

## Verification

Install development dependencies as above, then run from the repository root:

```sh
RAGGUARD_TEST_PYTHON="$PWD/.venv-dsh/bin/python" npm --prefix integrations/deepseek test
npm --prefix integrations/deepseek run typecheck
npm --prefix integrations/deepseek run build
```

CI also unpacks the npm tarball and runs its compiled JavaScript against an
installed Python wheel outside the checkout (`tests/package-smoke.mjs`).

Tests exercise real subprocess failures, concurrent correlation, cancellation,
shutdown, bounded extraction, middleware behavior and actual Cordis/tool-registry
execution against the real Python worker. They require no model credentials.

## Coverage and trust limits

This is a **post-execution tool-result policy**, not a sandbox or a complete
model-context firewall. Tool side effects have already happened. User input,
system prompts, old history, arbitrary filesystem reads and external logs need
separate controls. Heuristic detection has false positives and false negatives;
calibrate it against your corpus and threat model.

Install only trusted tools and middleware. Tool `finalizeContent` callbacks run
**after** this hook and can replace even blocked feedback. Earlier middleware can
bypass the hook, and framework errors from preparation, projection, middleware
or final materialization may take paths outside it. Ordinary tool-body errors
that enter post-execute are inspected. Review these host paths before claiming
complete context enforcement; this plugin does not monkeypatch the runtime.

Only text content blocks are supported. Images, audio, file references and other
unsupported blocks are held until an application extracts their text. Structured
JSON is scanned as keys and string leaves, plus adjacent rendered text; arbitrary
programmatic reconstruction/decoding of strings is not equivalent to scanning
the eventual rendering. Cross-result/session assembly needs an additional check.
Vector-store assessment remains an offline operation.

The real-registry tests cover native execution and nested registry dispatch;
they do not constitute a full CLI/profile installation or live-model/PTC sandbox
end-to-end test.

## Host references

- [Tool pipeline](https://deepseek-harness.github.io/deepseek-harness/en/reference/subsystems/tools)
- [Bundle installation](https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/publish)
- [Cordis lifecycle](https://deepseek-harness.github.io/deepseek-harness/en/develop/framework/)
