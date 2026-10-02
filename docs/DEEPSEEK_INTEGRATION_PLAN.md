# DeepSeek Harness integration plan

## Goal and compatibility boundary

Ship an installable Cordis bundle that checks tool results through ragguard's
existing Python boundary before releasing them to DeepSeek Harness. Pin and test
the published `@deepseek-ai/dsh-tools@0.1.7-rc.2` preview contract; the npm `latest`
tag for individual harness packages is older and is not an adequate compatibility
selector. This work does not install or change the user's active harness profile.

## Execution plan

1. **Verify the host contract (parent).** Inspect official package source and
   published types, especially post-execution blocking, canonical values, extra
   context, middleware composition and disposal.
2. **Python worker (subagent).** Add `python -m ragguard.worker`, a persistent,
   bounded JSON Lines process. Validate messages strictly; return only decisions
   and family/version summaries. Hold on scanner errors and malformed input.
3. **Worker client (subagent).** Implement a shell-free Node subprocess bridge,
   readiness handshake, bounded queues/frames, request correlation, cancellation,
   timeout handling, process retirement and disposal. Never release on failure.
4. **Cordis policy (subagent).** Intercept `tools/post-execute`, scan all supported
   result projections, and block held content using a real block decision. Preserve
   other policies' blocks and check downstream replacements. Reject unsupported
   content shapes instead of claiming to have inspected them.
5. **Packaging and integration (parent).** Add the npm bundle manifest, Cordis
   patch, build/type/test commands, lockfile, documentation and CI. Ship the Python
   worker with the Python library; the npm bundle uses a configured interpreter
   whose environment contains that library.
6. **Verification and review (parent plus subagent review).** Exercise both
   components independently, then execute real Cordis/tool-registry integration
   with the Python worker. Build and inspect the npm tarball and Python wheel.

## Acceptance criteria

- Clean text and canonical values pass unchanged; held values, metadata and
  additional contexts do not reach the final tool result.
- Review is withheld by default; monitoring release is an explicit configuration.
- Timeouts, malformed/oversized frames, worker exits and cancellation never fall
  back to raw content. Unload removes listeners and terminates owned processes.
- Parallel calls remain correlated, and canceled calls cannot consume another
  call's reply. A failed process is retired before replacement.
- Structured programmatic results are checked, not just rendered text. Nested
  tool calls use the same policy attachment. Direct and nested paths are tested.
- Downstream policy replacement cannot insert an unchecked value. Existing block
  decisions remain blocks.
- Unit tests, real registry/worker tests, Python regressions, type checks and
  packaging checks pass without model credentials or live model calls.

## Deliberate limits

The policy scans tool results, not pre-execution authorization or arbitrary user,
system-prompt or filesystem inputs. It cannot undo a tool's side effects. Trusted
same-process plugins, tool finalizers, and external logging paths are outside its
isolation boundary; a hostile plugin can bypass any cooperative in-process policy.
Existing session history is not retroactively cleaned. Images and file handles
require extraction before text scanning; unsupported shapes are withheld. Vector
assessment remains offline and is not run per tool call. Corpus calibration and
production performance tests remain deployment-specific.

## Sources

- [Tool pipeline contract](https://deepseek-harness.github.io/deepseek-harness/en/reference/subsystems/tools)
- [Cordis lifecycle](https://deepseek-harness.github.io/deepseek-harness/en/develop/framework/)
- [Bundle packaging](https://deepseek-harness.github.io/deepseek-harness/en/develop/basic/publish)
- [Official source](https://github.com/deepseek-ai/deepseek-harness)

## Completion and verification — 2026-09-27

All six steps are implemented. Three subagents delivered the Python worker,
process client and Cordis policy; a separate review found an in-flight queue
bound gap during process retirement, which was fixed with a regression test.

- Python suite: 195 passed; Ruff and mypy pass. Coverage reports 92% overall;
  subprocess-driven worker CLI paths are not included in parent-process coverage.
- TypeScript suite: 40 passed, including five actual Cordis/tool-registry tests
  using the installed Python wheel. Typecheck and compiled build pass.
- Tests cover native and nested registry calls, clean preservation, held value/
  metadata/context removal, monitoring, downstream replacement, missing workers,
  malformed replies, cancellation, restart and forced subprocess shutdown.
- Python wheel and source distribution build successfully; an isolated installed
  wheel emits the handshake and accepts a clean request outside the source tree.
- npm tarball contains the manifest, patch, license, README and compiled JS/types.
  Development dependencies and test fixtures are excluded.
- CI now runs the plugin suite on Node 22 with Python 3.12. Local verification
  used Node 24.21.0 and Python 3.12.13; remote CI has not been run here.

No active harness profile was changed, package published, or live model invoked.
A full CLI-profile/PTC-sandbox deployment test and corpus/performance calibration
remain deployment follow-ups, outside the verified tool-registry boundary.

## Follow-up verification and improvements

A second verification pass reran the complete Python suite (195 passed, 92%
parent-process coverage), Ruff, mypy, TypeScript checking and distributable
builds. The expanded JavaScript/TypeScript suite now has 49 passing tests,
including six real registry/worker tests. The unpacked npm artifact was also
loaded without a TypeScript loader and checked against an installed Python wheel
from outside the checkout: clean content passed, an attack was withheld and
Cordis disposal completed. CI now repeats this artifact-level smoke test.

Concrete defects fixed during this pass:

1. **Split text detection:** adjacency alone could merge word boundaries, while
   structural keys interrupted the separate leaf scan. Extraction now checks
   adjacency, whitespace-separated blocks and composed message projections.
2. **Mutable downstream decisions:** a producer could change its decision while
   the scanner awaited a response. The returned decision is now a detached,
   validated snapshot.
3. **Retirement deadlines:** cancellation and timeouts previously started after
   waiting for an old process to exit. They now cover the entire admitted call.
   Both regressions were confirmed to fail under the previous implementation.
4. **Extraction work bounds:** empty string contexts could accumulate render
   arrays before structural validation. Node/separator budgets now apply during
   that first pass; oversized sparse arrays are rejected before traversal.

Remaining improvement priorities:

- **Before production deployment:** test installation into an isolated CLI
  profile, real PTC sandbox calls, scope inheritance and plugin ordering. Audit
  post-hook finalizers and middleware; the plugin cannot guarantee enforcement
  over code that runs outside its hook. Local tests used Node 24/Python 3.12;
  Node 22 and the Python matrix are configured in CI but remote CI is unverified.
- **Operational visibility:** add an opt-in redacted event sink for decision,
  detector family, latency, timeout and restart counts. Monitor mode currently
  releases findings without a persistent telemetry interface.
- **Calibration and capacity:** measure false positives/negatives and latency on
  a representative corpus. Multiple result projections count toward resource
  limits; one cancellation retires the shared worker and holds other pending
  calls. Evaluate pooling only after measuring that availability tradeoff.
- **Broader coverage:** add application-owned multimodal extraction and a final
  session-assembly check for instructions split across separate tool results.
  Never treat heuristic acceptance as proof of safety.
