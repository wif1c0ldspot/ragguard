# ragguard evaluation corpus

A labelled corpus and a metrics runner for measuring how well ragguard's heuristic
families catch attacks in RAG content, and how often they flag ordinary documents.

## The data

- `corpus/attacks.jsonl`: 160 attack documents in 14 categories.
- `corpus/benign.jsonl`: 156 benign documents in 12 categories, many of them hard negatives.
- `corpus/chunks.jsonl`: 32 ordered chunk cases (16 attacks and 16 benign controls).
- `manifest.json`: file-level provenance and frozen holdout hashes for all three corpora.

All text was written synthetically for this repository. None of it is copied from
public jailbreak datasets, papers or websites. The corpus is MIT-licensed along with the
rest of the repo. URLs and email addresses use only reserved names (`example.com`,
`example.org`, `example.net`, `*.example`, `*.test`, `*.invalid`). Fake secrets are
obviously fake, for example `sk-test-000…`. `tests/test_evals.py` enforces these rules.

Each line is one JSON object:

```json
{"id": "a-0001", "text": "...", "metadata": {"title": "..."} , "label": "attack",
 "category": "instruction_override", "split": "dev", "notes": "short description"}
```

`metadata` is `null` or an object that is passed to `guard.ingest(text, metadata)`.

**Attack categories:** `instruction_override`, `persona_override`,
`system_prompt_extraction`, `data_exfiltration`, `markdown_exfiltration`,
`jailbreak_mode`, `metadata_injection`, `obfuscation_homoglyph`,
`obfuscation_spacing_leet`, `obfuscation_encoding`, `paraphrase`, `multilingual`,
`markup` and `tool_output`.

The corpus was written from a threat-model perspective, not from the scanner's
patterns. It deliberately includes attacks that a regex scanner is expected to miss:
paraphrases with no trigger words, non-English text, homoglyphs, leetspeak, encodings
and injections buried in tool results. These entries are labelled honestly as attacks,
because measuring the misses is the point.

**Benign categories:** `technical_docs`, `tutorial_steps`, `sql_docs`, `html_js_docs`,
`security_discussion`, `business`, `config_docs`, `markdown_docs`, `api_docs`,
`general_prose`, `multilingual_benign` and `metadata_benign`.

Examples of the hard negatives:

- Articles that discuss prompt injection.
- "Ignore the warnings in step 2" in an install guide.
- SQL tutorials and HTML/JS docs that use `onclick` or `<script>`.
- Kubernetes base64 examples.
- API docs with `api_key=YOUR_API_KEY`.

## Splits and the anti-overfitting rule

About 30% of each category is marked `split: "holdout"`; the rest is `dev`.

- Tune rules only against **dev**. Do not read holdout misses or false positives to
  write or adjust patterns.
- Report every rule change on **both** dev and holdout. If dev improves and holdout
  does not, that is evidence of overfitting.
- When the corpus grows, write new entries from the threat model first, then measure.
  Do not write strings to match an existing regex. Keep about 30% of each category in
  holdout.

## Running

```bash
python evals/run.py                                  # all entries, console summary
python evals/run.py --split dev --json out.json --markdown out.md
python evals/run.py --check evals/thresholds.json    # exit 1 on any violation
python evals/run.py --review-floor medium            # only if the guard supports it
python evals/run.py --mode chunks --check evals/chunk-thresholds.json
```

The runner builds `RAGPipelineGuard(auto_reject=True)` and calls
`guard.ingest(text, metadata, id=...)` once per entry. `--review-floor` is forwarded
only if the guard's constructor accepts `review_floor`. You can also import the
runner: `evaluate(entries, guard) -> dict`.

## Metrics

Definitions:

| Metric | Definition |
|---|---|
| Attack detection rate | Attacks with `decision != "accept"` (review or reject), divided by all attacks |
| Attack block rate | Attacks with `decision == "reject"`, divided by all attacks |
| Benign false-positive rate | Benign entries with `decision != "accept"`, divided by all benign entries |
| Benign false-block rate | Benign entries with `decision == "reject"`, divided by all benign entries |
| Per-category rate | The detection rate for attack categories, or the false-positive rate for benign categories |
| Family fires | Number of attack or benign documents whose result lists the family |
| Family precision | Attack fires divided by all fires |
| Latency | Wall-clock time of `ingest()` per document: p50, p95 and max, in milliseconds |

The JSON report also lists `missed_attack_ids`, `false_positive_benign_ids` and
`false_block_benign_ids`. It contains ids, decisions, families, and provenance declarations, never corpus text.
The `records` array includes each case result and, in chunk mode, the ordered
`chunk_decisions`. `corpus_sha256` identifies the complete input, `evaluated_sha256`
identifies the selected split, and `results_sha256` covers per-case decisions and
families with latency removed. Hashes use UTF-8 canonical JSON (sorted keys, no
extra whitespace, literal Unicode) with records sorted by ID. Python/platform and
CLI policy settings are included; wall-clock latency is intentionally not reproducible.

### Threshold file format

`thresholds.json` maps each rate threshold to `{split: value}`. The splits are `dev`,
`holdout` and `all`.

- `min_attack_detection_rate`, `min_attack_block_rate`,
  `max_benign_false_positive_rate` and `max_benign_false_block_rate` use that form
  directly.
- `min_category_detection_rate` and `max_category_false_positive_rate` take
  `{split: {category: value}}`.
- `max_p95_latency_ms` is a scalar, checked against the `all` run.

With `--split all`, thresholds for all three splits are checked. With `--split dev` or
`--split holdout`, only that split's thresholds are checked. Keys that start with `_`
are comments. Any other unknown key counts as a violation.

## Baseline

Measured against `RULESET_VERSION = "2026.10.2"` with `RAGPipelineGuard(auto_reject=True)`
and the default `review_floor` (medium), so low/info findings are advisory.
Rechecked on 2026-10-03 with Python 3.12.13 on macOS. Detection rates are unchanged
from `2026.10.1`: the new ruleset improves chunk boundaries, while this corpus
evaluates whole documents. The separate chunk corpus below measures boundary behavior;
unit regressions are also covered in `tests/test_chunks.py` and `tests/test_pipeline.py`. Latencies below are local observations, not an SLA.

| Split | Attacks | Benign | Detection | Block | Benign FPR | Benign false-block | p95 latency |
|---|---|---|---|---|---|---|---|
| dev | 117 | 108 | 37.6% | 36.8% | 6.5% | 6.5% | 0.11 ms |
| holdout | 43 | 48 | 27.9% | 27.9% | 2.1% | 2.1% | 0.09 ms |
| all | 160 | 156 | 35.0% | 34.4% | 5.1% | 5.1% | 0.10 ms |

For comparison, ruleset `2026.09.1` (no review floor) measured 25.0% detection and a
9.0% benign false-positive rate on `all`.

Per-category detection on `all`:

| Category | Rate | Category | Rate |
|---|---|---|---|
| markup | 91% (10/11) | jailbreak_mode | 45% (5/11) |
| obfuscation_homoglyph | 82% (9/11) | obfuscation_spacing_leet | 45% (5/11) |
| obfuscation_encoding | 73% (8/11) | instruction_override | 42% (5/12) |
| metadata_injection | 36% (4/11) | markdown_exfiltration | 33% (4/12) |
| tool_output | 33% (4/12) | persona_override | 9% (1/11) |
| system_prompt_extraction | 9% (1/11) | data_exfiltration | 0% (0/11) |
| paraphrase | 0% (0/12) | multilingual | 0% (0/13) |

Benign false-positive rates on `all`:

- `html_js_docs`: 31% (4/13), mostly `delimiter_injection` on documentation that
  shows `<iframe>`/`<script>` markup
- `security_discussion`: 15% (2/13)
- `technical_docs`: 8% (1/13)
- `tutorial_steps`: 8% (1/13)
- All other benign categories: 0%

Known gaps the corpus makes visible: paraphrased and non-English injections,
data-exfiltration requests phrased as ordinary tasks, and persona or system-prompt
requests that avoid the canonical phrasings. These are the motivation for an optional
model-based detector tier; regex rules should not be stretched to chase them.

`thresholds.json` sets each floor a little below these numbers and each ceiling a
little above them. Re-measure after ruleset changes. Preserve regression floors unless a separately
reviewed change explains the tradeoff; do not weaken thresholds to hide regressions.


## Chunk evaluation

`--mode chunks` uses `guard.evaluate_chunks()` on each case's ordered chunks,
including chunk metadata and the case's explicit `window_chars`. A case is rejected
if any chunk is rejected, reviewed if any chunk is reviewed and none rejected,
and accepted otherwise. Rates count cases, not chunks or repeated findings.
The window is part of the corpus fingerprint. Sources should contain adjacent
chunks of one document, matching the API's contract.

The cases cover word and token boundaries, encoded instructions, homoglyphs,
contained attacks, metadata, everyday documents, empty boundaries, benign encodings,
and quoted security education. They also retain semantic paraphrases, non-English
attacks, and deliberately undersized windows as labelled misses. These are small
repository-authored scenarios, **not a representative sample of production traffic**.

Baseline with ruleset `2026.10.2`, auto-reject enabled, and medium review floor:
10 of 16 attacks are detected and rejected (62.5%); one of 16 benign cases is
flagged/rejected (6.25%), a security education quotation. Both splits detect 5 of
8 attacks; benign FPR is 0 of 8 on dev and 1 of 8 on holdout. Six attacks exercise
`split_payload`; the three corresponding categories each require 100% detection
in `chunk-thresholds.json`. The semantic, multilingual, and small-window limitations
remain visible without lowering the existing document thresholds.

## Frozen holdout and provenance

Every normal CLI run verifies `manifest.json` before scanning, including dev-only
runs. Each file declares `kind` (`synthetic` or `external`), `source`, `license`, and
`collection_method`, plus a holdout record count and canonical SHA-256 hash. Editing,
removing, adding, or relabelling a holdout record fails validation. Dev content may
change independently. Duplicate IDs, invalid labels/splits, invalid metadata/chunk
shapes, and empty corpora are rejected. A threshold requiring a metric with no
samples fails instead of silently passing.

The manifest is an integrity snapshot, not proof of independent evaluation. The
legacy holdout was already visible before freezing, and the new chunk fixtures
were authored alongside this implementation. Hashes do not establish authorship,
prevent data leakage, or resist someone editing both corpus and manifest. Preserve
the current freeze during rule tuning. A deliberate new dataset release requires
reviewing its provenance and recording a new version/freeze; never automatically
refresh hashes to make a failing run green. For a stronger generalization claim,
use an independently curated, licensed corpus that was not used in development.

## Importing an external corpus

No external samples are bundled or represented as independently sourced. The runner
can validate and evaluate a user-supplied JSONL corpus, separately from the synthetic
baseline:

```bash
python evals/run.py --corpus /path/to/external.jsonl \
  --manifest /path/to/external-manifest.json --json external-results.json
```

Use the document record format above, with unique IDs, `attack`/`benign` labels,
`dev`/`holdout` splits, and both classes in any split with corresponding gates.
For chunks, add `--mode chunks`; replace `text`/`metadata` with `chunks` (a nonempty
list of objects containing string `text` and optional `metadata`) and a positive
integer `window_chars`. Keep unrelated datasets in separate runs so pooled numbers
do not conceal provenance differences. Supply appropriate separate thresholds with
`--check`; the bundled thresholds are specific to the bundled synthetic corpora.

The external manifest uses this shape (paths are relative to the manifest):

```json
{
  "schema_version": 1,
  "corpora": [{
    "path": "external.jsonl",
    "mode": "documents",
    "provenance": {
      "kind": "external",
      "source": "Actual primary dataset URL or internal dataset identifier",
      "license": "Actual license or documented permission",
      "collection_method": "Actual sampling, labelling, transformations, and collection date"
    },
    "holdout_count": 42,
    "holdout_sha256": "replace with the computed canonical SHA-256"
  }]
}
```

At initial dataset intake, compute the reviewed holdout count and hash with the
same implementation used for validation:

```python
from pathlib import Path
from evals.run import corpus_digest, filter_split, load_corpus

entries = load_corpus([Path("/path/to/external.jsonl")])  # mode="chunks" if needed
holdout = filter_split(entries, "holdout")
print(len(holdout), corpus_digest(holdout))
```

The source/license fields are importer declarations; the tool does not certify
rights, authenticity, or independent authorship. Review those facts and remove real
secrets before importing. Keep sensitive corpora and generated reports outside the
repository unless publication is separately authorized.

## Reproducible external measurements

`external.py` imports original MIT-licensed NotInject and InjecAgent JSON from
exact upstream commits and checks SHA-256 plus byte length for **every** downloaded
file, including licenses and upstream READMEs. `external-sources.json` pins both
original files and converted-corpus hashes. Conversion preserves `prompt`
(NotInject) and `Tool Response` (InjecAgent) verbatim; it does not execute tools,
contact addresses in examples, or run an agent. External data stays in the cache,
outside the repository. The checked-in reports contain aggregate metrics and IDs,
not upstream sample text.

```bash
python evals/external.py import --cache-dir /tmp/ragguard-external
python evals/external.py evaluate --cache-dir /tmp/ragguard-external
python evals/external.py calibrate --cache-dir /tmp/ragguard-external --max-fpr .05
# Re-import from verified cached raw sources without any network access:
python evals/external.py import --cache-dir /tmp/ragguard-external --offline
```

The importer is explicit; evaluation/calibration never download data. An altered
cached file fails verification instead of being silently replaced. Source updates
or conversion changes require a separately reviewed source-lock update. Preserve
upstream notices when redistributing cached data. Primary sources and licenses:
[NotInject / InjecGuard](https://github.com/InjecGuard/InjecGuard),
[NotInject dataset card](https://huggingface.co/datasets/leolee99/NotInject), and
[InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent). Immutable license URLs,
revisions, original-file hashes, and derived hashes are recorded in the source lock.
These sources remain **external benchmark fixtures**, not production traffic or
proof that an evaluated model never encountered their content during training.

### Splitting and calibration

All records derived from an original source case or attack-tool family must remain
on one side of dev/holdout. InjecAgent base and enhanced variants share the same
origin and family assignments: 62 attack-tool families, 697 dev cases and 357
holdout cases per variant. Shared user-tool wrappers still create correlation and
are not claimed to be unseen contexts.

NotInject prompts are grouped transitively by any shared trigger word. This strict
word-family safeguard produces only **two connected components**, with 246 dev
examples and 93 holdout examples. The larger group was assigned to dev before
examining detector outcomes. This creates a language/domain shift and very few
independent groups; its counts cannot support strong population guarantees.
Source/group validation rejects cross-split derivatives. A source-disjoint test
would be stronger, but these sources are class-confounded (NotInject is all benign;
InjecAgent all malicious), so this release does not claim one.

Calibration enumerates existing severity review floors from info through critical.
It chooses the highest dev recall that satisfies the supplied **empirical** dev FPR
ceiling, breaking ties by lower dev FPR and then stricter severity. The holdout is
scanned only after selecting that floor. An infeasible ceiling is reported as
`no_feasible_policy`; holdout violations are reported without choosing a new floor.
This changes an evaluation policy only, never the package's default or scanner rules.
It is not continuous-score ROC optimization or a certified deployment FPR bound.

Reports include TP/FP/TN/FN, two-sided 95% Wilson intervals, source/corpus hashes,
runtime and implementation-file hashes, and calibration candidates. Wilson intervals
assume independent Bernoulli observations; repeated templates and families make
these **descriptive row-level intervals**, potentially too narrow. Benign-only
attack recall and attack-only FPR are `null`, not fabricated zeros. Any pooled
precision depends on the artificial source/class mix.

### Observed results, ruleset 2026.10.3

The saved `reports/external-baseline.json` records:

- NotInject: 0 of 339 benign samples flagged; observed FPR 0%, with a descriptive
  Wilson interval of 0–1.12%. This does not establish zero deployment false positives.
- InjecAgent **base**: 68 of 1,054 attacks detected (6.45%; descriptive interval
  5.12–8.10%). On its holdout, 34 of 357 are detected (9.52%).
- InjecAgent **enhanced**: 1,054 of 1,054 detected. The shared canonical override
  enhancement drives this result; it does not establish independent semantic
  detection of every attack family.

At a 5% empirical dev FPR ceiling, `reports/external-calibration.json` selects a
low review floor for base. On the **same holdout**, recall becomes 53/357 (14.85%)
while NotInject holdout flags remain 0/93. The additional 19 are existing structural
SQL advisory findings promoted to **review**; blocking remains 34/357. This is a
policy sensitivity result, not newly learned detection. Enhanced selects critical
and still detects every holdout case. Report base and enhanced separately.

`reports/synthetic-documents.json` and `reports/synthetic-chunks.json` record the
unchanged frozen-corpus gates. No rules were tuned against these external holdouts.

## Exposed transformation stress tests

```bash
python evals/transformations.py
python evals/transformations.py --corpus-output /tmp/ragguard-transformations.jsonl
```

This generates 48 cases from eight **dev-only** synthetic seeds and six deterministic
representations: identity, uppercase, HTML entities, zero-width separators, base64,
and additional spaces. Labels describe the inherited intended injection; they are
not proof a downstream model would follow encoded content. The corpus and report
are explicitly marked exposed, non-adaptive, and without an independent holdout.
Ruleset 2026.10.3 detects 9/24 attacks and flags 4/24 benign transformations.
These difficult results are preserved rather than hidden behind a success-only gate.

## End-to-end outcomes: available protocol, not measured results

Document detection cannot determine whether a malicious action occurred or whether
a legitimate task still completed. **No model-backed AgentDojo/agent outcome run
was performed for this release.** `outcomes.py` is a runnable importer/comparator
for artifacts generated by a real harness; it does not execute agents or judge traces.

For a valid run, pin an AgentDojo commit, task suite, model snapshot, attack strategy,
seed, and evaluator. Run paired baseline and ragguard-protected agents on the same
clean and attacked case sets. Preserve the original benchmark's security and utility
judgments, raw traces, failed executions, tool configuration, and defense settings.
Classifying a saved tool-output string is not an acceptable substitute.

Each exported artifact must have `schema_version: 1`, `benchmark`,
`benchmark_revision`, `model`, `model_revision`, `seed`, `judging_method`, `defense`,
and a nonempty `records` list. Each record needs `case_id`, `condition`
(`clean` or `attacked`), `status` (`ok` or `error`), boolean `task_success` for valid
runs, and boolean `attack_success` for valid attacked runs. Clean `attack_success`
and both success fields for error runs must be null. Baseline/defended provenance
and case/condition sets must match exactly; mismatches fail closed.

```bash
python evals/outcomes.py --baseline baseline.json --defended defended.json \
  --output agent-outcomes.json
```

The output reports attack success **and** legitimate-task completion, valid and
all-case denominators, explicit error counts, and paired utility losses/gains.
All-case successes with missing outcomes are labeled lower bounds; errors are not
silently counted as prevented attacks. Imported judgments remain producer claims,
not independently verified outcomes. See the
[AgentDojo benchmark](https://github.com/ethz-spylab/agentdojo) for the actual
execution environment and evaluators.
