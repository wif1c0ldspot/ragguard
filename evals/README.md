# ragguard evaluation corpus

A labelled corpus and a metrics runner for measuring how well ragguard's heuristic
families catch attacks in RAG content, and how often they flag ordinary documents.

## The data

- `corpus/attacks.jsonl`: 160 attack documents in 14 categories.
- `corpus/benign.jsonl`: 156 benign documents in 12 categories, many of them hard negatives.

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
`false_block_benign_ids`. It contains ids only, not text.

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

Measured against `RULESET_VERSION = "2026.10.1"` with `RAGPipelineGuard(auto_reject=True)`
and the default `review_floor` (medium), so low/info findings are advisory.

| Split | Attacks | Benign | Detection | Block | Benign FPR | Benign false-block | p95 latency |
|---|---|---|---|---|---|---|---|
| dev | 117 | 108 | 37.6% | 36.8% | 6.5% | 6.5% | 0.10 ms |
| holdout | 43 | 48 | 27.9% | 27.9% | 2.1% | 2.1% | 0.08 ms |
| all | 160 | 156 | 35.0% | 34.4% | 5.1% | 5.1% | 0.09 ms |

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
little above them. Re-baseline both this section and the threshold file whenever the
ruleset version changes.
