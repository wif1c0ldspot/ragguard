# Contributing

Ragguard is an alpha, local heuristic scanner. Contributions should preserve its
explainable findings and explicit separation between detection, policy and host
application enforcement. Read the [architecture](docs/ARCHITECTURE.md) and
[threat model](docs/THREAT_MODEL.md) before changing security-sensitive behavior.

## Development

Use Python 3.10 or newer and `uv`:

```sh
uv sync --locked
uv run --frozen ruff check .
uv run --frozen mypy ragguard
uv run --frozen pytest
uv run --frozen python evals/run.py --quiet --check evals/thresholds.json
uv run --frozen python evals/run.py --mode chunks --quiet --check evals/chunk-thresholds.json
uv run --frozen python examples/retrieval_pipeline.py
uv build
```

The locked development environment includes the optional vector dependencies.
The base package must continue to work without them. CI tests Python 3.10–3.12
and checks the built wheel from outside the source tree.

For DeepSeek integration changes, use Node.js 22 or newer and the locked packages:

```sh
npm --prefix integrations/deepseek ci
npm --prefix integrations/deepseek run typecheck
RAGGUARD_TEST_PYTHON="$PWD/.venv/bin/python" npm --prefix integrations/deepseek test
npm --prefix integrations/deepseek run build
```

## Proposing a change

Open a bug report with a minimal, synthetic reproduction, or describe a feature's
intended use and constraints. For a pull request, explain the observed problem,
changed behavior and verification. Keep unrelated refactors separate. New rules
need both attack and benign near-match cases; report evaluation changes instead
of describing heuristic detection as a security guarantee. Changes to serialized
reports or worker messages must keep their schemas and contract tests consistent.

Never add real credentials, private documents or customer data to tests, reports,
issues or evaluation fixtures. Use synthetic examples. Report possible exploitable
bypasses and other vulnerabilities through [the private security process](SECURITY.md),
not a public issue. This project does not promise response or release timelines.
