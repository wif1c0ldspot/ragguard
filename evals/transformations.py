"""Deterministic exposed synthetic transformations; not an independent holdout."""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

if __package__:
    from . import external, run
else:
    import external
    import run


def generate() -> list[dict[str, Any]]:
    run.verify_manifest(list(run.CORPUS_FILES), run.MANIFEST_FILE, "documents")
    entries = run.filter_split(run.load_corpus(), "dev")
    categories = {
        "instruction_override",
        "data_exfiltration",
        "paraphrase",
        "multilingual",
        "technical_docs",
        "security_discussion",
        "business",
        "multilingual_benign",
    }
    seeds = {}
    for entry in entries:
        if entry["category"] in categories:
            seeds.setdefault(entry["category"], entry)
    transforms = {
        "identity": lambda text: text,
        "uppercase": str.upper,
        "html_entities": lambda text: "".join(f"&#{ord(char)};" for char in text),
        "zero_width": lambda text: "\u200b".join(text),
        "base64": lambda text: base64.b64encode(text.encode()).decode(),
        "extra_spaces": lambda text: text.replace(" ", "   "),
    }
    output = []
    for category, seed in sorted(seeds.items()):
        for name, transform in transforms.items():
            output.append(
                {
                    "id": f"transform-{seed['id']}-{name}",
                    "text": transform(seed["text"]),
                    "metadata": seed["metadata"],
                    "label": seed["label"],
                    "category": name,
                    "split": "dev",
                    "notes": f"Exposed synthetic {name} transform of dev seed {seed['id']} "
                    f"({category}); intended label inherited, not agent-validated.",
                    "source_id": "synthetic-transformations",
                    "origin_id": seed["id"],
                    "split_group": seed["id"],
                }
            )
    run.validate_split_groups(output)
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).resolve().parent / "reports" / "transformations.json",
    )
    parser.add_argument("--corpus-output", type=Path, help="optional generated JSONL path")
    args = parser.parse_args()
    entries = generate()
    if args.corpus_output:
        args.corpus_output.parent.mkdir(parents=True, exist_ok=True)
        args.corpus_output.write_text(
            "".join(json.dumps(e, ensure_ascii=False) + "\n" for e in entries), encoding="utf-8"
        )
    snapshot = {
        key: value
        for key, value in external.provenance().items()
        if key not in {"sources", "source_lock_sha256", "limitations"}
    }
    report = {
        **snapshot,
        "source_provenance": {"kind": "synthetic", "source": "bundled dev seeds", "license": "MIT"},
        "limitations": [
            "Exposed derived fixtures; correlated transforms are not independent samples",
            "No adaptive search or end-to-end agent outcomes were measured",
        ],
        "evaluation": "exposed_synthetic_transformations",
        "holdout": False,
        "adaptive_attack_search": False,
        "corpus_sha256": run.corpus_digest(entries),
        "seed_count": 8,
        "label_scope": "Inherited intended injection labels, not demonstrated agent outcomes",
        **run.evaluate(entries, external.make_guard()),
    }
    external.write_report(args.output, report)


if __name__ == "__main__":
    main()
