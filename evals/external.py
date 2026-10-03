"""Import pinned external benchmarks and evaluate text detection (never agent ASR).

Examples:
    python evals/external.py import --cache-dir /tmp/ragguard-external
    python evals/external.py evaluate --cache-dir /tmp/ragguard-external
    python evals/external.py calibrate --cache-dir /tmp/ragguard-external --max-fpr .05

Network access occurs only in the explicit import command. Sources and licenses are
pinned in external-sources.json; downloaded corpora are kept out of the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import ssl
import sys
import tempfile
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

if __package__:
    from . import run as runner
else:
    import run as runner

ROOT = Path(__file__).resolve().parent
LOCK = ROOT / "external-sources.json"
DATASETS = ("notinject", "injecagent-base", "injecagent-enhanced")
FLOORS = ("info", "low", "medium", "high", "critical")
LIMITATIONS = [
    "Text detector evaluation, not end-to-end agent attack success or utility.",
    "NotInject contains only benign examples; InjecAgent contains only attacks.",
    "Pooled precision is dependent on the artificial source/class mix, not deployment prevalence.",
    "Cases share templates/families; row-level Wilson intervals are descriptive "
    "and may be too narrow.",
    "Public datasets may have appeared in model training; independence is not established.",
    "NotInject trigger components form only two groups (246 dev / 93 holdout); "
    "this strict leakage safeguard creates a domain shift and a very small effective sample.",
]


def digest(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


def read_lock() -> dict[str, Any]:
    lock = json.loads(LOCK.read_text(encoding="utf-8"))
    if lock.get("schema_version") != 1:
        raise ValueError("unsupported external source lock")
    return lock


def source_path(cache: Path, source: dict[str, Any], item: dict[str, Any]) -> Path:
    path = cache / "raw" / source["id"] / item["path"]
    if not path.resolve().is_relative_to((cache / "raw").resolve()):
        raise ValueError("source path escapes cache")
    return path


def verify_file(path: Path, item: dict[str, Any]) -> bytes:
    raw = path.read_bytes()
    if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
        raise ValueError(f"source integrity mismatch: {path.name}")
    return raw


def fetch_sources(cache: Path, lock: dict[str, Any], *, download: bool = True) -> None:
    """Download only exact pinned URLs, with TLS verification and size/hash checks."""
    for source in lock["sources"]:
        for item in source["files"]:
            path = source_path(cache, source, item)
            if path.exists():
                verify_file(path, item)
                continue
            if not download:
                raise ValueError(f"missing offline source: {item['path']}")
            if not item["url"].startswith("https://raw.githubusercontent.com/"):
                raise ValueError("unexpected source host")
            request = urllib.request.Request(item["url"], headers={"User-Agent": "ragguard-evals"})
            with urllib.request.urlopen(
                request, timeout=60, context=ssl.create_default_context()
            ) as r:
                raw = r.read(item["bytes"] + 1)
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha256"]:
                raise ValueError(f"download integrity mismatch: {item['path']}")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)


def read_source(cache: Path, lock: dict[str, Any], name: str, filename: str) -> Any:
    source = next(item for item in lock["sources"] if item["id"] == name)
    item = next(item for item in source["files"] if item["path"] == filename)
    return json.loads(verify_file(source_path(cache, source, item), item))


def trigger_components(rows: list[dict[str, Any]]) -> list[str]:
    """Group all prompts linked by any shared trigger; do not leak derivatives."""
    parents: dict[str, str] = {}

    def find(word: str) -> str:
        parents.setdefault(word, word)
        if parents[word] != word:
            parents[word] = find(parents[word])
        return parents[word]

    words = [[word.casefold().strip() for word in row["word_list"]] for row in rows]
    for group in words:
        if not group or any(not word for word in group):
            raise ValueError("NotInject requires nonempty trigger words")
        for word in group:
            roots = sorted((find(group[0]), find(word)))
            parents[roots[1]] = roots[0]
    return [digest(find(group[0])) for group in words]


def convert_sources(cache: Path, lock: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Preserve upstream text verbatim; source/family groups determine the split."""
    converted: dict[str, list[dict[str, Any]]] = {name: [] for name in DATASETS}
    rows = []
    identities = []
    for subset in ("one", "two", "three"):
        part = read_source(cache, lock, "notinject", f"datasets/NotInject_{subset}.json")
        rows.extend(part)
        identities.extend((subset, index) for index in range(len(part)))
    groups = trigger_components(rows)
    counts = Counter(groups)
    if len(counts) < 2:
        raise ValueError("NotInject cannot form two trigger-disjoint partitions")
    # The published 339 rows form only two connected trigger components. Assign
    # the largest to dev before inspecting outcomes; retain the smaller as holdout.
    dev_group = sorted(counts, key=lambda group: (-counts[group], group))[0]
    for row, (subset, index), group in zip(rows, identities, groups, strict=True):
        converted["notinject"].append(
            {
                "id": f"notinject-{subset}-{index:03}",
                "text": row["prompt"],
                "metadata": None,
                "label": "benign",
                "category": row["category"],
                "split": "dev" if group == dev_group else "holdout",
                "notes": f"Verbatim NotInject {subset}-trigger subset row {index}; benign-only.",
                "source_id": "notinject",
                "origin_id": digest(row["prompt"]),
                "split_group": group,
            }
        )
    for variant in ("base", "enhanced"):
        for attack in ("dh", "ds"):
            rows = read_source(
                cache, lock, "injecagent", f"data/test_cases_{attack}_{variant}.json"
            )
            for index, row in enumerate(rows):
                # Same attack tool family stays together across 17 user-tool wrappers
                # and across base/enhanced variants. No outcome-dependent split tuning.
                group = digest(sorted(row["Attacker Tools"]))
                split = "holdout" if int(group[:8], 16) % 100 < 30 else "dev"
                converted[f"injecagent-{variant}"].append(
                    {
                        "id": f"injecagent-{attack}-{variant}-{index:04}",
                        "text": row["Tool Response"],
                        "metadata": None,
                        "label": "attack",
                        "category": row["Attack Type"],
                        "split": split,
                        "notes": f"Verbatim Tool Response from {attack}/{variant} row {index}; "
                        "original user task and agent are not executed.",
                        "source_id": "injecagent",
                        "origin_id": digest([row["User Tool"], row["Attacker Instruction"]]),
                        "split_group": group,
                        "variant": variant,
                    }
                )
    entries = [entry for corpus in converted.values() for entry in corpus]
    for entry in entries:
        runner.validate_entry(entry)
    runner.validate_split_groups(entries)
    return converted


def import_corpora(cache: Path, *, download: bool = True) -> Path:
    lock = read_lock()
    fetch_sources(cache, lock, download=download)
    corpora = convert_sources(cache, lock)
    manifest = {"schema_version": 1, "source_lock_sha256": digest(lock), "corpora": []}
    for name, entries in corpora.items():
        expected = lock["derived_corpora"][name]
        holdout = runner.filter_split(entries, "holdout")
        if (
            runner.corpus_digest(entries) != expected["corpus_sha256"]
            or runner.corpus_digest(holdout) != expected["holdout_sha256"]
        ):
            raise ValueError(f"derived corpus changed: {name}; review importer/source lock")
        source_id = "notinject" if name == "notinject" else "injecagent"
        source = next(item for item in lock["sources"] if item["id"] == source_id)
        path = cache / "converted" / f"{name}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "".join(json.dumps(entry, ensure_ascii=False) + "\n" for entry in entries),
            encoding="utf-8",
        )
        manifest["corpora"].append(
            {
                "path": path.name,
                "mode": "documents",
                "holdout_count": len(holdout),
                "holdout_sha256": runner.corpus_digest(holdout),
                "provenance": {
                    "kind": "external",
                    "source": source["repository"],
                    "license": "MIT",
                    "revision": source["revision"],
                    "collection_method": "Pinned original benchmark JSON; verbatim text; "
                    "derived labels and group-disjoint splits.",
                },
            }
        )
    path = cache / "converted" / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return path


def load_imported(cache: Path, name: str) -> list[dict[str, Any]]:
    """Check full input identity as well as frozen holdout before evaluation."""
    path = cache / "converted" / f"{name}.jsonl"
    runner.verify_manifest([path], path.parent / "manifest.json", "documents")
    entries = runner.load_corpus([path])
    if runner.corpus_digest(entries) != read_lock()["derived_corpora"][name]["corpus_sha256"]:
        raise ValueError(f"imported corpus changed: {name}")
    return entries


def make_guard(floor: str = "medium") -> Any:
    from ragguard import RAGPipelineGuard

    rank = {value: i for i, value in enumerate(FLOORS)}
    return RAGPipelineGuard(
        auto_reject=True,
        review_floor=floor,
        blocking_severities=[value for value in ("high", "critical") if rank[value] >= rank[floor]],
    )


def provenance() -> dict[str, Any]:
    lock = read_lock()
    return {
        "source_lock_sha256": digest(lock),
        "sources": lock["sources"],
        "measured_at_utc": datetime.now(timezone.utc).isoformat(),
        "implementation_files_sha256": {
            str(path.relative_to(ROOT.parent)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted((ROOT.parent / "ragguard").rglob("*.py"))
        },
        "evaluation_files_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (ROOT / "run.py", ROOT / "external.py")
        },
        "ruleset_version": runner.ruleset_version(),
        "runtime": {"python": platform.python_version(), "platform": platform.platform()},
        "limitations": LIMITATIONS,
    }


def evaluate_corpora(cache: Path, output: Path) -> dict[str, Any]:
    report = {**provenance(), "evaluation": "external_text_classifier", "datasets": {}}
    for name in DATASETS:
        entries = load_imported(cache, name)
        records = runner.run_entries(entries, make_guard())
        report["datasets"][name] = {
            "corpus_sha256": runner.corpus_digest(entries),
            "review_floor": "medium",
            "source_groups": len({entry["split_group"] for entry in entries}),
            "group_counts_by_split": {
                split: len({entry["split_group"] for entry in entries if entry["split"] == split})
                for split in ("dev", "holdout")
            },
            "splits": {
                split: runner.summarize(runner.filter_split(records, split))
                for split in runner.SPLITS
            },
            "results_sha256": runner.corpus_digest(
                [
                    {key: value for key, value in record.items() if key != "latency_ms"}
                    for record in records
                ]
            ),
        }
    write_report(output, report)
    return report


def select_floor(
    dev: list[dict[str, Any]], max_fpr: float
) -> tuple[str | None, list[dict[str, Any]]]:
    """Fit only on dev; finite ordinal policy choices are not continuous detector scores."""
    if not math.isfinite(max_fpr) or not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be finite and between 0 and 1")
    if any(entry["split"] != "dev" for entry in dev):
        raise ValueError("calibration may only inspect dev examples")
    if {entry["label"] for entry in dev} != {"attack", "benign"}:
        raise ValueError("calibration requires both attack and benign dev examples")
    candidates = []
    for floor in FLOORS:
        summary = runner.evaluate(dev, make_guard(floor))
        counts = summary["confusion"]
        actual_fpr = counts["fp"] / (counts["fp"] + counts["tn"])
        candidates.append(
            {"review_floor": floor, "dev": summary, "eligible": actual_fpr <= max_fpr}
        )
    eligible = [candidate for candidate in candidates if candidate["eligible"]]
    if not eligible:
        return None, candidates
    # Maximize dev recall, then minimize dev FPR, then use the stricter floor.
    selected = max(
        eligible,
        key=lambda candidate: (
            candidate["dev"]["overall"]["attack_detection_rate"],
            -candidate["dev"]["overall"]["benign_false_positive_rate"],
            FLOORS.index(candidate["review_floor"]),
        ),
    )
    return selected["review_floor"], candidates


def calibrate(cache: Path, output: Path, max_fpr: float) -> dict[str, Any]:
    benign = load_imported(cache, "notinject")
    report = {
        **provenance(),
        "evaluation": "dev_calibrated_severity_policy",
        "max_fpr": max_fpr,
        "ceiling_definition": "empirical dev FPR; not a certified population bound",
        "policy_selection": "maximize dev recall, minimize dev FPR, prefer stricter floor",
        "variants": {},
    }
    for variant in ("base", "enhanced"):
        entries = benign + load_imported(cache, f"injecagent-{variant}")
        runner.validate_split_groups(entries)
        floor, candidates = select_floor(runner.filter_split(entries, "dev"), max_fpr)
        result = {
            "selected_floor": floor,
            "dev_candidates": candidates,
            "status": "no_feasible_policy" if floor is None else "selected",
        }
        # Holdout is scanned only after selection; no candidate scores from it are consulted.
        if floor is not None:
            summary = runner.evaluate(runner.filter_split(entries, "holdout"), make_guard(floor))
            counts = summary["confusion"]
            actual_fpr = counts["fp"] / (counts["fp"] + counts["tn"])
            result.update(
                {
                    "holdout": summary,
                    "holdout_ceiling_met": actual_fpr <= max_fpr,
                    "heldout_recall_at_selected_policy": summary["overall"][
                        "attack_detection_rate"
                    ],
                }
            )
        report["variants"][variant] = result
    write_report(output, report)
    return report


def write_report(output: Path, report: dict[str, Any]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("import", "evaluate", "calibrate"))
    parser.add_argument(
        "--cache-dir", type=Path, default=Path(tempfile.gettempdir()) / "ragguard-external"
    )
    parser.add_argument("--output", type=Path, help="report JSON path")
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument(
        "--offline", action="store_true", help="import verified cached sources only"
    )
    args = parser.parse_args(argv)
    try:
        if args.command == "import":
            print(import_corpora(args.cache_dir, download=not args.offline))
        elif args.command == "evaluate":
            output = args.output or ROOT / "reports" / "external-baseline.json"
            evaluate_corpora(args.cache_dir, output)
            print(output)
        else:
            output = args.output or ROOT / "reports" / "external-calibration.json"
            calibrate(args.cache_dir, output, args.max_fpr)
            print(output)
    except (ValueError, OSError, KeyError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    sys.exit(main())
