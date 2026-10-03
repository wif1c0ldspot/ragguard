"""Measure a pinned offline classifier on external corpora without truncating inputs.

Score calibration uses dev rows only. Errors stay unknown and remain in all-row
conservative bounds; a token-budget refusal is not attack detection.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import math
import os
import time
from collections import Counter
from pathlib import Path
from typing import Any, Protocol

if __package__:
    from . import external, run
else:
    import external
    import run

MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"
MODEL_REVISION = "90c9989b1a342275dd0d1a95aad283c04e075671"


class Scorer(Protocol):
    def score(self, text: str) -> tuple[float, int]: ...


def select_rows(
    entries: list[dict[str, Any]],
    *,
    seed: str,
    limit_per_split: int,
) -> list[dict[str, Any]]:
    """Hash-select before scoring; origin identities keep base/enhanced paired."""
    if type(limit_per_split) is not int or limit_per_split < 0:
        raise ValueError("limit_per_split must be nonnegative (0 means full corpus)")
    selected = []
    for split in ("dev", "holdout"):
        rows = run.filter_split(entries, split)
        rows.sort(
            key=lambda row: (external.digest([seed, row["source_id"], row["origin_id"]]), row["id"])
        )
        selected.extend(rows[:limit_per_split] if limit_per_split else rows)
    return selected


def score_rows(
    entries: list[dict[str, Any]],
    scorer: Scorer,
    *,
    progress: bool = False,
) -> list[dict[str, Any]]:
    """Pass the entire text to the adapter once; persist no input text or error messages."""
    guard = external.make_guard()
    records = []
    for index, entry in enumerate(entries):
        rule_start = time.perf_counter()
        rule = guard.ingest(entry["text"], entry["metadata"], id=entry["id"])
        rule_ms = (time.perf_counter() - rule_start) * 1000
        record = {
            key: entry[key]
            for key in ("id", "label", "category", "split", "source_id", "origin_id", "split_group")
        }
        record.update(
            {
                "text_sha256": hashlib.sha256(entry["text"].encode()).hexdigest(),
                "input_chars": len(entry["text"]),
                "rule_decision": rule["decision"],
                "rule_families": rule["families"],
                "rule_scan_complete": rule["scan_complete"],
                "rule_incomplete_reasons": rule["incomplete_reasons"],
                "rule_latency_ms": rule_ms,
            }
        )
        started = time.perf_counter()
        try:
            score, tokens = scorer.score(entry["text"])
            if (
                type(score) not in (float, int)
                or not math.isfinite(score)
                or not 0 <= score <= 1
                or type(tokens) is not int
                or tokens < 1
            ):
                raise ValueError("invalid scorer output")
            record.update(status="ok", score=float(score), input_tokens=tokens)
        except Exception as exc:
            # Adapter errors can include sensitive input/provider strings: retain
            # only the class, never text or a fabricated safe/unsafe prediction.
            record.update(
                status="error", score=None, input_tokens=None, error_type=type(exc).__name__
            )
        record["model_latency_ms"] = (time.perf_counter() - started) * 1000
        records.append(record)
        if progress and (index + 1) % 16 == 0:
            print(f"scored {index + 1}/{len(entries)} ({entries[0]['split']})", flush=True)
    return records


def choose_threshold(dev: list[dict[str, Any]], max_fpr: float) -> dict[str, Any]:
    """Choose max recall under a conservative dev FPR ceiling with unknown errors.

    Benign errors consume the FPR budget; attack errors never earn recall. Ties
    prefer the larger threshold. Equality to threshold is a positive prediction.
    """
    if not math.isfinite(max_fpr) or not 0 <= max_fpr <= 1:
        raise ValueError("max_fpr must be finite within [0, 1]")
    if any(row["split"] != "dev" for row in dev):
        raise ValueError("threshold calibration may only use dev rows")
    attacks = [row for row in dev if row["label"] == "attack"]
    benign = [row for row in dev if row["label"] == "benign"]
    if not attacks or not benign:
        raise ValueError("calibration requires both attack and benign dev rows")
    valid = [row for row in dev if row["status"] == "ok"]
    if not valid:
        return {"status": "unavailable", "reason": "no_scored_dev_rows", "threshold": None}
    scores = {row["score"] for row in valid}
    candidates = {0.0, 1.0, *scores}
    candidates.update(math.nextafter(score, 1.0) for score in scores if score < 1)
    errors_benign = sum(row["status"] != "ok" for row in benign)
    feasible = []
    for threshold in sorted(candidates):
        tp = sum(row["status"] == "ok" and row["score"] >= threshold for row in attacks)
        fp = sum(row["status"] == "ok" and row["score"] >= threshold for row in benign)
        fpr_upper = (fp + errors_benign) / len(benign)
        if fpr_upper <= max_fpr:
            feasible.append((tp / len(attacks), threshold, fpr_upper, tp, fp))
    if not feasible:
        return {
            "status": "unavailable",
            "reason": "no_feasible_dev_threshold",
            "threshold": None,
            "benign_errors": errors_benign,
        }
    recall, threshold, fpr_upper, tp, fp = max(feasible)
    return {
        "status": "calibrated",
        "threshold": threshold,
        "dev_recall_lower_bound": recall,
        "dev_fpr_upper_bound": fpr_upper,
        "dev_tp": tp,
        "dev_fp": fp,
        "dev_attack_count": len(attacks),
        "dev_benign_count": len(benign),
        "dev_error_count": len(dev) - len(valid),
        "candidates_considered": len(candidates),
        "calibration_records_sha256": external.digest(
            [{key: value for key, value in row.items() if "latency" not in key} for row in dev]
        ),
    }


def summarize_mode(
    rows: list[dict[str, Any]],
    *,
    mode: str,
    threshold: float,
) -> dict[str, Any]:
    if mode not in ("rules", "model", "combined"):
        raise ValueError("unknown evaluation mode")

    def is_valid(row: dict[str, Any]) -> bool:
        if mode == "rules":
            return row["rule_scan_complete"]
        if mode == "model":
            return row["status"] == "ok"
        return row["status"] == "ok" and row["rule_scan_complete"]

    valid = [row for row in rows if is_valid(row)]
    records = []
    for row in valid:
        if mode == "rules":
            decision = row["rule_decision"]
        else:
            flagged = row["score"] >= threshold
            if mode == "combined":
                flagged |= row["rule_decision"] != "accept"
            # This is a flagging comparison, not a simulated downstream block.
            decision = "review" if flagged else "accept"
        records.append(
            {
                "id": row["id"],
                "label": row["label"],
                "category": row["category"],
                "split": row["split"],
                "decision": decision,
                # This list contains only completed rows for the selected mode.
                # Missing completeness is deliberately unknown to run.summarize.
                "scan_complete": True,
                "error_type": None,
                "families": [],
                "latency_ms": row["rule_latency_ms"]
                if mode == "rules"
                else row["model_latency_ms"]
                + (row["rule_latency_ms"] if mode == "combined" else 0),
            }
        )
    summary = run.summarize(records)
    errors = [row for row in rows if not is_valid(row)]
    counts = Counter(row["label"] for row in rows)
    unknown = Counter(row["label"] for row in errors)
    tp, fp = summary["confusion"]["tp"], summary["confusion"]["fp"]
    bounds = {}
    for metric, positive, label in (
        ("attack_detection_rate", tp, "attack"),
        ("benign_false_positive_rate", fp, "benign"),
    ):
        bounds[metric] = (
            [positive / counts[label], (positive + unknown[label]) / counts[label]]
            if counts[label]
            else None
        )
    return {
        "scored_only": summary,
        "selected_count": len(rows),
        "evaluated_count": len(valid),
        "unscored_count": len(errors),
        "unscored_by_label": dict(unknown),
        "operational_withholding": {
            "rule_incomplete_count": sum(not row["rule_scan_complete"] for row in rows),
            "model_error_count": sum(row["status"] != "ok" for row in rows),
            "credited_as_attack_detection": False,
        },
        "full_denominator_bounds": bounds,
        "coverage": len(valid) / len(rows) if rows else None,
        "semantic_positive_action": "review, not measured downstream blocking",
    }


def evaluate(
    datasets: dict[str, list[dict[str, Any]]],
    scorer: Scorer,
    *,
    max_fpr: float,
    progress: bool = False,
) -> dict[str, Any]:
    run.validate_split_groups([row for rows in datasets.values() for row in rows])
    dev = {
        name: score_rows(run.filter_split(rows, "dev"), scorer, progress=progress)
        for name, rows in datasets.items()
    }
    calibrations = {
        variant: choose_threshold(dev["notinject"] + dev[f"injecagent-{variant}"], max_fpr)
        for variant in ("base", "enhanced")
    }
    # Holdout is scored only after the dev operating points have been frozen.
    heldout = {
        name: score_rows(run.filter_split(rows, "holdout"), scorer, progress=progress)
        for name, rows in datasets.items()
    }
    results = {}
    for variant, calibration in calibrations.items():
        rows = heldout["notinject"] + heldout[f"injecagent-{variant}"]
        result = {
            "calibration": calibration,
            "rules_all_selected": summarize_mode(rows, mode="rules", threshold=0),
            "rules_on_model_scored_subset": summarize_mode(
                [row for row in rows if row["status"] == "ok"], mode="rules", threshold=0
            ),
        }
        if calibration["threshold"] is not None:
            for mode in ("model", "combined"):
                result[mode] = summarize_mode(rows, mode=mode, threshold=calibration["threshold"])
                bounds = result[mode]["full_denominator_bounds"]["benign_false_positive_rate"]
                result[mode]["holdout_fpr_ceiling_met_conservatively"] = (
                    bounds is not None and bounds[1] <= max_fpr
                )
        else:
            result["model"] = result["combined"] = {"status": "unavailable_no_dev_calibration"}
        results[variant] = result
    records = {name: dev[name] + heldout[name] for name in datasets}
    return {
        "variants": results,
        "score_records": records,
        "scoring_errors": dict(
            Counter(
                row.get("error_type", "unknown")
                for rows in records.values()
                for row in rows
                if row["status"] != "ok"
            )
        ),
    }


def runtime_provenance(model_cache: Path, model_id: str, revision: str) -> dict[str, Any]:
    snapshot = model_cache / ("models--" + model_id.replace("/", "--")) / "snapshots" / revision
    if not snapshot.is_dir():
        raise ValueError("pinned model snapshot is not present in the configured offline cache")
    hashes = {}
    for path in sorted(snapshot.rglob("*")):
        if path.is_file():
            checksum = hashlib.sha256()
            with path.open("rb") as handle:
                for block in iter(lambda: handle.read(1024 * 1024), b""):
                    checksum.update(block)
            hashes[str(path.relative_to(snapshot))] = checksum.hexdigest()
    return {
        "model_id": model_id,
        "model_revision": revision,
        "model_files_sha256": hashes,
        "libraries": {
            name: importlib.metadata.version(name)
            for name in (
                "torch",
                "transformers",
                "sentencepiece",
                "tokenizers",
                "safetensors",
                "huggingface-hub",
            )
        },
        "evaluation_code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--cache-dir", type=Path, required=True, help="verified external corpus cache"
    )
    parser.add_argument(
        "--model-cache", type=Path, required=True, help="provisioned offline HF cache"
    )
    parser.add_argument("--model-id", default=MODEL_ID)
    parser.add_argument("--model-revision", default=MODEL_REVISION)
    parser.add_argument(
        "--limit-per-split", type=int, default=32, help="per dataset/split; 0 means all"
    )
    parser.add_argument("--seed", default="ragguard-semantic-2026-10-03")
    parser.add_argument("--max-fpr", type=float, default=0.05)
    parser.add_argument("--max-tokens", type=int, default=512)
    parser.add_argument("--threads", type=int, default=2)
    parser.add_argument("--output", type=Path, default=external.ROOT / "reports" / "semantic.json")
    args = parser.parse_args()
    if not math.isfinite(args.max_fpr) or not 0 <= args.max_fpr <= 1 or args.threads < 1:
        parser.error("max-fpr must be in [0, 1] and threads must be positive")
    os.environ["HF_HUB_CACHE"] = str(args.model_cache.resolve())
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    try:
        import torch

        from ragguard.local_detector import LocalDetectorConfig, LocalPromptInjectionDetector

        torch.set_num_threads(args.threads)
        model = runtime_provenance(args.model_cache, args.model_id, args.model_revision)
        sources = {name: external.load_imported(args.cache_dir, name) for name in external.DATASETS}
        datasets = {
            name: select_rows(rows, seed=args.seed, limit_per_split=args.limit_per_split)
            for name, rows in sources.items()
        }
        scorer = LocalPromptInjectionDetector(
            LocalDetectorConfig(
                model_revision=args.model_revision,
                model_id=args.model_id,
                max_tokens=args.max_tokens,
            )
        )
        report = {
            **external.provenance(),
            "evaluation": "measured_local_semantic_text_classifier",
            "model": model,
            "configuration": {
                "max_fpr": args.max_fpr,
                "max_tokens": args.max_tokens,
                "threads": args.threads,
                "device": "cpu",
                "truncation": False,
                "max_input_chars": 20000,
            },
            "selection": {
                "seed": args.seed,
                "limit_per_dataset_split": args.limit_per_split,
                "method": "SHA256(seed, source_id, origin_id); select before scoring",
                "datasets": {
                    name: {
                        "available": len(sources[name]),
                        "selected": len(rows),
                        "selected_corpus_sha256": run.corpus_digest(rows),
                    }
                    for name, rows in datasets.items()
                },
            },
            **evaluate(datasets, scorer, max_fpr=args.max_fpr, progress=True),
        }
        report["limitations"] += [
            "Model training overlap with these public datasets is unknown; our calibration split "
            "is not independent of model pretraining.",
            "Model card describes an English classifier; "
            "multilingual generalization is not established.",
            "Full inputs exceeding adapter limits remain unscored; errors are never counted safe "
            "or credited as detected attacks.",
            "Combined means rules OR calibrated model flags; "
            "its FPR ceiling is checked separately.",
            (
                "A bounded subset was selected before outcomes; this is not the full benchmark."
                if args.limit_per_split
                else "All rows of each pinned external corpus were evaluated."
            ),
        ]
        external.write_report(args.output, report)
        print(args.output)
    except (ValueError, OSError, ImportError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
