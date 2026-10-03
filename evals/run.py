"""Run the ragguard evaluation corpus and report detection metrics.

Usage::

    python evals/run.py [--split dev|holdout|all] [--json out.json]
                        [--markdown out.md] [--check evals/thresholds.json]
                        [--review-floor SEVERITY]

Standard library only (plus ``ragguard``). Importable: ``evaluate(entries, guard)``.
"""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import math
import platform
import sys
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

EVALS_DIR = Path(__file__).resolve().parent
CORPUS_DIR = EVALS_DIR / "corpus"
CORPUS_FILES = (CORPUS_DIR / "attacks.jsonl", CORPUS_DIR / "benign.jsonl")
CHUNK_FILES = (CORPUS_DIR / "chunks.jsonl",)
MANIFEST_FILE = EVALS_DIR / "manifest.json"
SPLITS = ("dev", "holdout", "all")
REQUIRED_FIELDS = ("id", "text", "metadata", "label", "category", "split", "notes")


# --------------------------------------------------------------------------- corpus


def corpus_digest(entries: Sequence[dict[str, Any]]) -> str:
    """Hash canonical records by ID; file formatting/order does not affect identity."""
    encoded = json.dumps(sorted(entries, key=lambda item: item["id"]),
                         sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_entry(entry: Any, *, mode: str = "documents") -> None:
    """Validate imported labels/types before they can silently skew metrics."""
    if not isinstance(entry, dict):
        raise ValueError("entry must be an object")
    required = set(REQUIRED_FIELDS)
    if mode == "chunks":
        required = (required - {"text", "metadata"}) | {"chunks", "window_chars"}
    missing = required - entry.keys()
    if missing:
        raise ValueError(f"missing fields {sorted(missing)}")
    for name in ("id", "category", "notes"):
        if not isinstance(entry[name], str) or not entry[name].strip():
            raise ValueError(f"{name} must be a nonempty string")
    if entry["label"] not in ("attack", "benign"):
        raise ValueError("label must be attack or benign")
    if entry["split"] not in ("dev", "holdout"):
        raise ValueError("split must be dev or holdout")
    chunks = entry.get("chunks") if mode == "chunks" else [entry]
    if not isinstance(chunks, list) or not chunks:
        raise ValueError("chunks must be a nonempty list")
    if mode == "chunks" and (type(entry["window_chars"]) is not int or entry["window_chars"] < 1):
        raise ValueError("window_chars must be a positive integer")
    for chunk in chunks:
        if not isinstance(chunk, dict) or not isinstance(chunk.get("text"), str):
            raise ValueError("text must be a string")
        if chunk.get("metadata") is not None and not isinstance(chunk["metadata"], dict):
            raise ValueError("metadata must be an object or null")


def load_corpus(
    paths: Iterable[Path] = CORPUS_FILES, *, mode: str = "documents",
) -> list[dict[str, Any]]:
    """Load and validate JSONL files, rejecting duplicate IDs across files."""
    entries: list[dict[str, Any]] = []
    ids: set[str] = set()
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                    validate_entry(entry, mode=mode)
                    if entry["id"] in ids:
                        raise ValueError(f"duplicate id {entry['id']!r}")
                except (ValueError, TypeError) as exc:
                    raise ValueError(f"{path.name}:{lineno}: {exc}") from exc
                ids.add(entry["id"])
                entries.append(entry)
    if not entries:
        raise ValueError("corpus must not be empty")
    validate_split_groups(entries)
    return entries


def verify_manifest(paths: Sequence[Path], manifest_path: Path, mode: str) -> list[dict[str, Any]]:
    """Verify frozen holdout content and explicit provenance for every input file.

    Hashes detect accidental edits, not malicious replacement of the manifest.
    External source/license declarations are supplied by the importer, not certified.
    """
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
            or not isinstance(manifest.get("corpora"), list)):
        raise ValueError("unsupported corpus manifest")
    indexed = {}
    for item in manifest["corpora"]:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("manifest entries require a path string")
        path = (manifest_path.parent / item["path"]).resolve()
        if path in indexed:
            raise ValueError(f"duplicate manifest path {item['path']}")
        indexed[path] = item
    verified = []
    for path in paths:
        item = indexed.get(path.resolve())
        if item is None or item.get("mode") != mode:
            raise ValueError(f"{path.name}: missing manifest entry for mode {mode}")
        provenance = item.get("provenance")
        if (not isinstance(provenance, dict)
                or provenance.get("kind") not in ("synthetic", "external")):
            raise ValueError(f"{path.name}: provenance kind must be synthetic or external")
        for field in ("source", "license", "collection_method"):
            if not isinstance(provenance.get(field), str) or not provenance[field].strip():
                raise ValueError(f"{path.name}: missing provenance {field}")
        entries = load_corpus([path], mode=mode)
        holdout = filter_split(entries, "holdout")
        if not holdout or len(holdout) != item.get("holdout_count"):
            raise ValueError(f"{path.name}: frozen holdout count changed or is empty")
        if corpus_digest(holdout) != item.get("holdout_sha256"):
            raise ValueError(f"{path.name}: frozen holdout SHA-256 mismatch")
        verified.append({"path": item["path"], "provenance": provenance,
                         "holdout_count": len(holdout), "holdout_sha256": corpus_digest(holdout)})
    return verified


def filter_split(items: Iterable[dict[str, Any]], split: str) -> list[dict[str, Any]]:
    if split == "all":
        return list(items)
    return [item for item in items if item["split"] == split]


# --------------------------------------------------------------------------- guard


def build_guard(review_floor: str | None = None) -> Any:
    """Construct ``RAGPipelineGuard(auto_reject=True)``.

    ``review_floor`` is passed only if the installed guard accepts it, so the
    runner works before and after that constructor parameter exists.
    """
    from ragguard import RAGPipelineGuard

    kwargs: dict[str, Any] = {"auto_reject": True}
    if review_floor is not None:
        params = inspect.signature(RAGPipelineGuard.__init__).parameters
        if "review_floor" not in params:
            raise SystemExit("--review-floor given but RAGPipelineGuard has no review_floor")
        kwargs["review_floor"] = review_floor
    return RAGPipelineGuard(**kwargs)


def ruleset_version() -> str | None:
    try:
        from ragguard import RULESET_VERSION
    except ImportError:  # pragma: no cover - only without ragguard installed
        return None
    return str(RULESET_VERSION)


# --------------------------------------------------------------------------- metrics


def run_entries(
    entries: Sequence[dict[str, Any]], guard: Any, *, mode: str = "documents",
) -> list[dict[str, Any]]:
    """Ingest each entry once; return one record per entry (no text)."""
    records = []
    for entry in entries:
        start = time.perf_counter()
        decisions = []
        error_type = None
        try:
            if mode == "chunks":
                from ragguard import Document

                batch = guard.evaluate_chunks([
                    Document(chunk["text"], metadata=chunk.get("metadata"), id=f"{entry['id']}:{i}")
                    for i, chunk in enumerate(entry["chunks"])
                ], window_chars=entry["window_chars"])
                decisions = [document.decision.value for document in batch.documents]
                result = {
                    "decision": ("reject" if "reject" in decisions else
                                 "review" if "review" in decisions else "accept"),
                    "scan_complete": all(document.scan_complete for document in batch.documents),
                    "families": [family for document in batch.documents
                                 for family in document.families],
                }
            else:
                result = guard.ingest(entry["text"], entry.get("metadata"), id=entry["id"])
        except Exception as exc:
            # Keep failed cases in the denominator without retaining sensitive messages.
            result = {"decision": "unknown", "families": [], "scan_complete": False}
            error_type = type(exc).__name__
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        records.append({
            "id": entry["id"],
            "label": entry["label"],
            "category": entry["category"],
            "split": entry["split"],
            "decision": str(result["decision"]),
            "scan_complete": result.get("scan_complete") is True,
            "error_type": error_type,
            "families": sorted(set(result.get("families") or [])),
            "latency_ms": elapsed_ms,
            **({"chunk_decisions": decisions} if mode == "chunks" else {}),
        })
    return records


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def wilson_interval(successes: int, total: int) -> list[float] | None:
    """Two-sided 95% Wilson interval; descriptive if observations are correlated."""
    if not total:
        return None
    z = 1.959963984540054
    p = successes / total
    scale = 1 + z * z / total
    center = (p + z * z / (2 * total)) / scale
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / scale
    return [round(max(0.0, center - half), 6), round(min(1.0, center + half), 6)]


def validate_split_groups(entries: Sequence[dict[str, Any]]) -> None:
    """Keep all derivatives of an external source/family on one side of the split."""
    splits: dict[tuple[str, str, str], str] = {}
    for entry in entries:
        source = entry.get("source_id")
        if source is None:
            continue
        if not isinstance(source, str) or not source:
            raise ValueError("source_id must be a nonempty string")
        for field in ("origin_id", "split_group"):
            value = entry.get(field)
            if not isinstance(value, str) or not value:
                raise ValueError(f"external records require nonempty {field}")
            key = (source, field, value)
            if key in splits and splits[key] != entry["split"]:
                raise ValueError(f"source/family leakage across splits: {source}/{field}/{value}")
            splits[key] = entry["split"]


def _percentile(values: Sequence[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    rank = max(0, math.ceil(pct / 100.0 * len(ordered)) - 1)
    return round(ordered[rank], 3)


def summarize(records: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate per-entry records into the metrics report."""
    attacks = [r for r in records if r["label"] == "attack"]
    benign = [r for r in records if r["label"] == "benign"]
    def valid(record: dict[str, Any]) -> bool:
        return record.get("scan_complete") is True and not record.get("error_type")

    scored_attacks = [r for r in attacks if valid(r)]
    scored_benign = [r for r in benign if valid(r)]
    unknown_attacks = len(attacks) - len(scored_attacks)
    unknown_benign = len(benign) - len(scored_benign)
    detected = [r for r in scored_attacks if r["decision"] != "accept"]
    blocked = [r for r in scored_attacks if r["decision"] == "reject"]
    flagged = [r for r in scored_benign if r["decision"] != "accept"]
    false_blocks = [r for r in scored_benign if r["decision"] == "reject"]
    latencies = [r["latency_ms"] for r in records]
    tp, fp = len(detected), len(flagged)
    fn, tn = len(scored_attacks) - tp, len(scored_benign) - fp

    def by_category(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for category in sorted({r["category"] for r in rows}):
            group = [r for r in rows if r["category"] == category]
            hits = sum(1 for r in group if valid(r) and r["decision"] != "accept")
            rejects = sum(1 for r in group if valid(r) and r["decision"] == "reject")
            out[category] = {
                "count": len(group),
                "unknown": sum(not valid(r) for r in group),
                "flagged": hits,
                "rejected": rejects,
                key: _rate(hits, len(group)),
            }
        return out

    families: dict[str, dict[str, Any]] = {}
    for family in sorted({f for r in records for f in r["families"]}):
        on_attack = sum(1 for r in scored_attacks if family in r["families"])
        on_benign = sum(1 for r in scored_benign if family in r["families"])
        families[family] = {
            "fires_on_attacks": on_attack,
            "fires_on_benign": on_benign,
            "precision": _rate(on_attack, on_attack + on_benign),
        }

    return {
        "confusion": {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                      "unknown_attack": unknown_attacks, "unknown_benign": unknown_benign,
                      "positive_definition": "completed decision != accept"},
        "rate_denominators": "overall/category rates use all cases (lower bounds when unknown); "
                             "confusion and confidence intervals use completed scans only",
        "coverage": {"total": len(records), "scored": len(scored_attacks) + len(scored_benign),
                     "unknown": unknown_attacks + unknown_benign,
                     "errors": sum(bool(r.get("error_type")) for r in records)},
        "all_case_bounds": {
            "attack_detection_rate": [_rate(tp, len(attacks)),
                                      _rate(tp + unknown_attacks, len(attacks))],
            "benign_false_positive_rate": [_rate(fp, len(benign)),
                                            _rate(fp + unknown_benign, len(benign))],
        },
        "confidence_intervals_95": {
            "method": "Wilson on completed scans; assumes independent Bernoulli observations",
            "attack_detection_rate": wilson_interval(tp, len(scored_attacks)),
            "attack_block_rate": wilson_interval(len(blocked), len(scored_attacks)),
            "benign_false_positive_rate": wilson_interval(fp, len(scored_benign)),
            "benign_false_block_rate": wilson_interval(len(false_blocks), len(scored_benign)),
            "precision": wilson_interval(tp, tp + fp),
        },
        "overall": {
            "precision": _rate(tp, tp + fp),
            "attack_count": len(attacks),
            "benign_count": len(benign),
            "attacks_detected": len(detected),
            "attacks_blocked": len(blocked),
            "benign_flagged": len(flagged),
            "benign_blocked": len(false_blocks),
            "attack_detection_rate": _rate(len(detected), len(attacks)),
            "attack_block_rate": _rate(len(blocked), len(attacks)),
            "benign_false_positive_rate": _rate(len(flagged), len(benign)),
            "benign_false_block_rate": _rate(len(false_blocks), len(benign)),
            "latency_ms": {
                "p50": _percentile(latencies, 50),
                "p95": _percentile(latencies, 95),
                "max": round(max(latencies), 3) if latencies else None,
            },
        },
        "attack_categories": by_category(attacks, "detection_rate"),
        "benign_categories": by_category(benign, "false_positive_rate"),
        "families": families,
        "missed_attack_ids": sorted(r["id"] for r in scored_attacks if r["decision"] == "accept"),
        "unknown_ids": sorted(r["id"] for r in records if not valid(r)),
        "false_positive_benign_ids": sorted(r["id"] for r in flagged),
        "false_block_benign_ids": sorted(r["id"] for r in false_blocks),
    }


def evaluate(entries: Sequence[dict[str, Any]], guard: Any) -> dict[str, Any]:
    """Run ``guard`` over ``entries`` and return the metrics report."""
    return summarize(run_entries(entries, guard))


# --------------------------------------------------------------------------- thresholds


def check_thresholds(
    thresholds: dict[str, Any], reports: dict[str, dict[str, Any]],
) -> list[str]:
    """Return human-readable violations; ``reports`` maps split -> summary.

    Rate thresholds are ``{split: value}``; category thresholds are
    ``{split: {category: value}}``; ``max_p95_latency_ms`` is a scalar checked
    against the ``all`` report. Splits missing from ``reports`` are skipped.
    """
    violations: list[str] = []
    if not isinstance(thresholds, dict):
        return ["thresholds must be an object"]
    overall_rules = (
        ("min_attack_detection_rate", "attack_detection_rate", min),
        ("min_attack_block_rate", "attack_block_rate", min),
        ("max_benign_false_positive_rate", "benign_false_positive_rate", max),
        ("max_benign_false_block_rate", "benign_false_block_rate", max),
    )
    known = {name for name, _, _ in overall_rules} | {
        "min_category_detection_rate", "max_category_false_positive_rate", "max_p95_latency_ms",
    }
    for name in sorted(set(thresholds) - known):
        if not name.startswith("_"):
            violations.append(f"unknown threshold key {name!r}")

    def valid_bound(value: Any, *, latency: bool = False) -> bool:
        try:
            return (type(value) in (int, float) and math.isfinite(value)
                    and value >= 0 and (latency or value <= 1))
        except OverflowError:
            return False

    for name in known & thresholds.keys():
        value = thresholds[name]
        if name == "max_p95_latency_ms":
            if not valid_bound(value, latency=True):
                violations.append(f"{name}: expected finite nonnegative number")
            continue
        if not isinstance(value, dict):
            violations.append(f"{name}: expected split mapping")
            continue
        for split, bounds in value.items():
            if split not in SPLITS:
                violations.append(f"{name}: unknown split {split!r}")
            if "category" in name:
                if not isinstance(bounds, dict) or any(
                    not isinstance(category, str) or not category or not valid_bound(bound)
                    for category, bound in bounds.items()
                ):
                    violations.append(
                        f"{name}[{split}]: expected category mapping with rates in [0, 1]",
                    )
            elif not valid_bound(bounds):
                violations.append(f"{name}[{split}]: expected finite rate in [0, 1]")
    if violations:
        return violations
    if reports and any(report.get("coverage", {}).get("unknown", 0) for report in reports.values()):
        violations.append("incomplete evaluation: unknown cases cannot satisfy quality gates")

    def compare(label: str, actual: float | None, bound: float, kind: Any) -> None:
        if actual is None:
            violations.append(f"{label}: no samples for required metric")
            return
        if kind is min and actual < bound:
            violations.append(f"{label}: {actual:.4f} < minimum {bound}")
        if kind is max and actual > bound:
            violations.append(f"{label}: {actual:.4f} > maximum {bound}")

    for name, metric, kind in overall_rules:
        for split, bound in sorted((thresholds.get(name) or {}).items()):
            if split in reports:
                compare(f"{name}[{split}]", reports[split]["overall"][metric], bound, kind)

    category_rules = (
        ("min_category_detection_rate", "attack_categories", "detection_rate", min),
        ("max_category_false_positive_rate", "benign_categories", "false_positive_rate", max),
    )
    for name, section, metric, kind in category_rules:
        for split, per_category in sorted((thresholds.get(name) or {}).items()):
            if split not in reports:
                continue
            for category, bound in sorted(per_category.items()):
                stats = reports[split][section].get(category)
                if stats is None:
                    violations.append(f"{name}[{split}][{category}]: category not in corpus")
                    continue
                compare(f"{name}[{split}][{category}]", stats[metric], bound, kind)

    max_p95 = thresholds.get("max_p95_latency_ms")
    if max_p95 is not None and "all" in reports:
        p95 = reports["all"]["overall"]["latency_ms"]["p95"]
        compare("max_p95_latency_ms", p95, max_p95, max)
    return violations


# --------------------------------------------------------------------------- output


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def render_markdown(report: dict[str, Any], split: str, version: str | None) -> str:
    o = report["overall"]
    lat = o["latency_ms"]
    lines = [
        f"# ragguard eval — split `{split}`",
        "",
        f"Ruleset version: `{version}`",
        f"Coverage: {report['coverage']['scored']} completed / "
        f"{report['coverage']['total']} total; {report['coverage']['unknown']} unknown.",
        report["rate_denominators"],
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Attacks / benign | {o['attack_count']} / {o['benign_count']} |",
        f"| Attack detection rate (decision != accept) | {_pct(o['attack_detection_rate'])} |",
        f"| Attack block rate (reject) | {_pct(o['attack_block_rate'])} |",
        f"| Benign false-positive rate (!= accept) | {_pct(o['benign_false_positive_rate'])} |",
        f"| Benign false-block rate (reject) | {_pct(o['benign_false_block_rate'])} |",
        f"| Latency p50 / p95 / max (ms) | {lat['p50']} / {lat['p95']} / {lat['max']} |",
        "",
        "## Attack categories",
        "",
        "| Category | n | Detected | Detection rate |",
        "|---|---|---|---|",
    ]
    for name, s in report["attack_categories"].items():
        lines.append(f"| {name} | {s['count']} | {s['flagged']} | {_pct(s['detection_rate'])} |")
    lines += [
        "", "## Benign categories", "", "| Category | n | Flagged | FPR |", "|---|---|---|---|",
    ]
    for name, s in report["benign_categories"].items():
        lines.append(
            f"| {name} | {s['count']} | {s['flagged']} | {_pct(s['false_positive_rate'])} |"
        )
    lines += [
        "", "## Families", "",
        "| Family | Fires on attacks | Fires on benign | Precision |", "|---|---|---|---|",
    ]
    for name, s in report["families"].items():
        lines.append(
            f"| {name} | {s['fires_on_attacks']} | {s['fires_on_benign']} "
            f"| {_pct(s['precision'])} |"
        )
    lines += [
        "",
        f"Missed attacks ({len(report['missed_attack_ids'])}): "
        + (", ".join(report["missed_attack_ids"]) or "none"),
        "",
        f"Benign false positives ({len(report['false_positive_benign_ids'])}): "
        + (", ".join(report["false_positive_benign_ids"]) or "none"),
        "",
    ]
    return "\n".join(lines)


def render_console(report: dict[str, Any], split: str, version: str | None) -> str:
    o = report["overall"]
    lat = o["latency_ms"]
    lines = [
        f"ragguard eval  split={split}  ruleset={version}",
        f"Coverage: {report['coverage']['scored']}/{report['coverage']['total']} complete; "
        f"{report['coverage']['unknown']} unknown (rates are all-case lower bounds)",
        f"  attacks={o['attack_count']}  benign={o['benign_count']}",
        f"  attack detection rate   {_pct(o['attack_detection_rate'])}",
        f"  attack block rate       {_pct(o['attack_block_rate'])}",
        f"  benign FPR              {_pct(o['benign_false_positive_rate'])}",
        f"  benign false-block rate {_pct(o['benign_false_block_rate'])}",
        f"  latency ms p50={lat['p50']} p95={lat['p95']} max={lat['max']}",
        "  attack categories:",
    ]
    for name, s in report["attack_categories"].items():
        lines.append(f"    {name:<26} {s['flagged']:>3}/{s['count']:<3} "
                     f"{_pct(s['detection_rate'])}")
    lines.append("  benign categories (FPR):")
    for name, s in report["benign_categories"].items():
        lines.append(f"    {name:<26} {s['flagged']:>3}/{s['count']:<3} "
                     f"{_pct(s['false_positive_rate'])}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- CLI


def main(
    argv: Sequence[str] | None = None,
    *,
    entries: Sequence[dict[str, Any]] | None = None,
    guard: Any = None,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--split", choices=SPLITS, default="all")
    parser.add_argument("--mode", choices=("documents", "chunks"), default="documents")
    parser.add_argument("--manifest", type=Path, help="provenance and frozen holdout manifest")
    parser.add_argument("--json", type=Path, help="write the full JSON report here")
    parser.add_argument("--markdown", type=Path, help="write a Markdown summary here")
    parser.add_argument("--check", type=Path, help="thresholds JSON; exit 1 on violation")
    parser.add_argument("--review-floor", default=None,
                        help="passed to RAGPipelineGuard if it accepts review_floor")
    parser.add_argument("--corpus", type=Path, nargs="+", default=None,
                        help="override corpus JSONL files")
    parser.add_argument("--quiet", action="store_true", help="suppress console summary")
    args = parser.parse_args(argv)

    provenance = []
    if entries is None:
        paths = args.corpus or (CHUNK_FILES if args.mode == "chunks" else CORPUS_FILES)
        if args.corpus and args.manifest is None:
            parser.error("--corpus requires --manifest with provenance and frozen holdout hashes")
        try:
            provenance = verify_manifest(paths, args.manifest or MANIFEST_FILE, args.mode)
            entries = load_corpus(paths, mode=args.mode)
        except (ValueError, KeyError, TypeError, OSError) as exc:
            parser.error(str(exc))
    if guard is None:
        guard = build_guard(args.review_floor)
    version = ruleset_version()

    thresholds: dict[str, Any] = {}
    if args.check is not None:
        with open(args.check, encoding="utf-8") as fh:
            thresholds = json.load(fh)

    records = run_entries(filter_split(entries, args.split), guard, mode=args.mode)
    needed = {args.split}
    if thresholds:
        needed |= set(SPLITS) if args.split == "all" else {args.split}
    reports = {split: summarize(filter_split(records, split)) for split in sorted(needed)}
    report = reports[args.split]

    if not args.quiet:
        print(render_console(report, args.split, version))
    if args.json is not None:
        payload = {
            "split": args.split, "mode": args.mode, "ruleset_version": version,
            "corpus_sha256": corpus_digest(entries),
            "evaluated_sha256": corpus_digest(filter_split(entries, args.split)),
            "results_sha256": corpus_digest([
                {key: value for key, value in record.items() if key != "latency_ms"}
                for record in records
            ]),
            "provenance": provenance,
            "records": records,
            "runtime": {"python": platform.python_version(), "platform": platform.platform()},
            "configuration": {"auto_reject": getattr(guard, "auto_reject", None),
                              "review_floor": getattr(getattr(guard, "policy", None),
                                                      "review_floor", args.review_floor)},
            **report,
        }
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n",
                             encoding="utf-8")
    if args.markdown is not None:
        args.markdown.write_text(render_markdown(report, args.split, version), encoding="utf-8")

    if thresholds:
        violations = check_thresholds(thresholds, reports)
        if violations:
            print(f"\nTHRESHOLD CHECK FAILED ({len(violations)} violation(s)):", file=sys.stderr)
            for violation in violations:
                print(f"  - {violation}", file=sys.stderr)
            return 1
        print("\nthreshold check passed", file=sys.stderr if args.quiet else sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
