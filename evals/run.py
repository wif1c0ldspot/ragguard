"""Run the ragguard evaluation corpus and report detection metrics.

Usage::

    python evals/run.py [--split dev|holdout|all] [--json out.json]
                        [--markdown out.md] [--check evals/thresholds.json]
                        [--review-floor SEVERITY]

Standard library only (plus ``ragguard``). Importable: ``evaluate(entries, guard)``.
"""

from __future__ import annotations

import argparse
import inspect
import json
import math
import sys
import time
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

EVALS_DIR = Path(__file__).resolve().parent
CORPUS_DIR = EVALS_DIR / "corpus"
CORPUS_FILES = (CORPUS_DIR / "attacks.jsonl", CORPUS_DIR / "benign.jsonl")
SPLITS = ("dev", "holdout", "all")
REQUIRED_FIELDS = ("id", "text", "metadata", "label", "category", "split", "notes")


# --------------------------------------------------------------------------- corpus


def load_corpus(paths: Iterable[Path] = CORPUS_FILES) -> list[dict[str, Any]]:
    """Load JSONL corpus files; entries keep file order."""
    entries: list[dict[str, Any]] = []
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{path.name}:{lineno}: invalid JSON: {exc}") from exc
                missing = [field for field in REQUIRED_FIELDS if field not in entry]
                if missing:
                    raise ValueError(f"{path.name}:{lineno}: missing fields {missing}")
                entries.append(entry)
    return entries


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


def run_entries(entries: Sequence[dict[str, Any]], guard: Any) -> list[dict[str, Any]]:
    """Ingest each entry once; return one record per entry (no text)."""
    records = []
    for entry in entries:
        start = time.perf_counter()
        result = guard.ingest(entry["text"], entry.get("metadata"), id=entry["id"])
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        records.append({
            "id": entry["id"],
            "label": entry["label"],
            "category": entry["category"],
            "split": entry["split"],
            "decision": str(result["decision"]),
            "families": sorted(set(result.get("families") or [])),
            "latency_ms": elapsed_ms,
        })
    return records


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


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
    detected = [r for r in attacks if r["decision"] != "accept"]
    blocked = [r for r in attacks if r["decision"] == "reject"]
    flagged = [r for r in benign if r["decision"] != "accept"]
    false_blocks = [r for r in benign if r["decision"] == "reject"]
    latencies = [r["latency_ms"] for r in records]

    def by_category(rows: list[dict[str, Any]], key: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for category in sorted({r["category"] for r in rows}):
            group = [r for r in rows if r["category"] == category]
            hits = sum(1 for r in group if r["decision"] != "accept")
            rejects = sum(1 for r in group if r["decision"] == "reject")
            out[category] = {
                "count": len(group),
                "flagged": hits,
                "rejected": rejects,
                key: _rate(hits, len(group)),
            }
        return out

    families: dict[str, dict[str, Any]] = {}
    for family in sorted({f for r in records for f in r["families"]}):
        on_attack = sum(1 for r in attacks if family in r["families"])
        on_benign = sum(1 for r in benign if family in r["families"])
        families[family] = {
            "fires_on_attacks": on_attack,
            "fires_on_benign": on_benign,
            "precision": _rate(on_attack, on_attack + on_benign),
        }

    return {
        "overall": {
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
        "missed_attack_ids": sorted(r["id"] for r in attacks if r["decision"] == "accept"),
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

    def compare(label: str, actual: float | None, bound: float, kind: Any) -> None:
        if actual is None:
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
    parser.add_argument("--json", type=Path, help="write the full JSON report here")
    parser.add_argument("--markdown", type=Path, help="write a Markdown summary here")
    parser.add_argument("--check", type=Path, help="thresholds JSON; exit 1 on violation")
    parser.add_argument("--review-floor", default=None,
                        help="passed to RAGPipelineGuard if it accepts review_floor")
    parser.add_argument("--corpus", type=Path, nargs="*", default=None,
                        help="override corpus JSONL files")
    parser.add_argument("--quiet", action="store_true", help="suppress console summary")
    args = parser.parse_args(argv)

    if entries is None:
        entries = load_corpus(args.corpus or CORPUS_FILES)
    if guard is None:
        guard = build_guard(args.review_floor)
    version = ruleset_version()

    thresholds: dict[str, Any] = {}
    if args.check is not None:
        with open(args.check, encoding="utf-8") as fh:
            thresholds = json.load(fh)

    records = run_entries(filter_split(entries, args.split), guard)
    needed = {args.split}
    if thresholds:
        needed |= set(SPLITS) if args.split == "all" else {args.split}
    reports = {split: summarize(filter_split(records, split)) for split in sorted(needed)}
    report = reports[args.split]

    if not args.quiet:
        print(render_console(report, args.split, version))
    if args.json is not None:
        payload = {"split": args.split, "ruleset_version": version, **report}
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
