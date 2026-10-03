"""Compare paired, externally produced agent outcomes; does not run or judge agents.

python evals/outcomes.py --baseline baseline.json --defended defended.json --output outcomes.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

if __package__:
    from . import run as runner
else:
    import run as runner

IDENTITY_FIELDS = ("benchmark", "benchmark_revision", "model", "model_revision", "seed")


def load_outcomes(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("outcome artifact requires schema_version 1")
    for field in (*IDENTITY_FIELDS, "judging_method", "defense"):
        if field not in data or data[field] is None or data[field] == "":
            raise ValueError(f"missing outcome provenance {field}")
    records = data.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("outcome artifact must contain records")
    seen = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("outcome record must be an object")
        if not isinstance(record.get("case_id"), str) or not record["case_id"]:
            raise ValueError("case_id must be a nonempty string")
        if record.get("condition") not in ("clean", "attacked"):
            raise ValueError("condition must be clean or attacked")
        key = (record["case_id"], record["condition"])
        if key in seen:
            raise ValueError("duplicate outcome case/condition")
        seen.add(key)
        if record.get("status") not in ("ok", "error"):
            raise ValueError("status must be ok or error")
        if record["status"] == "error":
            if record.get("task_success") is not None or record.get("attack_success") is not None:
                raise ValueError("error outcomes must not claim success or failure")
        else:
            if type(record.get("task_success")) is not bool:
                raise ValueError("task_success must be boolean for successful executions")
            if record["condition"] == "attacked":
                if type(record.get("attack_success")) is not bool:
                    raise ValueError("attacked executions require boolean attack_success")
            elif record.get("attack_success") is not None:
                raise ValueError("clean outcomes cannot report attack_success")
    return data


def summarize(records: list[dict[str, Any]], condition: str) -> dict[str, Any]:
    rows = [record for record in records if record["condition"] == condition]
    valid = [record for record in rows if record["status"] == "ok"]
    total, count = len(rows), len(valid)
    successes = sum(record["task_success"] for record in valid)
    report = {
        "cases": total,
        "valid_cases": count,
        "error_cases": total - count,
        "legitimate_task_successes": successes,
        "legitimate_task_completion_valid": runner._rate(successes, count),
        "legitimate_task_completion_all_lower_bound": runner._rate(successes, total),
        "legitimate_task_completion_valid_ci95": runner.wilson_interval(successes, count),
    }
    if condition == "attacked":
        successes = sum(record["attack_success"] for record in valid)
        report.update(
            {
                "attack_successes": successes,
                "attack_success_rate_valid": runner._rate(successes, count),
                "attack_success_rate_all_lower_bound": runner._rate(successes, total),
                "attack_success_rate_valid_ci95": runner.wilson_interval(successes, count),
            }
        )
    return report


def compare(baseline_path: Path, defended_path: Path) -> dict[str, Any]:
    baseline, defended = load_outcomes(baseline_path), load_outcomes(defended_path)
    for field in (*IDENTITY_FIELDS, "judging_method"):
        if baseline[field] != defended[field]:
            raise ValueError(f"unpaired outcome provenance: {field}")
    index = lambda data: {(r["case_id"], r["condition"]): r for r in data["records"]}  # noqa: E731
    left, right = index(baseline), index(defended)
    if left.keys() != right.keys():
        raise ValueError("baseline and defended case/condition sets must match exactly")
    report = {
        "evaluation": "paired_external_agent_outcomes",
        "provenance": {field: baseline[field] for field in IDENTITY_FIELDS},
        "judging_method": baseline["judging_method"],
        "artifact_sha256": {
            "baseline": hashlib.sha256(baseline_path.read_bytes()).hexdigest(),
            "defended": hashlib.sha256(defended_path.read_bytes()).hexdigest(),
        },
        "defenses": {"baseline": baseline["defense"], "defended": defended["defense"]},
        "limitations": [
            "Imported outcomes are producer claims; this tool does not judge traces.",
            "Errors remain explicit; all-case success fractions are lower bounds.",
            "Valid-only rates can be biased when errors differ between conditions.",
        ],
        "conditions": {},
    }
    for condition in ("clean", "attacked"):
        pairs = [
            (left[key], right[key])
            for key in left
            if key[1] == condition and left[key]["status"] == right[key]["status"] == "ok"
        ]
        report["conditions"][condition] = {
            "baseline": summarize(baseline["records"], condition),
            "defended": summarize(defended["records"], condition),
            "joint_valid_pairs": len(pairs),
            "legitimate_successes_lost": sum(
                a["task_success"] and not b["task_success"] for a, b in pairs
            ),
            "legitimate_successes_gained": sum(
                not a["task_success"] and b["task_success"] for a, b in pairs
            ),
            "attack_successes_prevented": (
                sum(a["attack_success"] and not b["attack_success"] for a, b in pairs)
                if condition == "attacked"
                else None
            ),
        }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--defended", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = compare(args.baseline, args.defended)
    except (ValueError, OSError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
