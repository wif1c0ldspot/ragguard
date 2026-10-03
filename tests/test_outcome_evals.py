"""Do not turn classifier recall or incomplete agent runs into end-to-end claims."""

import json

import pytest

from evals import outcomes


def artifact(tmp_path, name, *, error=False, protected=False):
    data = {
        "schema_version": 1,
        "benchmark": "fixture",
        "benchmark_revision": "test",
        "model": "stub",
        "model_revision": "test",
        "seed": 0,
        "judging_method": "fixture assertions",
        "defense": name,
        "records": [
            {
                "case_id": "a",
                "condition": "attacked",
                "status": "ok",
                "task_success": True,
                "attack_success": not protected,
            },
            {
                "case_id": "b",
                "condition": "attacked",
                "status": "error" if error else "ok",
                "task_success": None if error else True,
                "attack_success": None if error else False,
            },
            {
                "case_id": "c",
                "condition": "clean",
                "status": "ok",
                "task_success": not protected,
                "attack_success": None,
            },
        ],
    }
    path = tmp_path / f"{name}.json"
    path.write_text(json.dumps(data))
    return path


def test_paired_outcomes_measure_security_and_utility_with_explicit_denominators(tmp_path):
    baseline = artifact(tmp_path, "baseline", error=True)
    defended = artifact(tmp_path, "defended", protected=True)
    report = outcomes.compare(baseline, defended)
    attacked = report["conditions"]["attacked"]
    assert attacked["baseline"]["attack_success_rate_valid"] == 1
    assert attacked["baseline"]["attack_success_rate_all_lower_bound"] == 0.5
    assert attacked["baseline"]["error_cases"] == 1
    assert attacked["joint_valid_pairs"] == 1
    assert attacked["attack_successes_prevented"] == 1
    assert report["conditions"]["clean"]["legitimate_successes_lost"] == 1


@pytest.mark.parametrize("mutation", ["model", "cases", "duplicate", "error-success"])
def test_unpaired_or_invalid_results_fail_closed(tmp_path, mutation):
    baseline = artifact(tmp_path, "baseline")
    defended = artifact(tmp_path, "defended")
    data = json.loads(defended.read_text())
    if mutation == "model":
        data["model"] = "different"
    elif mutation == "cases":
        data["records"].pop()
    elif mutation == "duplicate":
        data["records"].append(data["records"][0])
    else:
        data["records"][0]["status"] = "error"
    defended.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        outcomes.compare(baseline, defended)
