"""Do not turn classifier recall or incomplete agent runs into end-to-end claims."""

import json

import pytest

from evals import outcomes


def artifact(tmp_path, name, *, error=False, protected=False):
    data = {
        "schema_version": 2,
        "generation_config": {"do_sample": False, "max_new_tokens": 24},
        "input_sha256": "a" * 64,
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


@pytest.mark.parametrize("field,value", [
    ("schema_version", 1), ("generation_config", {}),
    ("generation_config", {"temperature": float("nan")}),
    ("generation_config", {"max_new_tokens": 12}),
    ("input_sha256", "b" * 64), ("input_sha256", "bad"),
])
def test_pairing_requires_versioned_finite_configuration_and_inputs(tmp_path, field, value):
    baseline = artifact(tmp_path, "baseline")
    defended = artifact(tmp_path, "defended")
    data = json.loads(defended.read_text())
    data[field] = value
    defended.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        outcomes.compare(baseline, defended)
