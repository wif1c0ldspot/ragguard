"""Probe contract tests use stubs; model results are recorded separately."""

import json

import pytest

from evals.rag_probe import (
    CASES,
    Generation,
    benchmark_revision,
    normalized_answer,
    run_cases,
    write_results,
)


def test_case_revision_is_frozen_before_model_inference():
    assert (
        benchmark_revision() == "b2ec8453c4350293c87be14af4ea42ea6dd225a1003aa81d538e69bf6e2f7eda"
    )
    assert len(CASES) == 6
    assert {case.category for case in CASES} == {
        "direct_injection",
        "paraphrased_injection",
        "factual_poisoning",
    }


@pytest.mark.parametrize(
    "answer, target, expected",
    [
        ("  BLUE.\n", "blue", True),
        ("I will not answer blue", "blue", False),
        ("blue or violet", "violet", False),
        ("48", "4", False),
    ],
)
def test_exact_judge_cannot_confuse_mentions_or_substrings(answer, target, expected):
    assert (normalized_answer(answer) == normalized_answer(target)) is expected


def test_pairs_preserve_contexts_and_blocks_count_as_utility_failures(tmp_path):
    calls = []

    def generate(question, context):
        calls.append((question, context))
        return Generation("blue", 10, 1, 0.1)

    baseline = run_cases(generate, defended=False)
    defended = run_cases(generate, defended=True)
    assert len(baseline["records"]) == len(defended["records"]) == 12
    assert [(r["case_id"], r["condition"], r["context_sha256"]) for r in baseline["records"]] == [
        (r["case_id"], r["condition"], r["context_sha256"]) for r in defended["records"]
    ]
    blocked = [row for row in defended["records"] if row["execution"] == "blocked"]
    assert len(blocked) == 2
    assert all(
        row["status"] == "ok"
        and row["task_success"] is False
        and row["attack_success"] is False
        and row["output"] is None
        for row in blocked
    )
    assert len(calls) == 22
    report = write_results(tmp_path, baseline, defended, {"fixture": True})
    assert report["conditions"]["attacked"]["defended"]["cases"] == 6
    assert report["conditions"]["attacked"]["defended"]["valid_cases"] == 6
    assert report["execution_counts"]["defended"]["blocked"] == 2
    assert report["provenance"]["model"]
    assert json.loads((tmp_path / "comparison.json").read_text())["benchmark_revision"]


def test_generation_errors_are_not_scored_as_prevention(tmp_path):
    def failed(question, context):
        raise RuntimeError("synthetic runtime failure")

    baseline = run_cases(failed, defended=False)
    defended = run_cases(failed, defended=True)
    assert all(
        row["status"] == "error" and row["task_success"] is None and row["attack_success"] is None
        for row in baseline["records"]
    )
    report = write_results(tmp_path, baseline, defended, {})
    attacked = report["conditions"]["attacked"]
    assert attacked["baseline"]["error_cases"] == 6
    assert attacked["defended"]["error_cases"] == 4
    assert attacked["joint_valid_pairs"] == 0
    assert attacked["attack_successes_prevented"] == 0


def test_snapshot_validation_rejects_substitution_and_extra_config(tmp_path, monkeypatch):
    import hashlib

    from evals import rag_probe

    path = tmp_path / "model.safetensors"
    path.write_bytes(b"fixture")
    monkeypatch.setattr(
        rag_probe,
        "MODEL_FILES_SHA256",
        {
            "model.safetensors": hashlib.sha256(b"fixture").hexdigest(),
        },
    )
    assert rag_probe.verify_snapshot(tmp_path)
    extra = tmp_path / "adapter_config.json"
    extra.write_text("{}")
    with pytest.raises(ValueError, match="exactly"):
        rag_probe.verify_snapshot(tmp_path)
    extra.unlink()
    path.write_bytes(b"substituted")
    with pytest.raises(ValueError, match="integrity mismatch"):
        rag_probe.verify_snapshot(tmp_path)
