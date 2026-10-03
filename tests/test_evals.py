"""Tests for the evaluation corpus and the metrics runner in ``evals/``."""

from __future__ import annotations

import importlib.util
import json
import re
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EVALS = ROOT / "evals"

_spec = importlib.util.spec_from_file_location("ragguard_evals_run", EVALS / "run.py")
assert _spec is not None and _spec.loader is not None
run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run)

ATTACK_CATEGORIES = {
    "instruction_override", "persona_override", "system_prompt_extraction",
    "data_exfiltration", "markdown_exfiltration", "jailbreak_mode", "metadata_injection",
    "obfuscation_homoglyph", "obfuscation_spacing_leet", "obfuscation_encoding",
    "paraphrase", "multilingual", "markup", "tool_output",
}
BENIGN_CATEGORIES = {
    "technical_docs", "tutorial_steps", "sql_docs", "html_js_docs", "security_discussion",
    "business", "config_docs", "markdown_docs", "api_docs", "general_prose",
    "multilingual_benign", "metadata_benign",
}
FILES = {"attack": EVALS / "corpus" / "attacks.jsonl", "benign": EVALS / "corpus" / "benign.jsonl"}

URL_RE = re.compile(r"(?i)\b(?:https?|ftp)://([^/\s\"'<>()\]\[?#{}|\\^`]+)")
EMAIL_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
RESERVED_DOMAINS = ("example.com", "example.org", "example.net")
RESERVED_TLDS = (".example", ".test", ".invalid", ".localhost")


def _load(label: str) -> list[dict]:
    with open(FILES[label], encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def _all_strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in _all_strings(k) + _all_strings(v)]
    if isinstance(value, list):
        return [s for item in value for s in _all_strings(item)]
    return []


def _is_reserved(host: str) -> bool:
    host = host.lower().rstrip(".").split(":")[0]
    if host in RESERVED_DOMAINS or any(host.endswith("." + d) for d in RESERVED_DOMAINS):
        return True
    return host.endswith(RESERVED_TLDS) or host == "localhost"


CORPUS = {label: _load(label) for label in FILES}
ALL_ENTRIES = CORPUS["attack"] + CORPUS["benign"]


# ------------------------------------------------------------------ corpus schema


@pytest.mark.parametrize("label", sorted(FILES))
def test_corpus_size_and_labels(label):
    entries = CORPUS[label]
    assert len(entries) >= 150
    allowed = ATTACK_CATEGORIES if label == "attack" else BENIGN_CATEGORIES
    for entry in entries:
        assert set(entry) == set(run.REQUIRED_FIELDS), entry["id"]
        assert entry["label"] == label, entry["id"]
        assert entry["category"] in allowed, entry["id"]
        assert entry["split"] in {"dev", "holdout"}, entry["id"]
        assert isinstance(entry["text"], str) and entry["text"].strip(), entry["id"]
        assert entry["metadata"] is None or isinstance(entry["metadata"], dict), entry["id"]
        assert isinstance(entry["notes"], str) and entry["notes"].strip(), entry["id"]
        assert entry["id"].startswith("a-" if label == "attack" else "b-"), entry["id"]


@pytest.mark.parametrize("label", sorted(FILES))
def test_categories_balanced_with_both_splits(label):
    entries = CORPUS[label]
    allowed = ATTACK_CATEGORIES if label == "attack" else BENIGN_CATEGORIES
    counts = Counter(e["category"] for e in entries)
    assert set(counts) == allowed
    assert min(counts.values()) >= 10
    for category in allowed:
        splits = Counter(e["split"] for e in entries if e["category"] == category)
        assert splits["dev"] and splits["holdout"], category
        assert 0.2 <= splits["holdout"] / counts[category] <= 0.4, category


def test_ids_unique():
    ids = [e["id"] for e in ALL_ENTRIES]
    assert len(ids) == len(set(ids))


def test_no_real_looking_secrets():
    for entry in ALL_ENTRIES:
        for s in _all_strings(entry["text"]) + _all_strings(entry["metadata"]):
            for token in re.findall(r"\bsk-[A-Za-z0-9_-]+", s):
                assert token.startswith("sk-test-"), (entry["id"], token)
                assert set(token[len("sk-test-"):]) <= {"0"}, (entry["id"], token)
            assert not re.search(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", s), entry["id"]
            assert not re.search(r"\bgh[pousr]_[A-Za-z0-9]{20,}", s), entry["id"]
            assert not re.search(r"\bxox[abprs]-[A-Za-z0-9-]{10,}", s), entry["id"]
            assert "BEGIN RSA PRIVATE KEY" not in s and "BEGIN OPENSSH" not in s, entry["id"]


def test_only_reserved_domains():
    for entry in ALL_ENTRIES:
        for s in _all_strings(entry["text"]) + _all_strings(entry["metadata"]):
            for host in URL_RE.findall(s):
                assert _is_reserved(host), (entry["id"], host)
            for host in EMAIL_RE.findall(s):
                assert _is_reserved(host), (entry["id"], host)
            for host in re.findall(r"(?i)\bwww\.([a-z0-9.-]+)", s):
                assert _is_reserved(host), (entry["id"], host)


def test_reserved_domain_check_rejects_real_hosts():
    assert not _is_reserved("github.com")
    assert not _is_reserved("example.com.evil.io")
    assert _is_reserved("exfil.example")
    assert _is_reserved("docs.example.com")


# ------------------------------------------------------------------ runner


class StubGuard:
    """Decides by marker words in the text; reports a family per marker."""

    def ingest(self, text, metadata=None, *, id=None):
        if "BLOCK" in text:
            return {"decision": "reject", "families": ["fam_block"]}
        if "FLAG" in text:
            return {"decision": "review", "families": ["fam_flag"]}
        return {"decision": "accept", "families": []}


def _entry(id_, label, category, text, split="dev"):
    return {"id": id_, "text": text, "metadata": None, "label": label,
            "category": category, "split": split, "notes": "t"}


TINY = [
    _entry("a-1", "attack", "cat_x", "BLOCK me"),
    _entry("a-2", "attack", "cat_x", "FLAG me", split="holdout"),
    _entry("a-3", "attack", "cat_y", "quiet attack"),
    _entry("a-4", "attack", "cat_y", "BLOCK too"),
    _entry("b-1", "benign", "doc", "fine"),
    _entry("b-2", "benign", "doc", "FLAG false positive"),
    _entry("b-3", "benign", "doc", "fine", split="holdout"),
    _entry("b-4", "benign", "prose", "BLOCK false block"),
]


def test_evaluate_metrics():
    report = run.evaluate(TINY, StubGuard())
    o = report["overall"]
    assert (o["attack_count"], o["benign_count"]) == (4, 4)
    assert o["attack_detection_rate"] == 0.75
    assert o["attack_block_rate"] == 0.5
    assert o["benign_false_positive_rate"] == 0.5
    assert o["benign_false_block_rate"] == 0.25
    assert set(o["latency_ms"]) == {"p50", "p95", "max"}
    assert report["attack_categories"]["cat_x"]["detection_rate"] == 1.0
    assert report["attack_categories"]["cat_y"]["detection_rate"] == 0.5
    assert report["benign_categories"]["doc"]["false_positive_rate"] == pytest.approx(1 / 3,
                                                                                    abs=1e-4)
    assert report["families"]["fam_block"] == {
        "fires_on_attacks": 2, "fires_on_benign": 1, "precision": pytest.approx(0.6667)}
    assert report["missed_attack_ids"] == ["a-3"]
    assert report["false_positive_benign_ids"] == ["b-2", "b-4"]
    assert report["false_block_benign_ids"] == ["b-4"]
    assert list(report["attack_categories"]) == sorted(report["attack_categories"])


def test_evaluate_empty_rates_are_none():
    report = run.evaluate([_entry("b-1", "benign", "doc", "fine")], StubGuard())
    assert report["overall"]["attack_detection_rate"] is None
    assert report["overall"]["benign_false_positive_rate"] == 0.0


def _write(tmp_path, name, payload):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_main_check_passes(tmp_path, capsys):
    thresholds = _write(tmp_path, "ok.json", {
        "min_attack_detection_rate": {"all": 0.7, "dev": 0.6},
        "max_benign_false_positive_rate": {"all": 0.5},
        "min_category_detection_rate": {"all": {"cat_x": 1.0}},
        "max_p95_latency_ms": 1000,
    })
    out_json = tmp_path / "out.json"
    out_md = tmp_path / "out.md"
    code = run.main(["--check", str(thresholds), "--json", str(out_json),
                     "--markdown", str(out_md)], entries=TINY, guard=StubGuard())
    assert code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["split"] == "all" and data["missed_attack_ids"] == ["a-3"]
    assert "Attack categories" in out_md.read_text(encoding="utf-8")
    assert "passed" in capsys.readouterr().out


def test_main_check_fails_with_readable_violations(tmp_path, capsys):
    thresholds = _write(tmp_path, "bad.json", {
        "min_attack_detection_rate": {"all": 0.9},
        "max_benign_false_block_rate": {"all": 0.1},
        "min_category_detection_rate": {"all": {"cat_y": 0.9, "missing_cat": 0.1}},
        "max_p95_latency_ms": -1,
    })
    code = run.main(["--quiet", "--check", str(thresholds)], entries=TINY, guard=StubGuard())
    assert code == 1
    err = capsys.readouterr().err
    assert "min_attack_detection_rate[all]: 0.7500 < minimum 0.9" in err
    assert "max_benign_false_block_rate[all]" in err
    assert "min_category_detection_rate[all][cat_y]" in err
    assert "missing_cat" in err
    assert "max_p95_latency_ms" in err


def test_main_split_filters_entries(tmp_path):
    out_json = tmp_path / "holdout.json"
    code = run.main(["--quiet", "--split", "holdout", "--json", str(out_json)],
                    entries=TINY, guard=StubGuard())
    assert code == 0
    data = json.loads(out_json.read_text(encoding="utf-8"))
    assert data["overall"]["attack_count"] == 1
    assert data["overall"]["benign_count"] == 1


def test_check_skips_splits_not_evaluated(tmp_path):
    thresholds = _write(tmp_path, "t.json", {"min_attack_detection_rate": {"holdout": 0.99}})
    assert run.main(["--quiet", "--split", "dev", "--check", str(thresholds)],
                    entries=TINY, guard=StubGuard()) == 0


def test_unknown_threshold_key_is_a_violation():
    report = run.evaluate(TINY, StubGuard())
    violations = run.check_thresholds({"min_detection": {"all": 0.1}, "_comment": "x"},
                                      {"all": report})
    assert violations == ["unknown threshold key 'min_detection'"]


def test_repo_thresholds_file_is_well_formed():
    thresholds = json.loads((EVALS / "thresholds.json").read_text(encoding="utf-8"))
    report = run.evaluate(TINY, StubGuard())
    violations = run.check_thresholds(thresholds, {"all": report})
    assert not [v for v in violations if v.startswith("unknown threshold key")]


def test_frozen_repo_document_holdout_and_provenance():
    sources = run.verify_manifest(list(run.CORPUS_FILES), run.MANIFEST_FILE, "documents")
    assert [source["holdout_count"] for source in sources] == [43, 48]
    assert {source["provenance"]["kind"] for source in sources} == {"synthetic"}


def _external_corpus(tmp_path):
    entries = [_entry("imported-dev", "benign", "doc", "fine"),
               _entry("imported-holdout", "attack", "cat_x", "BLOCK", "holdout")]
    corpus = tmp_path / "external.jsonl"
    corpus.write_text("\n".join(json.dumps(entry) for entry in entries), encoding="utf-8")
    manifest = _write(tmp_path, "manifest.json", {
        "schema_version": 1,
        "corpora": [{
            "path": corpus.name, "mode": "documents",
            "provenance": {"kind": "external", "source": "user-supplied test fixture",
                           "license": "test-only declaration",
                           "collection_method": "fixture; not an authentic external dataset"},
            "holdout_count": 1, "holdout_sha256": run.corpus_digest(entries[1:]),
        }],
    })
    return entries, corpus, manifest


def test_external_import_requires_manifest_and_reports_source(tmp_path):
    _, corpus, manifest = _external_corpus(tmp_path)
    with pytest.raises(SystemExit) as exc:
        run.main(["--corpus", str(corpus)], guard=StubGuard())
    assert exc.value.code == 2
    output = tmp_path / "report.json"
    assert run.main(["--corpus", str(corpus), "--manifest", str(manifest),
                     "--json", str(output), "--quiet"], guard=StubGuard()) == 0
    report = json.loads(output.read_text())
    assert report["provenance"][0]["provenance"]["kind"] == "external"
    assert len(report["corpus_sha256"]) == 64
    assert len(report["results_sha256"]) == 64


@pytest.mark.parametrize("mutation", ["text", "label", "split", "delete", "add"])
def test_holdout_mutations_fail_closed(tmp_path, mutation):
    entries, corpus, manifest = _external_corpus(tmp_path)
    if mutation == "delete":
        entries.pop()
    elif mutation == "add":
        entries.append(_entry("new-holdout", "benign", "doc", "extra", "holdout"))
    else:
        entries[1][mutation] = {"text": "changed", "label": "benign", "split": "dev"}[mutation]
    corpus.write_text("\n".join(json.dumps(entry) for entry in entries), encoding="utf-8")
    with pytest.raises(ValueError, match="frozen holdout"):
        run.verify_manifest([corpus], manifest, "documents")


def test_dev_can_change_without_changing_holdout(tmp_path):
    entries, corpus, manifest = _external_corpus(tmp_path)
    original = run.corpus_digest(entries)
    entries[0]["text"] = "changed dev only"
    corpus.write_text("\n".join(json.dumps(entry) for entry in entries), encoding="utf-8")
    run.verify_manifest([corpus], manifest, "documents")
    assert run.corpus_digest(entries) != original
    assert run.corpus_digest(entries) == run.corpus_digest(list(reversed(entries)))


@pytest.mark.parametrize(("field", "value"), [
    ("label", "typo"), ("split", "test"), ("id", ""), ("metadata", []),
    ("text", None), ("category", []),
])
def test_invalid_imported_records_are_rejected(tmp_path, field, value):
    entry = _entry("bad", "attack", "cat", "text")
    entry[field] = value
    path = _write(tmp_path, "bad.jsonl", entry)
    with pytest.raises(ValueError, match="bad.jsonl:1"):
        run.load_corpus([path])


def test_duplicate_ids_across_files_are_rejected(tmp_path):
    entry = _entry("duplicate", "attack", "cat", "text")
    paths = [_write(tmp_path, f"{i}.jsonl", entry) for i in range(2)]
    with pytest.raises(ValueError, match="duplicate id"):
        run.load_corpus(paths)


def test_threshold_with_no_required_samples_fails():
    report = run.evaluate([_entry("benign", "benign", "doc", "fine")], StubGuard())
    assert run.check_thresholds({"min_attack_detection_rate": {"all": 0.5}},
                                {"all": report}) == [
        "min_attack_detection_rate[all]: no samples for required metric",
    ]


def test_result_fingerprint_ignores_latency(tmp_path):
    reports = []
    for i in range(2):
        path = tmp_path / f"report-{i}.json"
        run.main(["--quiet", "--json", str(path)], entries=TINY, guard=StubGuard())
        reports.append(json.loads(path.read_text()))
    assert reports[0]["results_sha256"] == reports[1]["results_sha256"]
    assert reports[0]["evaluated_sha256"] == reports[1]["evaluated_sha256"]
