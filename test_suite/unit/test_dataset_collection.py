"""Offline curation tests; never execute adversarial fixture text."""
from collections import Counter
import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("collect_ipi", Path(__file__).parents[2] / "training/collect.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


def source(name):
    return {"id": name, "repo": "fixture/" + name, "revision": "a" * 40, "license": "fixture"}


def row(row_id, text, label, group, split=None):
    item = collector.record(source("fixture"), row_id, text, label, group, "fixture")
    if split:
        item["_fixed_split"] = split
    return item


def baseline():
    return [row(s + str(label), s + " sample " + ("benign" if label == 0 else "attack"), label, s, s)
            for s in collector.SPLITS for label in (0, 1)]


def curate(extra):
    audit = Counter()
    result = collector.curate(baseline() + extra, 13, 100, 100, audit)
    return result, audit


def test_unicode_is_preserved_but_dedup_is_normalized():
    text = "Fullwidth Ａ and invisible \u200b characters"
    item = row("unicode", text, 1, "unicode", "train")
    result, _ = curate([item])
    assert next(r for r in result["train"] if r["id"].endswith("unicode"))["text"] == text
    assert collector.canonical(" Ａ  TEXT ") == "a text"


def test_duplicate_conflicting_labels_are_quarantined():
    result, audit = curate([row("a", "Same document", 0, "a"), row("b", "same DOCUMENT", 1, "b")])
    assert audit["conflicting_label_component_rows"] == 2
    assert not any(r["text"].casefold() == "same document" for rs in result.values() for r in rs)


def test_fixed_split_collisions_are_quarantined():
    _, audit = curate([row("a", "repeated", 1, "a", "train"),
                       row("b", "repeated", 1, "b", "test")])
    assert audit["cross_fixed_split_component_rows"] == 2


def test_pairs_cannot_cross_splits_and_run_is_deterministic():
    extra = [row("a", "attack fixture", 1, "pair"), row("b", "benign fixture", 0, "pair")]
    first, _ = curate(extra)
    second, _ = curate(extra)
    assert first == second
    locations = [split for split, rows in first.items() for r in rows if r["id"] in {"fixture:a", "fixture:b"}]
    assert len(locations) == 2 and len(set(locations)) == 1


def test_near_duplicate_numeric_variants_share_group():
    text = "A detailed and distinctive fixture document with many unique words for numeric identifier 12345 and additional explanatory sentences about unusual equipment maintenance procedures and scientific calibration specifications."
    result, audit = curate([row("a", text, 0, "a"), row("b", text.replace("12345", "67890"), 0, "b")])
    chosen = [r for rs in result.values() for r in rs if r["id"] in {"fixture:a", "fixture:b"}]
    assert audit["near_duplicate_links"] >= 1
    assert len({r["leakage_group"] for r in chosen}) == 1


def test_short_numeric_variants_share_group():
    result, _ = curate([row("short_a", "Result value 1234", 0, "a"),
                        row("short_b", "Result value 9876", 0, "b")])
    items = [r for rs in result.values() for r in rs if "short_" in r["id"]]
    assert len(items) == 2
    assert len({r["leakage_group"] for r in items}) == 1


def test_repeated_attack_on_different_hosts_shares_split(tmp_path):
    path = tmp_path / "records.jsonl"
    records = [{"id": i, "domain": "fixture", "attack_category": "test",
                "injection": {"injection_text": "PAYLOAD_FIXTURE"},
                "environment": {"notes": host + " PAYLOAD_FIXTURE"}}
               for i, host in enumerate(["Clinical details", "Maintenance details"])]
    path.write_text("\n".join(json.dumps(r) for r in records))
    extra = list(collector.extract_nemotron(source("nemotron"), [path], 13, Counter()))
    result, _ = curate(extra)
    locations = [s for s, rs in result.items() for r in rs if r["source"] == "nemotron"]
    assert len(locations) == 4
    assert len(set(locations)) == 1


def test_empty_and_oversized_text_excluded():
    _, audit = curate([row("a", " ", 0, "a"), row("b", "x" * 50001, 1, "b")])
    assert audit["empty_text"] == 1
    assert audit["over_50000_characters"] == 1


def test_nemotron_extracts_only_untrusted_unique_field(tmp_path):
    payload = "INJECTION_FIXTURE"
    value = {"id": 7, "domain": "test", "attack_category": "test",
             "injection": {"injection_text": payload},
             "environment": {"record": {"notes": "before " + payload + " after"}},
             "responses_create_params": {"input": "TRUSTED_PROMPT_NOT_A_FEATURE"}}
    path = tmp_path / "rows.jsonl"
    path.write_text(json.dumps(value) + "\n")
    audit = Counter()
    rows = list(collector.extract_nemotron(source("nemotron"), [path], 13, audit))
    assert [r["label"] for r in rows] == [1, 0]
    assert rows[1]["text"] == "before  after"
    assert rows[1]["label_quality"] == "derived_exact_removal"
    assert rows[0]["_groups"][0] == rows[1]["_groups"][0]
    assert "nemotron_attack:" + collector.digest(collector.canonical(payload)) in rows[0]["_groups"]
    assert all("TRUSTED_PROMPT" not in r["text"] for r in rows)
    value["environment"]["duplicate"] = payload
    path.write_text(json.dumps(value) + "\n")
    assert list(collector.extract_nemotron(source("nemotron"), [path], 13, audit)) == []
    assert audit["nemotron_ambiguous_payload"] == 1


def test_llmail_failed_or_unknown_submissions_not_benign(tmp_path):
    attacks, controls = tmp_path / "attacks.json", tmp_path / "controls.json"
    attacks.write_text(json.dumps({"attack": {"attack_attempt": "True", "reason": "judge"},
                                  "unknown": {"attack_attempt": "False"}}))
    controls.write_text(json.dumps(["clean email"]))
    audit = Counter()
    rows = list(collector.extract_llmail(source("llmail"), [attacks, controls], 13, audit))
    assert [(r["text"], r["label"]) for r in rows] == [("attack", 1), ("clean email", 0)]
    assert audit["llmail_nonpositive_excluded"] == 1


def test_offline_download_requires_cached_revision(tmp_path):
    with pytest.raises(ValueError, match="Missing cached"):
        collector.download(source("fixture"), "file.json", tmp_path, True)


def test_cached_file_checksum_is_verified(tmp_path):
    metadata = source("fixture")
    metadata["file_sha256"] = {"file.json": collector.digest("expected")}
    path = tmp_path / "fixture" / metadata["revision"] / "file.json"
    path.parent.mkdir(parents=True)
    path.write_text("tampered")
    with pytest.raises(ValueError, match="Checksum mismatch"):
        collector.download(metadata, "file.json", tmp_path, True)
    path.write_text("expected")
    actual_path, info = collector.download(metadata, "file.json", tmp_path, True)
    assert actual_path == path
    assert info["sha256"] == collector.digest("expected")


def test_invalid_output_overlap_is_rejected_before_network(tmp_path):
    manifest = tmp_path / "sources.json"
    manifest.write_text('{"sources": []}')
    class Args:
        sources = manifest
        cache_dir = tmp_path / "cache"
        output_dir = tmp_path / "cache" / "data"
    with pytest.raises(ValueError, match="non-overlapping"):
        collector.collect(Args())
