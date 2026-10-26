import importlib.util
from pathlib import Path

import pytest

_PATH = Path(__file__).resolve().parents[2] / "training" / "train.py"
_spec = importlib.util.spec_from_file_location("safeparse_train", _PATH)
train = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(train)


def test_device_selection():
    from types import SimpleNamespace
    torch = SimpleNamespace(cuda=SimpleNamespace(is_available=lambda: False),
                            backends=SimpleNamespace(mps=SimpleNamespace(is_available=lambda: True)))
    assert train.select_device(torch, "auto") == "cpu"
    assert train.select_device(torch, "mps") == "mps"
    assert train.select_device(torch, "cpu") == "cpu"
    with pytest.raises(ValueError, match="CUDA"):
        train.select_device(torch, "cuda")
    torch.backends.mps.is_available = lambda: False
    with pytest.raises(ValueError, match="Apple GPU"):
        train.select_device(torch, "mps")
    assert train.parse_args(["--output-dir", "example", "--device", "mps"]).device == "mps"


def test_sample_indices_matches_runtime():
    from app.security.guardrail_model import _sample_indices
    for n in range(0, 30):
        for k in (0, 1, 3, 8):
            assert train.sample_indices(n, k) == _sample_indices(n, k)


def test_binary_metrics():
    m = train.binary_metrics([1, 1, 0, 0], [0.9, 0.2, 0.6, 0.1], 0.5)
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["fpr"] == 0.5 and m["recall"] == 0.5


def test_choose_threshold_f1_and_fpr():
    labels, scores = [1, 1, 0, 0, 0], [0.9, 0.6, 0.7, 0.2, 0.1]
    assert train.choose_threshold(labels, scores)["threshold"] == 0.6
    m = train.choose_threshold(labels, scores, max_fpr=0.0)
    assert m["fpr"] == 0.0 and m["threshold"] == 0.9
    with pytest.raises(ValueError):
        train.choose_threshold([0, 0], [0.5, 0.6], max_fpr=-1)


def test_per_source_with_coverage():
    rows = [{"label": 1, "source": "a"}, {"label": 0, "source": "b"}]
    out = train.per_source_metrics(rows, [0.9, 0.9], 0.5, [(10, 8), (2, 2)])
    assert out["a"]["tp"] == 1 and out["a"]["window_coverage"] == 0.8
    assert out["b"]["fp"] == 1 and out["b"]["docs_truncated"] == 0


def test_leakage_detection():
    ok = {"train": [{"text": "a"}], "validation": [{"text": "b"}], "test": [{"text": "c"}]}
    train.check_leakage(ok)
    with pytest.raises(ValueError):
        train.check_leakage({**ok, "test": [{"text": "a"}]})
    with pytest.raises(ValueError):
        train.check_leakage({"train": [{"text": "a", "leakage_group": "g"}],
                             "test": [{"text": "z", "leakage_group": ["x", "g"]}]})


def test_output_dir_guard(tmp_path):
    inp = tmp_path / "data" / "train.jsonl"
    inp.parent.mkdir()
    inp.write_text("")
    for bad in (tmp_path / "data", tmp_path, inp):
        with pytest.raises(ValueError):
            train.check_output_dir(bad, [inp])
    train.check_output_dir(tmp_path / "out", [inp])
    (tmp_path / "full").mkdir()
    (tmp_path / "full" / "x").write_text("")
    with pytest.raises(ValueError):
        train.check_output_dir(tmp_path / "full", [inp])


def _write(path, rows):
    import json
    path.write_text("\n".join(json.dumps(r) for r in rows))


def test_load_jsonl_rejects_bad_rows(tmp_path):
    f = tmp_path / "a.jsonl"
    for row in ({"text": "x", "label": True}, {"text": "  ", "label": 0},
                {"text": "x", "label": 2}, {"text": "x", "label": 1.0}, {"label": 1}):
        _write(f, [row])
        with pytest.raises(ValueError):
            train.load_jsonl(f)
    _write(f, [{"text": "x", "label": 1}])
    assert train.load_jsonl(f)[0]["source"] == "unknown"


def test_check_classes():
    both = [{"label": 0}, {"label": 1}]
    train.check_classes({"train": both, "validation": both, "test": both})
    with pytest.raises(ValueError):
        train.check_classes({"train": both, "validation": both, "test": [{"label": 0}]})


def test_metrics_input_validation():
    for scores in ([0.5], [0.5, float("nan")], [0.5, 1.5], [0.5, -0.1], [0.5, float("inf")]):
        with pytest.raises(ValueError):
            train.binary_metrics([1, 0], scores, 0.5)
        with pytest.raises(ValueError):
            train.choose_threshold([1, 0], scores)


def test_choose_threshold_matches_bruteforce():
    import random
    rng = random.Random(1)
    for _ in range(50):
        n = rng.randint(2, 30)
        labels = [rng.randint(0, 1) for _ in range(n)]
        scores = [round(rng.random(), 1) for _ in range(n)]
        for fpr in (None, 0.0, 0.3):
            cands = sorted(set(scores), reverse=True) + ([max(scores) + 1e-6] if max(scores) < 1 else [])
            best = None
            for t in cands:
                m = train.binary_metrics(labels, scores, t)
                if fpr is not None and m["fpr"] > fpr:
                    continue
                key = (m["f1"], t) if fpr is None else (m["recall"], m["f1"], t)
                best = max(best, key) if best else key
            if best is None:
                with pytest.raises(ValueError):
                    train.choose_threshold(labels, scores, fpr)
                continue
            got = train.choose_threshold(labels, scores, fpr)
            gkey = (got["f1"], got["threshold"]) if fpr is None else (got["recall"], got["f1"], got["threshold"])
            assert gkey[:-1] == best[:-1]


def test_holdout_included_in_leakage_and_path_guard(tmp_path):
    with pytest.raises(ValueError):
        train.check_leakage({"train": [{"text": "a"}], "source_holdout": [{"text": "a"}]})
    hold = tmp_path / "data" / "source_holdout.jsonl"
    hold.parent.mkdir()
    with pytest.raises(ValueError):
        train.check_output_dir(hold.parent, [hold])


def test_cli_validation():
    ok = ["--output-dir", "o"]
    assert train.parse_args(ok).max_length == 512
    for bad in (["--epochs", "0"], ["--grad-accum", "0"], ["--max-windows", "0"], ["--lr", "0"],
                ["--lr", "nan"], ["--max-length", "256"], ["--stride", "32"],
                ["--max-fpr", "1.5"], ["--max-fpr", "-0.1"]):
        with pytest.raises(SystemExit):
            train.parse_args(ok + bad)
    assert train.parse_args(ok + ["--max-fpr", "0"]).max_fpr == 0.0


def test_file_sha256(tmp_path):
    import hashlib
    f = tmp_path / "x"
    f.write_bytes(b"abc")
    assert train.file_sha256(f) == hashlib.sha256(b"abc").hexdigest()


def test_saturated_negative_with_zero_fpr_errors():
    with pytest.raises(ValueError):
        train.choose_threshold([1, 0], [1.0, 1.0], max_fpr=0.0)


def test_threshold_never_exceeds_one():
    labels, scores = [1, 0, 0, 1], [1.0, 0.1235, 0.0, 0.9999]
    for fpr in (None, 0.0, 0.5):
        assert train.choose_threshold(labels, scores, fpr)["threshold"] <= 1.0
    assert train.choose_threshold([0, 0, 1], [0.2, 0.3, 1.0])["threshold"] <= 1.0
    # all-benign-saturated data in F1 mode still yields a valid threshold
    assert train.choose_threshold([1, 0], [1.0, 1.0])["threshold"] <= 1.0
