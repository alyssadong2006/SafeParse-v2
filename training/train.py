#!/usr/bin/env python3
"""Fine-tune a binary indirect-prompt-injection classifier for SafeParse.

Starts from a general encoder (fresh classification head), trains on whole
documents with the same window sampling as app/security/guardrail_model.py
(max_length 512, stride 64, <=8 evenly spread windows incl. endpoints), and
scores a document by its max injection logit margin (== max injection
probability at inference). Only the `text` field is used as a feature.

Example:
  python training/train.py --data-dir training/data --output-dir models/safeparse-ipi-v2
"""
import argparse
import hashlib
import json
import math
import random
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

ID2LABEL = {0: "BENIGN", 1: "INJECTION"}
LABEL2ID = {v: k for k, v in ID2LABEL.items()}
SPLITS = ("train", "validation", "test")
HOLDOUT = "source_holdout"
RUNTIME_MAX_LENGTH, RUNTIME_STRIDE = 512, 64  # must match app/security/guardrail_model.py


# ---------------------------------------------------------------- pure helpers
def sample_indices(item_count: int, limit: int) -> List[int]:
    """Identical to the runtime's _sample_indices."""
    if item_count <= 0 or limit <= 0:
        return []
    if item_count <= limit:
        return list(range(item_count))
    if limit == 1:
        return [0]
    return sorted({round(i * (item_count - 1) / (limit - 1)) for i in range(limit)})


def load_jsonl(path: Path) -> List[dict]:
    rows = []
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            if not isinstance(row.get("text"), str) or not row["text"].strip():
                raise ValueError("%s:%d needs non-empty text" % (path, n))
            if type(row.get("label")) is not int or row["label"] not in (0, 1):
                raise ValueError("%s:%d label must be int 0 or 1 (not bool)" % (path, n))
            row.setdefault("source", "unknown")
            rows.append(row)
    if not rows:
        raise ValueError("%s is empty" % path)
    return rows


def _group_keys(row: dict) -> List[str]:
    value = row.get("leakage_group")
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple)) else [value]
    return [str(v) for v in values]


def check_leakage(splits: Dict[str, List[dict]]) -> None:
    """Raise if an exact text hash or leakage_group key appears in >1 split."""
    seen: Dict[Tuple[str, str], str] = {}
    for name, rows in splits.items():
        for row in rows:
            keys = [("text", hashlib.sha256(row["text"].encode("utf-8")).hexdigest())]
            keys += [("group", k) for k in _group_keys(row)]
            for key in keys:
                other = seen.setdefault(key, name)
                if other != name:
                    raise ValueError("leakage: %s %s... in both %s and %s"
                                     % (key[0], key[1][:12], other, name))


def check_classes(splits: Dict[str, List[dict]], required: Sequence[str] = SPLITS) -> None:
    for name in required:
        if {r["label"] for r in splits[name]} != {0, 1}:
            raise ValueError("split %s must contain both labels 0 and 1" % name)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_output_dir(output: Path, inputs: Iterable[Path]) -> None:
    out = output.resolve()
    for p in inputs:
        p = p.resolve()
        if out == p or out in p.parents or p in out.parents or out == p.parent:
            raise ValueError("output dir %s overlaps input %s" % (out, p))
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise ValueError("output dir %s exists and is not empty" % out)


def _div(a: float, b: float) -> float:
    return a / b if b else 0.0


def _from_counts(tp: int, fp: int, tn: int, fn: int, threshold: float) -> dict:
    precision, recall = _div(tp, tp + fp), _div(tp, tp + fn)
    return {
        "n": tp + fp + tn + fn, "positives": tp + fn, "negatives": tn + fp,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "threshold": threshold,
        "precision": precision, "recall": recall,
        "f1": _div(2 * precision * recall, precision + recall),
        "fpr": _div(fp, fp + tn), "fnr": _div(fn, fn + tp),
        "accuracy": _div(tp + tn, tp + fp + tn + fn),
    }


def _check_scores(labels: Sequence[int], scores: Sequence[float]) -> None:
    if len(labels) != len(scores):
        raise ValueError("labels and scores differ in length (%d vs %d)" % (len(labels), len(scores)))
    if any(type(y) is not int or y not in (0, 1) for y in labels):
        raise ValueError("labels must be int 0/1")
    if any(not math.isfinite(s) or s < 0 or s > 1 for s in scores):
        raise ValueError("scores must be finite probabilities in [0, 1]")


def binary_metrics(labels: Sequence[int], scores: Sequence[float], threshold: float) -> dict:
    _check_scores(labels, scores)
    tp = fp = tn = fn = 0
    for y, s in zip(labels, scores):
        pred = s >= threshold
        if y and pred:
            tp += 1
        elif y:
            fn += 1
        elif pred:
            fp += 1
        else:
            tn += 1
    return _from_counts(tp, fp, tn, fn, threshold)


def choose_threshold(labels: Sequence[int], scores: Sequence[float],
                     max_fpr: Optional[float] = None) -> dict:
    """Pick a threshold on validation data only (O(n log n) sweep).

    Default: maximise F1. With max_fpr: maximise recall (then F1) among
    thresholds with FPR <= max_fpr. Ties go to the higher threshold.
    Prediction rule is score >= threshold.
    """
    if not labels:
        raise ValueError("no validation data")
    _check_scores(labels, scores)
    pos = sum(labels)
    neg = len(labels) - pos
    top = max(scores)
    # start from "predict nothing", then admit score groups from high to low
    best, best_key = None, None
    # "predict nothing" sentinel only if it stays <= 1 (thresholds must be valid probabilities)
    candidates = [(math.nextafter(top, math.inf), 0, 0)] if top < 1 else []
    by_score = defaultdict(lambda: [0, 0])
    for y, s in zip(labels, scores):
        by_score[s][0 if y else 1] += 1
    tp = fp = 0
    for t in sorted(by_score, reverse=True):
        tp += by_score[t][0]
        fp += by_score[t][1]
        candidates.append((t, tp, fp))
    for t, tp, fp in candidates:
        m = _from_counts(tp, fp, neg - fp, pos - tp, t)
        if max_fpr is not None:
            if m["fpr"] > max_fpr:
                continue
            key = (m["recall"], m["f1"], t)
        else:
            key = (m["f1"], t)
        if best_key is None or key > best_key:
            best, best_key = m, key
    if best is None:
        raise ValueError("no threshold satisfies max_fpr=%s" % max_fpr)
    return best


def per_source_metrics(rows: Sequence[dict], scores: Sequence[float], threshold: float,
                       windows: Sequence[Tuple[int, int]] = ()) -> dict:
    """Metrics per `source`; windows = (total, used) per row for coverage."""
    groups = defaultdict(list)
    for i, row in enumerate(rows):
        groups[row.get("source", "unknown")].append(i)
    out = {}
    for src, idx in sorted(groups.items()):
        m = binary_metrics([rows[i]["label"] for i in idx], [scores[i] for i in idx], threshold)
        if windows:
            total = sum(windows[i][0] for i in idx)
            used = sum(windows[i][1] for i in idx)
            m["windows_total"], m["windows_used"] = total, used
            m["window_coverage"] = _div(used, total)
            m["docs_truncated"] = sum(1 for i in idx if windows[i][1] < windows[i][0])
        out[src] = m
    return out


# ------------------------------------------------------------------ training
def resolve_revision(name: str, revision: str) -> str:
    """Resolve a branch/tag to an immutable commit sha on the Hub."""
    from huggingface_hub import HfApi
    return HfApi().model_info(name, revision=revision).sha


class Windows:
    """Tokenizes a document into sampled runtime-style windows."""

    def __init__(self, tokenizer, max_length: int, stride: int, max_windows: int):
        self.tok, self.max_length, self.stride, self.max_windows = tokenizer, max_length, stride, max_windows

    def __call__(self, text: str):
        enc = self.tok(text, add_special_tokens=True, truncation=True,
                       max_length=self.max_length, stride=self.stride,
                       return_overflowing_tokens=True)
        total = len(enc["input_ids"])
        picked = sample_indices(total, self.max_windows)
        feats = [{n: enc[n][i] for n in self.tok.model_input_names if n in enc} for i in picked]
        return self.tok.pad(feats, padding=True, return_tensors="pt"), total, len(picked)


def doc_margin(model, batch, device, low_memory=False):
    """Max window margin; checkpoint individual windows in low-memory training.

    Checkpointing recomputes activations during backward, retaining the same
    max-window loss and all sampled windows instead of dropping document coverage.
    Evaluation always streams windows because no backward activations are needed.
    """
    import torch
    if not low_memory and model.training and torch.is_grad_enabled():
        logits = model(**{k: v.to(device) for k, v in batch.items()}).logits
        return (logits[:, 1] - logits[:, 0]).max()

    names = tuple(batch)

    def window_margin(*inputs):
        logits = model(**dict(zip(names, inputs))).logits
        return (logits[:, 1] - logits[:, 0]).max()

    margins = []
    for index in range(batch["input_ids"].shape[0]):
        inputs = tuple(batch[name][index:index + 1].to(device) for name in names)
        if model.training and torch.is_grad_enabled():
            from torch.utils.checkpoint import checkpoint
            margins.append(checkpoint(window_margin, *inputs, use_reentrant=False,
                                      preserve_rng_state=True))
        else:
            margins.append(window_margin(*inputs))
    return torch.stack(margins).max()


def evaluate(model, windower, rows, device):
    import torch
    from tqdm import tqdm
    model.eval()
    scores, cover = [], []
    with torch.inference_mode():
        for row in tqdm(rows, desc="Evaluating", unit="doc"):
            batch, total, used = windower(row["text"])
            # round like the runtime (round(prob, 4)) so the threshold applies to served scores
            scores.append(round(float(torch.sigmoid(doc_margin(model, batch, device)).item()), 4))
            cover.append((total, used))
    return scores, cover


def report_split(rows, scores, cover, threshold):
    return {"overall": binary_metrics([r["label"] for r in rows], scores, threshold),
            "window_coverage": {"windows_total": sum(c[0] for c in cover),
                                "windows_used": sum(c[1] for c in cover)},
            "per_source": per_source_metrics(rows, scores, threshold, cover)}


def select_device(torch, requested):
    if requested == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    if requested == "cuda" and not torch.cuda.is_available():
        raise ValueError("CUDA is unavailable; use --device cpu or mps")
    if requested == "mps" and not torch.backends.mps.is_available():
        raise ValueError("Apple GPU (MPS) is unavailable; use --device cpu")
    return requested


def train(args) -> dict:
    import torch
    from tqdm import tqdm
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    data_dir, out_dir = Path(args.data_dir), Path(args.output_dir)
    paths = {s: data_dir / ("%s.jsonl" % s) for s in SPLITS}
    holdout_path = data_dir / ("%s.jsonl" % HOLDOUT)
    manifest_path = data_dir / "manifest.json"
    protected = list(paths.values()) + [holdout_path, manifest_path]
    check_output_dir(out_dir, protected)
    splits = {s: load_jsonl(p) for s, p in paths.items()}
    check_classes(splits)
    holdout = load_jsonl(holdout_path) if holdout_path.exists() else None
    check_leakage(dict(splits, **({HOLDOUT: holdout} if holdout else {})))
    provenance = {"input_sha256": {p.name: file_sha256(p) for p in paths.values()}}
    if holdout:
        provenance["input_sha256"][holdout_path.name] = file_sha256(holdout_path)
    if manifest_path.exists():
        provenance["input_sha256"][manifest_path.name] = file_sha256(manifest_path)
        provenance["manifest"] = json.loads(manifest_path.read_text(encoding="utf-8"))

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    device = torch.device(select_device(torch, args.device))
    print("Device: %s | training: %d documents | validation: %d | epochs: %d" % (
        device, len(splits["train"]), len(splits["validation"]), args.epochs),
        file=sys.stderr, flush=True)
    print("Loading base encoder and fresh classifier head...", file=sys.stderr, flush=True)

    revision = resolve_revision(args.base_model, args.base_revision)
    tok = AutoTokenizer.from_pretrained(args.base_model, revision=revision, trust_remote_code=False)
    model = AutoModelForSequenceClassification.from_pretrained(
        args.base_model, revision=revision, num_labels=2, id2label=ID2LABEL,
        label2id=LABEL2ID, use_safetensors=True, trust_remote_code=False).to(device)
    windower = Windows(tok, args.max_length, args.stride, args.max_windows)
    if args.low_memory:
        print("Low-memory mode: one window per forward; activation checkpointing enabled.",
              file=sys.stderr, flush=True)

    train_rows = splits["train"]
    steps = math.ceil(len(train_rows) / args.grad_accum) * args.epochs
    opt = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=0.01, foreach=False)
    sched = torch.optim.lr_scheduler.LambdaLR(
        opt, lambda s: min(1.0, (s + 1) / max(1, int(0.06 * steps))) * max(0.0, (steps - s) / steps))
    loss_fn = torch.nn.BCEWithLogitsLoss()

    best, history = None, []
    for epoch in range(1, args.epochs + 1):
        model.train()
        order = list(range(len(train_rows)))
        random.shuffle(order)
        total_loss = 0.0
        progress = tqdm(order, desc="Training epoch %d/%d" % (epoch, args.epochs), unit="doc")
        for n, i in enumerate(progress, 1):
            row = train_rows[i]
            batch, _, _ = windower(row["text"])
            target = torch.tensor(float(row["label"]), device=device)
            loss = loss_fn(doc_margin(model, batch, device, low_memory=args.low_memory), target)
            start = ((n - 1) // args.grad_accum) * args.grad_accum
            group = min(args.grad_accum, len(order) - start)  # final group may be partial
            (loss / group).backward()
            total_loss += loss.item()
            if n % 25 == 0 or n == len(order):
                progress.set_postfix(loss="%.4f" % (total_loss / n))
            if n % args.grad_accum == 0 or n == len(order):
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                opt.step(); sched.step(); opt.zero_grad(set_to_none=True)
        v_scores, _ = evaluate(model, windower, splits["validation"], device)
        v_labels = [r["label"] for r in splits["validation"]]
        chosen = choose_threshold(v_labels, v_scores, args.max_fpr)
        history.append({"epoch": epoch, "train_loss": total_loss / len(order),
                        "validation": chosen})
        print("epoch %d loss %.4f val f1 %.4f fpr %.4f" % (
            epoch, total_loss / len(order), chosen["f1"], chosen["fpr"]), file=sys.stderr)
        key = (chosen["recall"], chosen["f1"]) if args.max_fpr is not None else (chosen["f1"],)
        if best is None or key > best[0]:
            best = (key, epoch, chosen["threshold"],
                    {k: v.detach().cpu().clone() for k, v in model.state_dict().items()})

    _, best_epoch, threshold, state = best
    model.load_state_dict(state)
    v_scores, v_cover = evaluate(model, windower, splits["validation"], device)
    t_scores, t_cover = evaluate(model, windower, splits["test"], device)  # test: once, fixed threshold

    h_report = None
    if holdout:  # evaluated once, after model and threshold are final
        h_scores, h_cover = evaluate(model, windower, holdout, device)
        h_report = report_split(holdout, h_scores, h_cover, threshold)

    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(out_dir, safe_serialization=True)
    tok.save_pretrained(out_dir)
    report = {
        "device": str(device),
        "base_model": args.base_model, "base_revision_requested": args.base_revision,
        "base_revision_resolved": revision, "seed": args.seed, "best_epoch": best_epoch,
        "id2label": ID2LABEL, "threshold": threshold,
        "threshold_objective": "max_recall_at_fpr<=%s" % args.max_fpr if args.max_fpr is not None else "max_f1",
        "windowing": {"max_length": args.max_length, "stride": args.stride, "max_windows": args.max_windows},
        "hyperparameters": {k: getattr(args, k) for k in ("epochs", "lr", "grad_accum", "low_memory")},
        "split_sizes": dict({s: len(r) for s, r in splits.items()},
                            **({HOLDOUT: len(holdout)} if holdout else {})),
        "provenance": provenance,
        "history": history,
        "validation": report_split(splits["validation"], v_scores, v_cover, threshold),
        "test": report_split(splits["test"], t_scores, t_cover, threshold),
        HOLDOUT: h_report,
    }
    (out_dir / "training_report.json").write_text(json.dumps(report, indent=2))
    return report


def validate_args(args) -> None:
    for name in ("epochs", "grad_accum", "max_windows"):
        if getattr(args, name) < 1:
            raise ValueError("--%s must be >= 1" % name.replace("_", "-"))
    if not (math.isfinite(args.lr) and args.lr > 0):
        raise ValueError("--lr must be a positive finite number")
    if (args.max_length, args.stride) != (RUNTIME_MAX_LENGTH, RUNTIME_STRIDE):
        raise ValueError("max_length/stride must be %d/%d to match the runtime"
                         % (RUNTIME_MAX_LENGTH, RUNTIME_STRIDE))
    if args.max_fpr is not None and not (0 <= args.max_fpr <= 1):
        raise ValueError("--max-fpr must be within [0, 1]")


def parse_args(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data-dir", default="training/data")
    p.add_argument("--output-dir", required=True)
    p.add_argument("--base-model", default="distilbert/distilbert-base-uncased")
    p.add_argument("--base-revision", default="main", help="branch/tag/sha; resolved to a commit sha")
    p.add_argument("--device", choices=("auto", "cpu", "cuda", "mps"), default="auto",
                   help="auto uses CUDA if available, otherwise CPU; mps enables Apple GPU")
    p.add_argument("--low-memory", action="store_true",
                   help="train one window at a time with activation checkpointing; preserves coverage")
    p.add_argument("--epochs", type=int, default=3)
    p.add_argument("--lr", type=float, default=2e-5)
    p.add_argument("--grad-accum", type=int, default=8, help="documents per optimizer step")
    p.add_argument("--max-length", type=int, default=RUNTIME_MAX_LENGTH, help="must equal runtime (512)")
    p.add_argument("--stride", type=int, default=RUNTIME_STRIDE, help="must equal runtime (64)")
    p.add_argument("--max-windows", type=int, default=8)
    p.add_argument("--max-fpr", type=float, default=None,
                   help="select threshold maximising recall with validation FPR <= this (default: max F1)")
    p.add_argument("--seed", type=int, default=13)
    args = p.parse_args(argv)
    try:
        validate_args(args)
    except ValueError as exc:
        p.error(str(exc))
    return args


def main(argv=None) -> int:
    report = train(parse_args(argv))
    print(json.dumps({"threshold": report["threshold"], "test": report["test"]["overall"]}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
