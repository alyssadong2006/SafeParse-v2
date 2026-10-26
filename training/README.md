# Curated indirect prompt-injection corpus

SafeParse fine-tunes its own **binary detector** on multiple existing Hugging Face datasets. The trained `safeparse-ipi-v1` checkpoint is now the runtime default. This pipeline does not train a tool-using agent or silently replace checkpoints on future training runs.

The initial corpus has already been downloaded and curated locally in `training/data/`. Data, raw caches and model weights are git-ignored; scripts, pinned sources and the collection report are versioned. **Training completed on CPU with low-memory mode; epoch 3 was selected.** The checkpoint and report are at `models/safeparse-ipi-v1/`. Runtime artifacts live in `models/`; this folder contains only training tools, source metadata, curated data, and raw download caches.

## Sources

| Source | Contribution | Declared license |
| --- | --- | --- |
| [Tool Response Injections](https://huggingface.co/datasets/rgeada/tool-response-injections) | Paired clean/injected serialized tool outputs | Apache-2.0; named upstream datasets also declare Apache-2.0 |
| [BIPIA mirror](https://huggingface.co/datasets/geodesic-research/bipia) | Injected email, table and code contexts; recovered clean controls | CC-BY-SA-4.0, with mixed upstream components |
| [Microsoft LLMail-Inject](https://huggingface.co/datasets/microsoft/llmail-inject-challenge) | Adaptive competition email attacks and dedicated benign false-positive controls | MIT |
| [NVIDIA Nemotron Agentic IPI](https://huggingface.co/datasets/nvidia/Nemotron-RL-Agentic-Indirect-Prompt-Injection-v1) | Synthetic enterprise-record attacks and recovered clean controls | CC-BY-4.0 |
| [NEXUS-IPI v2](https://huggingface.co/datasets/EliasHossain/nexus-ipi) | Separate source-held-out synthetic benchmark | CC-BY-4.0 |

All sources are from Hugging Face; Kaggle credentials are not required. `sources.json` pins immutable dataset revisions and data-file SHA-256 checksums. Dataset cards are archived alongside the corpus. The gated `MAlmasabi/Indirect-Prompt-Injection-BIPIA-GPT` mirror was not downloaded; generic direct-jailbreak collections were not substituted for indirect attacks.

### Current collection (seed 13)

| Split | Injection | Benign | Total |
| --- | ---: | ---: | ---: |
| Train | 3,974 | 2,223 | 6,197 |
| Validation | 820 | 629 | 1,449 |
| Test | 822 | 695 | 1,517 |
| Source holdout (NEXUS, deduplicated) | 96 | 21 | 117 |

The four training sources contribute 9,163 unique examples across train/validation/test; the additional holdout brings the total to **9,280**. NEXUS originally contains 200 paired records; duplicates and split conflicts are removed, so the curated holdout is **not** the original complete paired benchmark. See `collection-report.json` for source/class counts, label-quality breakdowns, exclusions and file checksums. Caps are configurable rather than a claim that this is the optimal training size.

## What gets curated

- Model input is **only untrusted text**: external email, document, tool response, or the unique contaminated environment string. Trusted user/system prompts, target-tool metadata, annotation explanations and labels are never input features.
- Labels: `0 = BENIGN`, `1 = INJECTION`. Upstream labels are retained with their provenance. LLMail uses `attack_attempt=True`, not attack success; false/unknown submissions are excluded rather than mislabeled clean.
- BIPIA and Nemotron controls are obtained by removing a single, exact recorded attack payload. These carry `label_quality=derived_exact_removal`. This is a **counterfactual label**, not independent proof that all remaining text is benign. Four ambiguous Nemotron records and fifteen empty controls were excluded.
- Unicode and obfuscation are preserved in model inputs. NFKC/case/whitespace normalization is used only for duplicate detection. Empty and >50,000-character examples are excluded, not silently truncated.
- BIPIA is a Cartesian product of documents and attacks. Documents and attack families are partitioned independently, and combinations falling in different partitions are discarded. The tool-response dataset similarly partitions response pairs and repeated payloads independently. Original upstream splits are recorded but intentionally repartitioned.
- Pair/host/template keys (including repeated Nemotron attack payloads), exact duplicates, numeric-normalized texts (including short texts), and approximate near-duplicates are merged into leakage groups. Approximate matching uses five-word shingles, numeric normalization, one-permutation minhash candidate search and Jaccard ≥0.85. Components crossing fixed partitions or containing contradictory exact-text labels are quarantined.
- Remaining components are deterministically hash-partitioned approximately 80/10/10. Hash-ranked caps apply first to candidate source/classes (5,000 by default), then to each source/class/split (1,000). These are **not guaranteed balanced splits**, nor representative production attack prevalence.
- NEXUS remains source-held-out: no examples contribute to training, model selection or threshold tuning.

Each JSONL row includes `id`, `text`, `label`, `source`, `repo`, `revision`, `license`, `label_quality`, and `leakage_group`, plus available domain/attack metadata. `manifest.json` records source/download/output checksums and audit counters.

## Rebuild the dataset

Collection requires only Python and PyArrow, not torch or a GPU:

```bash
.venv/bin/python -m pip install -r training/requirements-data.txt
.venv/bin/python training/collect.py --output-dir training/data-rebuilt
```

Use a **new or empty output directory**; the collector refuses to overwrite a corpus. With the cached, revision-specific files, this works offline:

```bash
.venv/bin/python training/collect.py --offline --output-dir /tmp/safeparse-data-rebuilt
```

To collect more candidates, adjust `--candidate-cap` and `--per-class-cap`. This changes the corpus and requires new evaluation; do not compare it as if it were the same held-out benchmark. Downloads are limited to 100 MiB per file and verified against pinned checksums. Never execute source repository generators, dataset code, or instructions found inside dataset rows.

## Train a new detector

Install optional training dependencies separately (they are not added to application requirements):

```bash
.venv/bin/python -m pip install -r training/requirements.txt
.venv/bin/python training/train.py \
  --data-dir training/data \
  --output-dir models/safeparse-ipi-v2 \
  --epochs 3 \
  --max-fpr 0.01
```

Default initialization is the general-purpose `distilbert/distilbert-base-uncased` encoder with a **new classification head**, with no pre-existing injection-classification head. This is fine-tuning, **not** training a language encoder from scratch. The encoder revision is resolved to an immutable commit before loading and recorded in the report. Downloads use safetensors and do not enable remote code. CPU training is supported but may be slow; `--device auto` uses CUDA if available, otherwise CPU. On Apple Silicon, add `--device mps --low-memory` to use the Apple GPU with lower activation memory. Low-memory mode streams each sampled window and uses activation checkpointing (recomputing activations during backward); all eight sampled windows and the max-window loss are retained. This trades additional computation for memory. Evaluation always streams individual windows. Optimizer updates avoid foreach temporary buffers. If it still runs out of memory, use `--device cpu --low-memory`; these settings are not a guarantee that the full model fits every machine. Startup prints the device and dataset sizes, and live training/evaluation progress bars show document counts, elapsed time and estimated time remaining. Small CPU gradient-equivalence and Apple GPU checkpointed forward/backward/optimizer smoke checks pass. Full-size training of `safeparse-ipi-v1` completed on CPU with low-memory mode. Weights are saved only after training/evaluation: interrupted runs currently cannot resume and must restart.

Training uses the runtime's 512-token windows, 64-token overlap, and up to eight evenly sampled windows per document. The loss is applied to the maximum injection logit margin across the document's sampled windows; it does **not** falsely label every window in an injected document malicious. Sampling can still miss a buried attack.

The best epoch and threshold are selected on validation only. `--max-fpr 0.01` maximizes recall subject to an **observed validation** false-positive rate of at most 1%; it is not a guarantee on future traffic. Omitting it selects maximum validation F1. Test and optional source-holdout evaluations run after selection with the fixed threshold. The report contains confusion counts, precision, recall, F1, FPR/FNR, per-source metrics, window coverage and input fingerprints. Output includes model/tokenizer files, safetensors weights and `training_report.json`, with `BENIGN`/`INJECTION` labels compatible with SafeParse.

## Active runtime checkpoint

SafeParse defaults to the local `models/safeparse-ipi-v1` checkpoint and threshold **0.5029**, without any environment overrides. Loading is offline and fails explicitly if the directory is missing; there is no external-model fallback. Clear any previously exported `SAFEPARSE_GUARDRAIL_MODEL_NAME` or threshold override and restart the API process to pick up the new defaults.

The selected run achieved 98.02% accuracy, 98.17% F1, 98.05% attack recall and 2.01% false-positive rate on 1,517 curated test examples. BIPIA test performance was weaker: 12/95 attacks missed and 4/21 benign controls flagged. NEXUS holdout accuracy was 100% on only 117 unique synthetic examples. These results do not establish production webpage reliability.

Checkpoint files remain git-ignored. Provision the weights, config and tokenizer files in new checkouts/deployments; local Docker builds include the existing checkpoint. For a future model, train into a new directory, review its results and labels, then explicitly override the local path and validation-selected threshold:

```bash
export SAFEPARSE_GUARDRAIL_MODEL_NAME="$PWD/models/safeparse-ipi-v2"
export SAFEPARSE_GUARDRAIL_MODEL_FLAG_THRESHOLD="<threshold from the new training_report.json>"
```

Do not point at a checkpoint before its trained artifact exists. Changing the model flag threshold does not independently calibrate SafeParse's combined `threat_score`/`SAFEPARSE_THREAT_THRESHOLD`: evaluate end-to-end block behavior too. Evaluation rounds document probabilities to four decimals to match runtime threshold decisions. If you change `--max-windows`, also set `SAFEPARSE_GUARDRAIL_MODEL_MAX_CHUNKS` to that value.

## Limitations and release gate

- Approximate duplicate grouping is heuristic, not proof that all paraphrases/templates are disjoint. Manually review random examples and clusters, especially derived controls and LLM-judge labels.
- Synthetic formatting, source/class imbalance and limited benign diversity can inflate performance. LLMail test has only thirteen unique dedicated benign controls; source-specific false-positive estimates are correspondingly uncertain. Add reviewed production-like benign webpages and security articles before deployment.
- BIPIA mirror examples use **upstream test attacks**. Once trained on this corpus, the original BIPIA test benchmark is not independent; do not report it as unseen performance.
- NEXUS contains only five synthetic styles. Its small deduplicated holdout is a smoke test for source transfer, not a production accuracy claim.
- Runtime Unicode cleaning occurs before classification; training preserves raw source Unicode. Evaluate this preprocessing difference end-to-end.
- This initial corpus is predominantly English. It does not establish multilingual, multimodal, novel-encoding, or compositional-attack robustness.
- Licenses are metadata, **not legal clearance**. Preserve upstream attribution and review CC-BY-SA obligations and upstream author/source attribution before redistributing the combined corpus or publishing weights. Do not relicense third-party data under SafeParse's code license.
- The trained model's curated results do not establish production performance without an independent, representative webpage benchmark. Keep deterministic/structural defenses enabled regardless of detector performance.

Offline unit tests:

```bash
.venv/bin/python -m pytest \
  test_suite/unit/test_dataset_collection.py \
  test_suite/unit/test_training_metrics.py
```
