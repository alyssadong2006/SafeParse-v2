# Runtime model checkpoints

This folder contains model artifacts used by the application, separate from the offline tooling in `training/`.

## Active checkpoint

`safeparse-ipi-v1/` is SafeParse's default locally trained DistilBERT injection detector. The default probability threshold is **0.5029**, selected using its validation set. Its files are:

```text
models/
├── README.md
└── safeparse-ipi-v1/             # git-ignored runtime artifacts
    ├── config.json              # BENIGN / INJECTION label mapping
    ├── model.safetensors        # Trained weights (~255 MiB)
    ├── tokenizer.json
    ├── tokenizer_config.json
    ├── special_tokens_map.json
    ├── vocab.txt
    └── training_report.json     # Provenance and evaluation results
```

The default path is anchored to the project root, independently of the working directory. Loading is strictly local, with remote code disabled and no external-model fallback. If the checkpoint is missing, inference fails explicitly; the application does not substitute a different detector.

## Deployment and future versions

Checkpoint subdirectories are git-ignored. New checkouts and deployments must receive the trained weights, configuration and tokenizer files separately. Keep the training report with the artifact for traceability. Local Docker builds include these files when present, but exclude training corpus/download caches.

Future training runs should use a new output directory, such as `--output-dir models/safeparse-ipi-v2`, rather than overwrite the active checkpoint. After reviewing that version, select it explicitly using `SAFEPARSE_GUARDRAIL_MODEL_NAME` and its validation-selected `SAFEPARSE_GUARDRAIL_MODEL_FLAG_THRESHOLD`. Restart the API process after changing configuration. Clear any environment override pointing to the former checkpoint location.

See [`training/README.md`](../training/README.md) for datasets, training commands and evaluation limitations. Curated benchmark results do not establish production webpage reliability.
