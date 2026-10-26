# SafeParse IPI Corpus — initial curated collection

- **Task:** binary classification of untrusted text for indirect prompt injection.
- **Labels:** `0 = BENIGN`, `1 = INJECTION`.
- **Language:** predominantly English.
- **Size:** 9,280 unique curated examples (6,197 train; 1,449 validation; 1,517 test; 117 source-held-out).
- **Distribution:** intentionally security-focused, capped by source/class; not production attack prevalence.
- **Construction:** adaptation of five existing Hugging Face datasets, four contributing to training. No new attack generation or execution. Version-pinned sources and data checksums in `sources.json`; exact collection details in `collection-report.json`.
- **Inputs:** untrusted content only. Trusted requests, labels, judge rationales and attacker metadata are excluded from classifier features.
- **Label provenance:** original synthetic/competition annotations and matched controls; BIPIA/Nemotron benign controls are derived by exact payload removal, not independently certified clean.
- **Privacy:** public upstream datasets, some synthetic, some containing realistic email/contact/record identifiers. No claim that every identifier is fictitious or that these sources are PII-free. Do not log or publish payloads unnecessarily.
- **Licensing:** MIT, Apache-2.0, CC-BY-4.0 and CC-BY-SA-4.0 components. This collection is **not** relicensed as MIT. Preserve source dataset cards and original attribution; review component obligations before redistribution or publication of weights.
- **Safety:** payloads are adversarial text. They must never be interpreted as agent instructions, executed as code, or run with access to secrets/tools.
- **Use:** defensive detector development and evaluation in controlled environments. Not an authorization layer, nor a guarantee that content is safe.
- **Splits:** document/pair and repeated attack-template grouping where source metadata permits; approximate near-duplicate grouping elsewhere. These heuristics reduce leakage but do not prove all paraphrases or shared templates are isolated.
- **Important benchmark caveat:** the BIPIA mirror uses original BIPIA test attacks. Training on it invalidates treating the original BIPIA test set as independent unseen evaluation.
- **Holdout caveat:** deduplicated NEXUS has only five synthetic attack styles and no longer preserves all original pairs; it is a source-transfer smoke test, not a comprehensive benchmark.
- **Release gate:** manually audit labels, increase benign webpage/security-article coverage, compare against the current detector, measure per-source and end-to-end false-positive/false-negative behavior, and review licenses before replacing the runtime model.

See `README.md` for source links, attribution references, curation rules, reproducible commands and limitations. The local `safeparse-ipi-v1` model has now been trained on this collection and selected as the runtime default. Its report is saved beside the checkpoint; production reliability is not established by the curated results alone.
