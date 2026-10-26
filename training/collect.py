"""Collect version-pinned IPI data. Dataset strings are data, never executable code."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import re
import shutil
import unicodedata
import urllib.request


HERE = Path(__file__).resolve().parent
SPLITS = ("train", "validation", "test")


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(text):
    # Only for deduplication/grouping; retain original Unicode in model inputs.
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def bucket(key, seed):
    value = int(digest(str(seed) + ":" + key)[:8], 16) / 2**32
    return "train" if value < .8 else "validation" if value < .9 else "test"


def jsonl(path):
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


def strings(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from strings(item, path + (str(key),))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from strings(item, path + (str(index),))
    elif isinstance(value, str):
        yield path, value


def download(source, filename, cache, offline):
    destination = cache / source["id"] / source["revision"] / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        if offline:
            raise ValueError("Missing cached file: " + str(destination))
        url = ("https://huggingface.co/datasets/" + source["repo"] + "/resolve/"
               + source["revision"] + "/" + filename)
        temporary = destination.with_suffix(destination.suffix + ".part")
        try:
            with urllib.request.urlopen(url, timeout=120) as response, temporary.open("wb") as out:
                size = 0
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > 100 * 1024 * 1024:
                        raise ValueError("Source exceeds 100 MiB download limit")
                    out.write(chunk)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
    checksum = hashlib.sha256()
    with destination.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            checksum.update(chunk)
    actual = checksum.hexdigest()
    expected = source.get("file_sha256", {}).get(filename)
    if expected is not None and actual != expected:
        raise ValueError("Checksum mismatch for " + str(destination))
    return destination, {"file": filename, "sha256": actual,
                         "bytes": destination.stat().st_size}


def record(source, row_id, text, label, group, quality, **metadata):
    return {"id": source["id"] + ":" + str(row_id), "text": text, "label": label,
            "source": source["id"], "repo": source["repo"],
            "revision": source["revision"], "license": source["license"],
            "label_quality": quality, "_groups": [group], **metadata}


def extract_bipia(source, paths, seed, audit):
    import pyarrow.parquet as pq
    clean_seen = set()
    for row in pq.read_table(paths[0]).to_pylist():
        text, attack = row["context"], row["attack_str"]
        if not attack or text.count(attack) != 1:
            audit["bipia_ambiguous_payload"] += 1
            continue
        if row["position"] == "start" and text.startswith(attack + "\n"):
            clean = text[len(attack) + 1:]
        elif row["position"] == "end" and text.endswith("\n" + attack):
            clean = text[:-len(attack) - 1]
        elif row["position"] == "middle" and "\n" + attack + "\n" in text:
            clean = text.replace("\n" + attack + "\n", "", 1)
        else:
            audit["bipia_unknown_insertion"] += 1
            continue
        host = "host:" + digest(canonical(clean))
        attack_group = "bipia_attack:" + row["attack_name"]
        split = bucket(host, seed)
        # BIPIA is a Cartesian product: splitting rows leaks BOTH hosts and attacks.
        # Partition these independently, then discard cross-partition combinations.
        if host not in clean_seen:
            clean_seen.add(host)
            item = record(source, host, clean, 0, host, "derived_exact_removal",
                          domain=row["task_name"], upstream_split=row["split_name"])
            item["_fixed_split"] = split
            yield item
        if split != bucket(attack_group, seed):
            audit["bipia_cross_partition_discarded"] += 1
            continue
        item = record(source, row["id"], text, 1, host, "upstream_attack_assembly",
                      domain=row["task_name"], attack_family=row["attack_name"],
                      upstream_split=row["split_name"], position=row["position"])
        item["_groups"].append(attack_group)
        item["_fixed_split"] = split
        yield item


def extract_llmail(source, paths, seed, audit):
    with paths[0].open(encoding="utf-8") as handle:
        data = json.load(handle)
    for text, annotation in data.items():
        # Never equate failure to trigger a tool with absence of injection.
        if annotation.get("attack_attempt") not in (True, "True"):
            audit["llmail_nonpositive_excluded"] += 1
            continue
        yield record(source, digest(text), text, 1, "mail:" + digest(canonical(text)),
                     "upstream_" + annotation.get("reason", "unknown"))
    with paths[1].open(encoding="utf-8") as handle:
        controls = json.load(handle)
    for text in controls:
        yield record(source, "control:" + digest(text), text, 0,
                     "mail:" + digest(canonical(text)), "upstream_fp_control")


def extract_nemotron(source, paths, seed, audit):
    for row in jsonl(paths[0]):
        attack = row["injection"]["injection_text"]
        matches = [(path, text) for path, text in strings(row["environment"])
                   if attack and attack in text]
        if len(matches) != 1 or matches[0][1].count(attack) != 1:
            audit["nemotron_ambiguous_payload"] += 1
            continue
        path, text = matches[0]
        clean = text.replace(attack, "", 1)
        group = "host:" + digest(canonical(clean)) if clean.strip() else "nemotron:" + str(row["id"])
        metadata = {"domain": row["domain"], "attack_family": row["attack_category"],
                    "environment_path": list(path)}
        item = record(source, row["id"], text, 1, group,
                      "upstream_synthetic_successful_attack", **metadata)
        item["_groups"].append("nemotron_attack:" + digest(canonical(attack)))
        yield item
        if clean.strip():
            yield record(source, str(row["id"]) + ":control", clean, 0, group,
                         "derived_exact_removal", **metadata)
        else:
            audit["nemotron_empty_control"] += 1


def extract_nexus(source, paths, seed, audit):
    for row in jsonl(paths[0]):
        row_id = row["instance_id"]
        label = 1 if row_id.endswith("-adv") else 0 if row_id.endswith("-ctrl") else None
        history = row["structured_plan"]["context"]["history"]
        if label is None or row["safety_label"] != label or not all(isinstance(x, str) for x in history):
            audit["nexus_label_mismatch"] += 1
            continue
        item = record(source, row_id, "\n".join(history), label,
                      "nexus_pair:" + row["control_pair_id"], "upstream_synthetic_pair",
                      attack_family=row["adversarial_type"])
        item["_fixed_split"] = "source_holdout"
        yield item


def extract_tool_response(source, paths, seed, audit):
    csv.field_size_limit(1024 * 1024)
    for path in paths:
        with path.open(encoding="utf-8", newline="") as handle:
            for index, row in enumerate(csv.DictReader(handle)):
                label = {"safe": 0, "injection": 1}.get(row["label"])
                if label is None:
                    audit["tool_response_unknown_label"] += 1
                    continue
                pair = "tool_response_pair:" + path.name + ":" + row["response_id"]
                split = bucket(pair, seed)
                item = record(source, path.name + ":" + str(index), row["text"], label,
                              pair, "upstream_synthetic_pair", upstream_split=path.name)
                if label:
                    attack = row["injection"]
                    if not attack.strip():
                        audit["tool_response_missing_attack"] += 1
                        continue
                    attack_group = "tool_response_attack:" + digest(canonical(attack))
                    if split != bucket(attack_group, seed):
                        audit["tool_response_cross_partition_discarded"] += 1
                        continue
                    item["_groups"].append(attack_group)
                item["_fixed_split"] = split
                yield item


EXTRACTORS = {"bipia": extract_bipia, "llmail": extract_llmail,
              "nemotron": extract_nemotron, "nexus": extract_nexus,
              "tool_response": extract_tool_response}


class Groups:
    def __init__(self, n):
        self.parent = list(range(n))

    def root(self, x):
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def join(self, a, b):
        a, b = self.root(a), self.root(b)
        self.parent[max(a, b)] = min(a, b)


def shingles(text):
    # Normalize numbers to catch small identifier/amount variants. Not model input.
    words = re.findall(r"\w+", re.sub(r"\d+", "0", canonical(text)))
    return {" ".join(words[i:i + 5]) for i in range(len(words) - 4)}


def curate(rows, seed, candidate_cap, per_class_cap, audit):
    valid = []
    for row in rows:
        if not isinstance(row["text"], str) or not row["text"].strip():
            audit["empty_text"] += 1
        elif len(row["text"]) > 50000:
            audit["over_50000_characters"] += 1
        else:
            valid.append(row)
    # Stable, hash-ranked candidate selection; never take just the first examples.
    selected = defaultdict(list)
    for row in valid:
        selected[(row["source"], row["label"])].append(row)
    rows = []
    for key in sorted(selected):
        items = sorted(selected[key], key=lambda r: digest(str(seed) + r["id"]))
        cap = len(items) if key[0] == "nexus" else candidate_cap
        audit["candidate_cap_discarded"] += max(0, len(items) - cap)
        rows.extend(items[:cap])
    groups = Groups(len(rows))
    index, bands = {}, defaultdict(list)
    sets = []
    for i, row in enumerate(rows):
        exact = "text:" + digest(canonical(row["text"]))
        numeric = "numeric_text:" + digest(re.sub(r"\d+", "0", canonical(row["text"])))
        for key in row["_groups"] + [exact, numeric]:
            if key in index:
                groups.join(i, index[key])
            else:
                index[key] = i
        tokens = shingles(row["text"])
        sets.append(tokens)
        if len(tokens) < 10:
            continue
        # One-permutation minhash with 16 bins, 8 bands. Candidate search only;
        # actual merges require shingle Jaccard >= .85. This is heuristic, not proof.
        sketch = [2**64 - 1] * 16
        for token in tokens:
            h = int.from_bytes(hashlib.blake2b(token.encode(), digest_size=8).digest(), "big")
            sketch[h % 16] = min(sketch[h % 16], h)
        candidates = set()
        for band in range(8):
            key = (band, tuple(sketch[2 * band:2 * band + 2]))
            # Skip empty bins, which are uninformative.
            if 2**64 - 1 in key[1]:
                continue
            candidates.update(bands[key])
            bands[key].append(i)
        for j in sorted(candidates):
            union = len(tokens | sets[j])
            if union and len(tokens & sets[j]) / union >= .85:
                groups.join(i, j)
                audit["near_duplicate_links"] += 1
    components = defaultdict(list)
    for i, row in enumerate(rows):
        components[groups.root(i)].append(row)
    result = defaultdict(list)
    exact_seen = set()
    for component in components.values():
        labels_by_text = defaultdict(set)
        fixed = {r["_fixed_split"] for r in component if "_fixed_split" in r}
        for row in component:
            labels_by_text[canonical(row["text"])].add(row["label"])
        if any(len(labels) > 1 for labels in labels_by_text.values()):
            audit["conflicting_label_component_rows"] += len(component)
            continue
        if len(fixed) > 1:
            audit["cross_fixed_split_component_rows"] += len(component)
            continue
        group_id = digest("|".join(sorted(r["id"] for r in component)))
        split = next(iter(fixed)) if fixed else bucket(group_id, seed)
        for row in sorted(component, key=lambda r: r["id"]):
            text_hash = digest(canonical(row["text"]))
            if text_hash in exact_seen:
                audit["exact_duplicates_removed"] += 1
                continue
            exact_seen.add(text_hash)
            row = {k: v for k, v in row.items() if not k.startswith("_")}
            row["leakage_group"] = group_id
            result[split].append(row)
    # Cap each source/class/split independently after grouping, not the test labels.
    for split, items in list(result.items()):
        if split == "source_holdout":
            continue
        partition = defaultdict(list)
        for row in items:
            partition[(row["source"], row["label"])].append(row)
        result[split] = []
        for key in sorted(partition):
            items = sorted(partition[key], key=lambda r: digest(str(seed) + r["id"]))
            audit["final_cap_discarded"] += max(0, len(items) - per_class_cap)
            result[split].extend(items[:per_class_cap])
    for split in SPLITS:
        if {r["label"] for r in result[split]} != {0, 1}:
            raise ValueError("Split lacks both classes: " + split + "; change seed/caps")
    return result


def collect(args):
    manifest = json.loads(args.sources.read_text(encoding="utf-8"))
    output, cache = args.output_dir.resolve(), args.cache_dir.resolve()
    if output == cache or output in cache.parents or cache in output.parents:
        raise ValueError("Output and cache must be non-overlapping directories")
    if output == args.sources.resolve() or output in args.sources.resolve().parents:
        raise ValueError("Output must not contain the source manifest")
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError("Output directory must be new or empty")
    audit, rows, provenance = Counter(), [], []
    for source in manifest["sources"]:
        print("Collecting " + source["repo"], flush=True)
        paths, files = [], []
        # Cache dataset cards too: licensing/attribution travels with the corpus.
        for filename in source["files"] + ["README.md"]:
            path, info = download(source, filename, args.cache_dir, args.offline)
            files.append(info)
            if filename != "README.md":
                paths.append(path)
        extracted = list(EXTRACTORS[source["id"]](source, paths, args.seed, audit))
        rows.extend(extracted)
        provenance.append({**source, "downloaded_files": files,
                           "extracted_class_counts": dict(Counter(str(r["label"]) for r in extracted))})
    splits = curate(rows, args.seed, args.candidate_cap, args.per_class_cap, audit)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_files, stats = {}, {}
    for split in (*SPLITS, "source_holdout"):
        items = sorted(splits[split], key=lambda r: r["id"])
        path = args.output_dir / (split + ".jsonl")
        with path.open("w", encoding="utf-8") as handle:
            for row in items:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        output_files[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        stats[split] = {"rows": len(items), "class_counts": dict(Counter(str(r["label"]) for r in items)),
                        "source_counts": dict(Counter(r["source"] for r in items)),
                        "label_quality_counts": dict(Counter(r["label_quality"] for r in items)),
                        "leakage_groups": len({r["leakage_group"] for r in items})}
    for source in manifest["sources"]:
        shutil.copyfile(args.cache_dir / source["id"] / source["revision"] / "README.md",
                        args.output_dir / (source["id"] + "_DATASET_CARD.md"))
    report = {"schema_version": 1, "seed": args.seed, "candidate_cap": args.candidate_cap,
              "per_source_class_split_cap": args.per_class_cap, "max_characters": 50000,
              "near_duplicate_jaccard": .85, "sources": provenance,
              "audit": dict(audit), "splits": stats, "file_sha256": output_files,
              "limitations": ["Near-duplicate search is heuristic; residual template leakage is possible.",
                              "Derived controls need manual label review before deployment.",
                              "BIPIA upstream test attacks are used; original BIPIA is not an independent benchmark.",
                              "Synthetic/source artifacts and non-production class ratios can inflate accuracy."]}
    (args.output_dir / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"splits": stats, "audit": dict(audit)}, indent=2))
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", type=Path, default=HERE / "sources.json")
    parser.add_argument("--cache-dir", type=Path, default=HERE / "raw")
    parser.add_argument("--output-dir", type=Path, default=HERE / "data")
    parser.add_argument("--seed", type=int, default=13)
    parser.add_argument("--candidate-cap", type=int, default=5000)
    parser.add_argument("--per-class-cap", type=int, default=1000)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    if args.candidate_cap < 1 or args.per_class_cap < 1:
        parser.error("caps must be positive")
    collect(args)


if __name__ == "__main__":
    main()
