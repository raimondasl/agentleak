"""Overlap between MiMo-V2.6-RL-oss (cyber) training tasks and CyberGym test tasks.

Both datasets are built from ARVO, a public set of reproducible OSS-Fuzz bugs. OSS-Fuzz
renumbered its bugs when it moved issue trackers, so one bug can carry an old (Monorail)
ID and a new ID. We translate with ARVO's own old->new mapping before matching.

Run:  uv run mimo_cybergym.py [--signatures]
Writes everything to out/.
"""

import argparse
import csv
import io
import json
import math
import re
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from datasets import load_dataset
from huggingface_hub import HfApi, hf_hub_download

# Pinned sources. Set a revision to None to use the current one (it is recorded in out/summary.json).
MIMO_REPO, MIMO_REV = "XiaomiMiMo/MiMo-V2.6-RL-oss", "639865fd3374018d6cb29b9fb82dd531406fcf5f"
CYBERGYM_REPO, CYBERGYM_REV = "sunblaze-ucb/cybergym", "bde190ded494e52bc684b66073b436c9d992c7c6"
ARVO_MAPPING = ("https://raw.githubusercontent.com/n132/ARVO/"
                "bc2a373c6b32fb3d9e7f86c516b1844885dcec51/arvo/oss_fuzz_mappings.csv")
ARVO_V1_META_TREE = ("https://api.github.com/repos/n132/ARVO-Meta/git/trees/"
                     "df107a1b3bc839de773b477a49e86d2d9ee75ff9")  # archive_data/meta @ 7e1a64f

OUT = Path(__file__).parent / "out"


def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "agentleak"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read().decode()


def trailing_int(s) -> int:
    return int(re.search(r"(\d+)$", str(s)).group(1))


def hypergeom(N: int, K: int, n: int, observed: int) -> dict:
    """Overlap expected if n items are drawn at random from a pool of N that contains K benchmark items."""
    mean = n * K / N
    var = n * (K / N) * (1 - K / N) * (N - n) / (N - 1)
    denom = math.comb(N, n)
    p_ge = sum(math.comb(K, k) * math.comb(N - K, n - k) for k in range(observed, min(K, n) + 1)) / denom
    return {"pool_N": N, "benchmark_in_pool_K": K, "sample_n": n, "expected": round(mean, 1),
            "sd": round(math.sqrt(var), 1), "observed": observed, "z": round((observed - mean) / math.sqrt(var), 2),
            "p_ge_observed": round(p_ge, 4)}


def load_mimo():
    path = hf_hub_download(MIMO_REPO, "cyber.parquet", repo_type="dataset", revision=MIMO_REV)
    rows = pq.read_table(path).to_pylist()
    tasks = []
    for r in rows:
        iid = r["extra_info"]["instance_id"]
        spec = r["prompt"][0]["content"] if r["prompt"] else ""
        m = re.search(r"in function `([^`]*)` in file `([^`]*)`", spec)
        t = re.search(r"Sanitizer: (.+?) in function", spec)
        tasks.append({"instance_id": iid, "num": trailing_int(iid), "spec": spec,
                      "type": t.group(1).strip() if t else "",
                      "function": m.group(1) if m else "", "file": m.group(2) if m else ""})
    return tasks


def load_cybergym(rev: str):
    ds = load_dataset(CYBERGYM_REPO, split="tasks", revision=rev)
    return [{"task_id": r["task_id"], "num": trailing_int(r["task_id"]), "project": r["project_name"]} for r in ds]


def load_mapping() -> dict:
    old2new = {}
    for row in csv.reader(io.StringIO(fetch(ARVO_MAPPING))):
        if len(row) >= 2 and row[0].strip().isdigit() and row[1].strip().isdigit():
            old2new[int(row[0])] = int(row[1])
    return old2new


def load_v1_pool() -> set:
    tree = json.loads(fetch(ARVO_V1_META_TREE))
    assert not tree.get("truncated"), "ARVO v1 meta tree truncated"
    return {trailing_int(Path(t["path"]).stem) for t in tree["tree"] if re.search(r"\d", t["path"])}


HARNESS_FUNCS = {"LLVMFuzzerInitialize", "LLVMFuzzerTestOneInput"}


def crash_type(error_txt: str) -> str:
    """Bug type from the sanitizer report, e.g. 'heap-buffer-overflow', 'SEGV', 'double-free'.
    The SUMMARY line carries the canonical name; fall back to the headline."""
    m = (re.search(r"SUMMARY: \w+Sanitizer: ([\w-]+)", error_txt)
         or re.search(r"(?:ERROR|WARNING): \w+Sanitizer: (?:attempting )?([\w-]+)", error_txt))
    return m.group(1) if m else ""


def first_stack(error_txt: str) -> list:
    """Frames (line text) of the first stack trace in a sanitizer report."""
    frames, started = [], False
    for line in error_txt.splitlines():
        if re.match(r"\s*#\d+ 0x[0-9a-f]+ in ", line):
            frames.append(line.strip())
            started = True
        elif started:
            break
    return frames


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--signatures", action="store_true",
                    help="download CyberGym error.txt for overlapping tasks and compare crash frames")
    args = ap.parse_args()
    OUT.mkdir(exist_ok=True)

    cg_rev = CYBERGYM_REV or HfApi().dataset_info(CYBERGYM_REPO).sha
    mimo, cg = load_mimo(), load_cybergym(cg_rev)
    old2new, v1 = load_mapping(), load_v1_pool()
    canon = lambda i: old2new.get(i, i)  # old Monorail ID -> new tracker ID; new IDs map to themselves

    # 1. Exact numeric matches (prefix ignored: MiMo writes arvo_N for new-tracker IDs, CyberGym oss-fuzz:N).
    exact = sorted({t["num"] for t in mimo} & {t["num"] for t in cg})
    exact_same_prefix = [n for n in exact if any(t["num"] == n and t["task_id"].startswith("arvo") for t in cg)]

    # 2. Translated matches on canonical bug IDs.
    mimo_by_bug, cg_by_bug = defaultdict(list), defaultdict(list)
    for t in mimo:
        mimo_by_bug[canon(t["num"])].append(t)
    for t in cg:
        cg_by_bug[canon(t["num"])].append(t)
    shared = sorted(set(mimo_by_bug) & set(cg_by_bug))
    cg_hit = [t for b in shared for t in cg_by_bug[b]]
    mimo_hit = [t for b in shared for t in mimo_by_bug[b]]
    dups = {b: ts for b, ts in mimo_by_bug.items() if len(ts) > 1}

    # 3. Chance baselines on the ARVO v1 pool (the first ARVO release), which all CyberGym ARVO tasks come from.
    v1_canon = {canon(i) for i in v1}
    assert len(v1_canon) == len(v1), "ARVO mapping collapses v1 IDs"
    cg_arvo_old = {t["num"] for t in cg if t["task_id"].startswith("arvo")}
    assert cg_arvo_old <= v1, "CyberGym ARVO task outside the ARVO v1 pool"
    mimo_old_in_pool = {t["num"] for t in mimo if t["num"] in v1}
    base_exact = hypergeom(len(v1), len(cg_arvo_old), len(mimo_old_in_pool), len(mimo_old_in_pool & cg_arvo_old))
    cg_arvo_canon = {canon(n) for n in cg_arvo_old}
    mimo_bugs_in_pool = {b for b in mimo_by_bug if b in v1_canon}
    base_bugs = hypergeom(len(v1_canon), len(cg_arvo_canon), len(mimo_bugs_in_pool),
                          len(mimo_bugs_in_pool & cg_arvo_canon))

    # MiMo tasks whose spec names a fuzzer entry point instead of a crash site in project code
    # (e.g. "ABRT in function `LLVMFuzzerInitialize`"). These look like environment defects.
    suspect = [t for t in mimo if t["function"] in HARNESS_FUNCS]

    # 4. Optional corroboration that matched IDs are the same crash. The identity itself comes from
    #    the ID mapping; here we check MiMo's spec against CyberGym's ground-truth sanitizer report.
    #    Control: MiMo specs of *other* overlapping bugs from the same project, to see how often
    #    the check passes by accident.
    sig = None
    if args.signatures:
        reports = {}
        for b in shared:
            kind, n = cg_by_bug[b][0]["task_id"].split(":")
            txt = Path(hf_hub_download(CYBERGYM_REPO, f"data/{kind}/{n}/error.txt",
                                       repo_type="dataset", revision=cg_rev)).read_text(errors="replace")
            reports[b] = (first_stack(txt), crash_type(txt))

        def grade(b, m):
            frames, cg_type = reports[b]
            if m["function"] in HARNESS_FUNCS:
                return "names_fuzzer_entry_point"
            fn = bool(m["function"]) and any(f" in {m['function']} " in f for f in frames)
            if fn and m["type"] and cg_type and m["type"].lower() == cg_type.lower():
                return "function_and_type"
            if fn:
                return "function_only"
            if m["file"] and any(m["file"].split("/", 1)[-1] in f for f in frames):
                return "file_only"
            return "no_match"

        order = ["function_and_type", "function_only", "file_only", "names_fuzzer_entry_point", "no_match"]
        best = {b: min((grade(b, m) for m in mimo_by_bug[b]), key=order.index) for b in shared}
        project = {b: cg_by_bug[b][0]["project"] for b in shared}
        control = [grade(b, m) for b in shared for b2 in shared
                   if b2 != b and project[b2] == project[b] for m in mimo_by_bug[b2]]
        cc = Counter(control)
        sig = {"checked": len(shared), "result": dict(Counter(best.values())),
               "not_function_and_type": [{"bug": b, "cybergym": cg_by_bug[b][0]["task_id"], "grade": g,
                                          "cybergym_type": reports[b][1],
                                          "mimo_spec": sorted({m["spec"] for m in mimo_by_bug[b]})}
                                         for b, g in best.items() if g != "function_and_type"],
               "control_same_project_other_bug": {"pairs": len(control), **dict(cc),
                                                  "function_and_type_rate": round(cc["function_and_type"] / max(len(control), 1), 3)}}

    # 5. Filtered split: drop bugs that are in CyberGym, keep one task per remaining bug (preferring a
    #    spec that names a real crash site), and drop bugs whose only spec names a fuzzer entry point.
    clean, dropped_suspect = [], 0
    for b, ts in mimo_by_bug.items():  # first-appearance order
        if b in cg_by_bug:
            continue
        good = [t for t in ts if t["function"] not in HARNESS_FUNCS]
        if good:
            clean.append(good[0]["instance_id"])
        else:
            dropped_suspect += len(ts)
    non_cg_tasks = sum(len(ts) for b, ts in mimo_by_bug.items() if b not in cg_by_bug)

    # Outputs
    with open(OUT / "overlap.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["canonical_bug_id", "cybergym_task_ids", "cybergym_project", "mimo_instance_ids", "match_type"])
        for b in shared:
            cts, mts = cg_by_bug[b], mimo_by_bug[b]
            match = "exact" if any(m["num"] == c["num"] for m in mts for c in cts) else "translated"
            w.writerow([b, ";".join(c["task_id"] for c in cts), cts[0]["project"],
                        ";".join(m["instance_id"] for m in mts), match])
    with open(OUT / "mimo_duplicates.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["canonical_bug_id", "mimo_instance_ids", "specs_identical"])
        for b, ts in sorted(dups.items()):
            w.writerow([b, ";".join(t["instance_id"] for t in ts), len({t["spec"] for t in ts}) == 1])
    (OUT / "mimo_cyber_clean_ids.txt").write_text("\n".join(clean) + "\n")
    with open(OUT / "mimo_suspect_specs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mimo_instance_id", "spec", "bug_in_cybergym"])
        for t in suspect:
            w.writerow([t["instance_id"], t["spec"], canon(t["num"]) in cg_by_bug])

    summary = {
        "sources": {"mimo": f"{MIMO_REPO}@{MIMO_REV} cyber.parquet", "cybergym": f"{CYBERGYM_REPO}@{cg_rev} split=tasks",
                    "arvo_mapping": ARVO_MAPPING, "arvo_v1_pool": ARVO_V1_META_TREE},
        "counts": {"mimo_tasks": len(mimo), "mimo_old_scheme_ids": sum(t["num"] < 10**6 for t in mimo),
                   "mimo_unique_issues": len(mimo_by_bug), "mimo_duplicated_issues": len(dups),
                   "mimo_duplicate_pairs_identical_prompt": sum(len({t["spec"] for t in ts}) == 1 for ts in dups.values()),
                   "mimo_suspect_specs": len(suspect), "cybergym_tasks": len(cg),
                   "cybergym_by_kind": dict(Counter(t["task_id"].split(":")[0] for t in cg)),
                   "arvo_v1_pool": len(v1), "mapping_pairs": len(old2new)},
        "overlap": {"exact_same_prefix": len(exact_same_prefix), "exact_any_prefix": len(exact),
                    "translated_cybergym_tasks": len(cg_hit),
                    "translated_cybergym_share": round(len(cg_hit) / len(cg), 4),
                    "translated_mimo_tasks": len(mimo_hit), "translated_unique_bugs": len(shared)},
        "chance_baseline": {"exact_ids_old_scheme": base_exact, "unique_bugs_translated": base_bugs},
        "filtered_split": {"kept": len(clean), "removed_cybergym_tasks": len(mimo_hit),
                           "removed_fuzzer_entry_point_only": dropped_suspect,
                           "removed_duplicate_copies": non_cg_tasks - len(clean) - dropped_suspect},
        "signature_check": sig,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("counts", "overlap", "chance_baseline", "filtered_split")}, indent=2))
    if sig:
        print("signatures:", json.dumps(sig["result"]), "| control:", json.dumps(sig["control_same_project_other_bug"]))


if __name__ == "__main__":
    main()
