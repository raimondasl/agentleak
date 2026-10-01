"""Overlap between the SWE-rebench-V2 training sets and multilingual SWE benchmarks.

SWE-rebench-V2 (and its companion SWE-rebench-V2-PRs) are open SWE training sets built from GitHub pull requests.
We match them against Multi-SWE-bench (including its Kotlin extension), SWE-PolyBench (and its Verified subset) and
SWE-bench Multilingual on the pull request itself. Repo names are not stable (case differs between datasets and repos
get renamed), so besides exact and case-insensitive (repo, PR) joins we use a rename-proof key: (base commit, PR).

Run:  uv run swerebench_v2.py
Writes everything to out/swerebench_v2/. Shared helpers come from the case-1 and case-2 scripts.
"""

import csv
import gzip
import json
import math
import re
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from huggingface_hub import HfApi, HfFileSystem, hf_hub_download

from mimo_cybergym import NGRAM_SIZES, longest_common_run, ngrams, words
from secbench_cybergym import blob_eq, patch_blobs

# Pinned sources: (HF dataset repo, revision).
V2 = ("nebius/SWE-rebench-V2", "475dd5e8703bb5fb22dd3c60b5d038b019eba1e0")
V2_PRS = ("nebius/SWE-rebench-V2-PRs", "fbf0ecf50f268d5344149e2f0097db6bede83737")
MSB = ("ByteDance-Seed/Multi-SWE-bench", "56ff018c04a38e27ada1e9d0a6d5839a51f88f0d")
MSB_DISCARDED = ("ByteDance-Seed/Multi-SWE-RL", "9777648932daa214ba18c70c81e85821b5836f32",
                 "data_20240601_20250331/multi_swe_bench_discarded_instances.jsonl")
POLY = ("AmazonScience/SWE-PolyBench", "d56445f9940eae4e9d2974ec66820c2f1d7754e6")
POLY_VERIFIED = ("AmazonScience/SWE-PolyBench_Verified", "b3fca77b637379f0c01ad86d18753a7ac1998b53")
MULTILINGUAL = ("SWE-bench/SWE-bench_Multilingual", "846e647b9f33c0b51b739d005d13d85493c9af09")
SWEBENCH = ("SWE-bench/SWE-bench", "c6fe717fd7a4c3ac1daa4055a4fd082c6a1d28a2")
SWEBENCH_VERIFIED = ("SWE-bench/SWE-bench_Verified", "78f471bf655a3137b2e8a75af1501690ec009ec3")
SWEBENCH_PRO = ("ScaleAI/SWE-bench_Pro", "2d52cb3df914a3fcf80c7f66738b3a88ae37fc50")

OUT = Path(__file__).parent / "out" / "swerebench_v2"
CACHE = Path.home() / ".cache" / "agentleak"  # slim extract of Multi-SWE-bench's 1.8 GB of JSONL, keyed by revision
csv.field_size_limit(sys.maxsize if sys.maxsize < 2**31 else 2**31 - 1)


def pr_number(instance_id: str) -> int:
    """'owner__repo-1234' -> 1234 (owners and names can contain '-', so split on the last one)."""
    return int(instance_id.rsplit("-", 1)[1])


def item(bench, iid, repo, pr, base, text, patch, language=""):
    return {"bench": bench, "id": iid, "repo": repo, "pr": int(pr), "base": (base or "").lower(), "text": text or "",
            "patch": patch or "", "language": language}


def load_v2() -> list:
    path = hf_hub_download(V2[0], "data/train-00000-of-00001.parquet", repo_type="dataset", revision=V2[1])
    t = pq.read_table(path, columns=["instance_id", "repo", "base_commit", "problem_statement", "patch", "language"]).to_pylist()
    return [item("SWE-rebench-V2", r["instance_id"], r["repo"], pr_number(r["instance_id"]), r["base_commit"],
                 r["problem_statement"], r["patch"], r["language"]) for r in t]


def load_v2_prs_keys() -> list:
    """Key columns of all V2-PRs rows (2.7 GB of parquet; only these columns are fetched), with row locations."""
    fs, rows = HfFileSystem(), []
    files = sorted(f for f in HfApi().list_repo_files(V2_PRS[0], repo_type="dataset", revision=V2_PRS[1])
                   if f.endswith(".parquet"))
    for f in files:
        with fs.open(f"datasets/{V2_PRS[0]}@{V2_PRS[1]}/{f}", "rb") as fh:
            pf = pq.ParquetFile(fh)
            for g in range(pf.num_row_groups):
                t = pf.read_row_group(g, columns=["instance_id", "repo", "pull_number", "base_commit"]).to_pylist()
                rows += [{**item("SWE-rebench-V2-PRs", r["instance_id"], r["repo"], r["pull_number"], r["base_commit"], "", ""),
                          "loc": (f, g, i)} for i, r in enumerate(t)]
    return rows


def fill_v2_prs_text(rows: list):
    """Fetch problem_statement and patch only for the given V2-PRs rows."""
    fs, by_group = HfFileSystem(), defaultdict(list)
    for r in rows:
        by_group[r["loc"][:2]].append(r)
    for (f, g), group in by_group.items():
        with fs.open(f"datasets/{V2_PRS[0]}@{V2_PRS[1]}/{f}", "rb") as fh:
            t = pq.ParquetFile(fh).read_row_group(g, columns=["problem_statement", "patch"]).to_pylist()
        for r in group:
            r["text"], r["patch"] = t[r["loc"][2]]["problem_statement"] or "", t[r["loc"][2]]["patch"] or ""


def load_msb() -> list:
    """Multi-SWE-bench, one JSONL file per repo. python/ is a copy of SWE-bench Verified and is left out;
    kotlin/ is the Kotlin extension (added 2026-07-08)."""
    cache = CACHE / f"msb-{MSB[1]}.jsonl.gz"
    if not cache.exists():
        CACHE.mkdir(parents=True, exist_ok=True)
        fs = HfFileSystem()
        files = sorted(f for f in HfApi().list_repo_files(MSB[0], repo_type="dataset", revision=MSB[1])
                       if f.endswith(".jsonl") and not f.startswith("python/"))
        with gzip.open(cache, "wt", encoding="utf-8") as out:
            for f in files:
                with fs.open(f"datasets/{MSB[0]}@{MSB[1]}/{f}", "r", encoding="utf-8") as fh:
                    for line in fh:
                        if not line.strip():
                            continue
                        r = json.loads(line)
                        issues = " ".join(f"{i.get('title') or ''} {i.get('body') or ''}" for i in r.get("resolved_issues") or [])
                        out.write(json.dumps({"file": f, "org": r["org"], "repo": r["repo"], "number": r["number"],
                                              "base": (r.get("base") or {}).get("sha"), "text": issues,
                                              "patch": r.get("fix_patch")}) + "\n")
    rows = []
    for line in gzip.open(cache, "rt", encoding="utf-8"):
        r = json.loads(line)
        bench = "Multi-SWE-bench (Kotlin extension)" if r["file"].startswith("kotlin/") else "Multi-SWE-bench"
        rows.append(item(bench, f"{r['org']}__{r['repo']}-{r['number']}", f"{r['org']}/{r['repo']}", r["number"],
                         r["base"], r["text"], r["patch"], r["file"].split("/")[0]))
    return rows


def load_csv_bench(name, repo_rev) -> list:
    path = hf_hub_download(repo_rev[0], "test.csv", repo_type="dataset", revision=repo_rev[1])
    with open(path, newline="", encoding="utf-8") as f:
        return [item(name, r["instance_id"], r["repo"], float(r["pull_number"]), r["base_commit"], r["problem_statement"],
                     r["patch"]) for r in csv.DictReader(f)]


def load_multilingual() -> list:
    path = hf_hub_download(MULTILINGUAL[0], "data/test-00000-of-00001.parquet", repo_type="dataset", revision=MULTILINGUAL[1])
    return [item("SWE-bench Multilingual", r["instance_id"], r["repo"], pr_number(r["instance_id"]), r["base_commit"],
                 r["problem_statement"], r["patch"]) for r in pq.read_table(path).to_pylist()]


def repos_of(repo_rev, files) -> set:
    names = set()
    for f in files:
        path = hf_hub_download(repo_rev[0], f, repo_type="dataset", revision=repo_rev[1])
        names |= {r.lower() for r in pq.read_table(path, columns=["repo"]).column("repo").to_pylist()}
    return names


def stratified_test(strata: list, observed: int) -> dict:
    """Within each stratum (pool N, items in the training set K, benchmark items n), draw the benchmark items at random.
    Exact tails from the convolution of the per-stratum hypergeometrics."""
    mean = var = 0.0
    pmf = [1.0]
    for N, K, n in strata:
        if not n:
            continue
        mean += n * K / N
        var += n * (K / N) * (1 - K / N) * (N - n) / max(N - 1, 1)
        p = [math.comb(K, k) * math.comb(N - K, n - k) / math.comb(N, n) for k in range(min(K, n) + 1)]
        pmf = [sum(pmf[i] * p[j - i] for i in range(len(pmf)) if 0 <= j - i < len(p)) for j in range(len(pmf) + len(p) - 1)]
    return {"strata": sum(1 for s in strata if s[2]), "expected": round(mean, 1), "sd": round(math.sqrt(var), 1),
            "observed": observed, "z": round((observed - mean) / math.sqrt(var), 2) if var else None,
            "p_le_observed": round(sum(pmf[:observed + 1]), 4), "p_ge_observed": round(sum(pmf[observed:]), 4)}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    v2 = load_v2()
    benches = load_msb() + load_csv_bench("SWE-PolyBench", POLY) + load_multilingual()
    poly_verified = {r["id"] for r in load_csv_bench("SWE-PolyBench Verified", POLY_VERIFIED)}
    bench_names = ["Multi-SWE-bench", "Multi-SWE-bench (Kotlin extension)", "SWE-PolyBench", "SWE-bench Multilingual"]

    # 1. Joins, from strict to rename-proof: exact (repo, PR); case-insensitive (repo, PR); (base commit, PR).
    def index(rows, key):
        d = defaultdict(list)
        for r in rows:
            d[key(r)].append(r)
        return d

    keys = {"exact_repo": lambda r: (r["repo"], r["pr"]), "case_insensitive_repo": lambda r: (r["repo"].lower(), r["pr"]),
            "base_commit_and_pr": lambda r: (r["base"], r["pr"])}

    def join(train, label):
        idx = {k: index(train, f) for k, f in keys.items()}
        pairs, counts = {}, {}
        for name in bench_names:
            items = [b for b in benches if b["bench"] == name]
            counts[name] = {"benchmark_items": len(items)}
            for k, f in keys.items():
                hit = [b for b in items if f(b) in idx[k]]
                counts[name][k] = len(hit)
                for b in hit:
                    for t in idx[k][f(b)]:
                        pairs.setdefault((b["id"], t["id"]), {"bench": b, "train": t, "joins": set()})["joins"].add(k)
        if label == "SWE-rebench-V2":
            counts["SWE-PolyBench Verified (subset)"] = {
                "benchmark_items": len(poly_verified),
                **{k: len({bid for (bid, _), p in pairs.items() if bid in poly_verified and k in p["joins"]}) for k in keys}}
        for c in counts.values():
            c["share_by_base_commit_and_pr"] = round(c["base_commit_and_pr"] / c["benchmark_items"], 3)
        return pairs, counts

    v2_pairs, v2_counts = join(v2, "SWE-rebench-V2")
    v2_prs = load_v2_prs_keys()
    v2_prs_pairs, v2_prs_counts = join(v2_prs, "SWE-rebench-V2-PRs")
    fill_v2_prs_text([p["train"] for p in v2_prs_pairs.values()])

    # 2. Same task? Same base commit and same fix (git blob pairs, as in case 2), per matched pair.
    for p in list(v2_pairs.values()) + list(v2_prs_pairs.values()):
        b, t = p["bench"], p["train"]
        p["same_base"] = bool(b["base"]) and b["base"] == t["base"]
        bb, tb = patch_blobs(b["patch"]), patch_blobs(t["patch"])
        shared = set(bb) & set(tb)
        same = sum(blob_eq(bb[f][0], tb[f][0]) and blob_eq(bb[f][1], tb[f][1]) for f in shared)
        p["same_fix"] = ("not_comparable" if not (bb and tb and shared) else "identical" if same == len(shared)
                         else "partly_identical" if same else "different")
        p["same_file_set"] = bool(bb) and set(bb) == set(tb)

    # 3. Text check: would a 13-gram (or 8-gram) filter between the training set's problem statement and the
    #    benchmark's problem text flag the overlapping items? Filter view over all V2 rows; pair view for both sets.
    overlap_v2 = {p["train"]["id"] for p in v2_pairs.values()}
    text_check = {"benchmark_text": "Multi-SWE-bench: resolved issues (title + body); PolyBench and Multilingual: problem_statement",
                  "training_text": "problem_statement"}
    for n in NGRAM_SIZES:
        gram_to_bench = defaultdict(set)
        for b in benches:
            for g in ngrams(words(b["text"]), n):
                gram_to_bench[hash(g)].add(b["id"])
        own = {pid[1]: set() for pid in v2_pairs}
        for (bid, tid) in v2_pairs:
            own[tid].add(bid)
        flagged = flagged_own = other_flagged = 0
        for t in v2:
            hit = set().union(*(gram_to_bench.get(hash(g), set()) for g in ngrams(words(t["text"]), n)))
            if t["id"] in overlap_v2:
                flagged += bool(hit)
                flagged_own += bool(hit & own[t["id"]])
            else:
                other_flagged += bool(hit)
        text_check[f"v2_filter_{n}gram"] = {"overlap_flagged": flagged, "overlap_flagged_by_own_benchmark_item": flagged_own,
                                            "overlap": len(overlap_v2), "other_flagged": other_flagged,
                                            "other": len({t["id"] for t in v2}) - len(overlap_v2)}
    for label, pairs in (("v2", v2_pairs), ("v2_prs", v2_prs_pairs)):
        runs = sorted(longest_common_run(words(p["train"]["text"]), words(p["bench"]["text"])) for p in pairs.values())
        text_check[f"{label}_pairs_longest_shared_run"] = {
            "pairs": len(runs), "max": runs[-1] if runs else None, "median": statistics.median(runs) if runs else None,
            **{f"pairs_ge_{n}": sum(x >= n for x in runs) for n in NGRAM_SIZES}}

    #    Same issue text, different PR: non-overlapping V2 tasks whose problem statement is word-for-word a benchmark
    #    task's text (at least 13 words). The PR joins cannot see these.
    bench_by_text = defaultdict(list)
    for b in benches:
        ws = tuple(words(b["text"]))
        if len(ws) >= 13:
            bench_by_text[ws].append(b)
    text_check["same_issue_text_different_pr"] = [
        {"v2": t["id"], "benchmark": b["id"], "benchmark_name": b["bench"], "words": len(words(t["text"])),
         "benchmark_task_also_in_v2_by_pr": any(bid == b["id"] for bid, _ in v2_pairs)}
        for t in v2 if t["id"] not in overlap_v2 for b in bench_by_text.get(tuple(words(t["text"])), [])]

    # 4. Repo presence (case-insensitive names). A V2 repo that matches a benchmark PR by (base commit, PR) under a
    #    different name is treated as the same repo (renames), so presence is not undercounted.
    v2_repos = {t["repo"].lower() for t in v2}
    alias = {p["train"]["repo"].lower(): p["bench"]["repo"].lower() for p in v2_pairs.values()
             if p["train"]["repo"].lower() != p["bench"]["repo"].lower()}
    v2_repos_aliased = v2_repos | set(alias.values())
    presence = {}
    for name in bench_names:
        repos = {b["repo"].lower() for b in benches if b["bench"] == name}
        presence[name] = {"repos": len(repos), "in_v2": len(repos & v2_repos_aliased)}
    for name, repo_rev, files in (
            ("SWE-bench (test)", SWEBENCH, ["data/test-00000-of-00001.parquet"]),
            ("SWE-bench Verified", SWEBENCH_VERIFIED, ["data/test-00000-of-00001.parquet"]),
            ("SWE-bench (dev, not a test set)", SWEBENCH, ["data/dev-00000-of-00001.parquet"]),
            ("SWE-bench Pro (all public configs)", SWEBENCH_PRO, ["data/default/test-00000-of-00001.parquet",
                                                                  "data/hard/test-00000-of-00001.parquet",
                                                                  "data/v1/test-00000-of-00001.parquet"])):
        repos = repos_of(repo_rev, files)
        presence[name] = {"repos": len(repos), "in_v2": len(repos & v2_repos_aliased)}

    # 5. Inclusion baseline for Multi-SWE-bench: within each shared repo, are benchmark PRs in V2 at the same rate as
    #    PRs that Multi-SWE-bench's own pipeline collected and then discarded? (Kotlin extension excluded: different
    #    pipeline.) A low rate would suggest V2 filtered benchmark PRs; equal rates are consistent with no filtering.
    path = hf_hub_download(MSB_DISCARDED[0], MSB_DISCARDED[2], repo_type="dataset", revision=MSB_DISCARDED[1])
    discarded = {(f"{r['org']}/{r['repo']}".lower(), int(r["number"])) for r in map(json.loads, open(path, encoding="utf-8"))}
    v2_keys = {(alias.get(t["repo"].lower(), t["repo"].lower()), t["pr"]) for t in v2}
    msb_keys = {(b["repo"].lower(), b["pr"]) for b in benches if b["bench"] == "Multi-SWE-bench"}
    strata = []
    per_repo = {}
    for repo in sorted({k[0] for k in msb_keys | discarded} & v2_repos_aliased):
        bench_prs = {k for k in msb_keys if k[0] == repo}
        disc_prs = {k for k in discarded if k[0] == repo} - bench_prs
        pool = bench_prs | disc_prs
        in_v2 = pool & v2_keys
        strata.append((len(pool), len(in_v2), len(bench_prs)))
        per_repo[repo] = {"benchmark": len(bench_prs), "benchmark_in_v2": len(bench_prs & v2_keys),
                          "discarded": len(disc_prs), "discarded_in_v2": len(disc_prs & v2_keys)}
    observed = sum(v["benchmark_in_v2"] for v in per_repo.values())
    v2_range = defaultdict(list)
    for repo, pr in v2_keys:
        v2_range[repo].append(pr)
    strata_r, observed_r = [], 0
    for repo in per_repo:
        lo, hi = min(v2_range[repo]), max(v2_range[repo])
        bench_prs = {k for k in msb_keys if k[0] == repo and lo <= k[1] <= hi}
        pool = bench_prs | {k for k in discarded if k[0] == repo and lo <= k[1] <= hi}
        strata_r.append((len(pool), len(pool & v2_keys), len(bench_prs)))
        observed_r += len(bench_prs & v2_keys)
    inclusion = {**stratified_test(strata, observed), "discarded_list_size": len(discarded),
                 "within_v2_pr_range": stratified_test(strata_r, observed_r), "per_repo": per_repo,
                 "note": "pool = Multi-SWE-bench PRs + PRs its pipeline discarded, in repos also in V2; no date window"}

    # 6. Where the SWE-bench Multilingual overlaps are, by repo.
    ml_repos = Counter(p["bench"]["repo"] for p in v2_pairs.values() if p["bench"]["bench"] == "SWE-bench Multilingual")
    ml_prs_repos = Counter(p["bench"]["repo"] for p in v2_prs_pairs.values() if p["bench"]["bench"] == "SWE-bench Multilingual")

    # Outputs
    def write_pairs(path, pairs):
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["benchmark", "benchmark_instance_id", "in_polybench_verified", "training_instance_id",
                        "benchmark_repo", "training_repo", "pr", "joins", "same_base", "same_fix"])
            for (bid, tid), p in sorted(pairs.items()):
                w.writerow([p["bench"]["bench"], bid, bid in poly_verified, tid, p["bench"]["repo"], p["train"]["repo"],
                            p["bench"]["pr"], ";".join(sorted(p["joins"])), p["same_base"], p["same_fix"]])

    write_pairs(OUT / "overlap_v2.csv", v2_pairs)
    write_pairs(OUT / "overlap_v2_prs.csv", v2_prs_pairs)
    (OUT / "v2_not_in_benchmarks.txt").write_text("\n".join(sorted({t["id"] for t in v2} - overlap_v2)) + "\n")

    def fix_summary(pairs):
        return {"pairs": len(pairs), "same_base": sum(p["same_base"] for p in pairs.values()),
                "fix_by_blobs_of_shared_files": dict(Counter(p["same_fix"] for p in pairs.values())),
                "identical_and_same_file_set": sum(p["same_fix"] == "identical" and p["same_file_set"] for p in pairs.values()),
                "fix_not_comparable_because_benchmark_patch_has_no_index_lines": sum(
                    p["same_fix"] == "not_comparable" and not patch_blobs(p["bench"]["patch"]) for p in pairs.values())}

    summary = {
        "sources": {name: f"{r}@{rev}" for name, (r, rev, *_) in {
            "swe_rebench_v2": V2, "swe_rebench_v2_prs": V2_PRS, "multi_swe_bench": MSB, "multi_swe_bench_discarded": MSB_DISCARDED,
            "swe_polybench": POLY, "swe_polybench_verified": POLY_VERIFIED, "swe_bench_multilingual": MULTILINGUAL,
            "swe_bench": SWEBENCH, "swe_bench_verified": SWEBENCH_VERIFIED, "swe_bench_pro": SWEBENCH_PRO}.items()},
        "counts": {"v2_rows": len(v2), "v2_distinct_instance_ids": len({t["id"] for t in v2}),
                   "v2_prs_rows": len(v2_prs), "v2_prs_distinct_instance_ids": len({t["id"] for t in v2_prs}),
                   "v2_languages": len({t["language"] for t in v2}),
                   "multi_swe_bench_languages": len({b["language"] for b in benches if b["bench"] == "Multi-SWE-bench"}),
                   "benchmark_items": dict(Counter(b["bench"] for b in benches)), "polybench_verified_items": len(poly_verified)},
        "joins_v2": v2_counts, "joins_v2_prs": v2_prs_counts,
        "overlap_v2": {"distinct_v2_instances": len(overlap_v2), "repo_renames_found_by_base_commit": alias},
        "same_task_v2": fix_summary(v2_pairs), "same_task_v2_prs": fix_summary(v2_prs_pairs),
        "polybench_overlap_by_repo": dict(Counter(p["bench"]["repo"] for p in v2_pairs.values()
                                                  if p["bench"]["bench"] == "SWE-PolyBench").most_common()),
        "multilingual_overlap_by_repo": {"v2": dict(ml_repos), "v2_prs": dict(ml_prs_repos)},
        "repo_presence_in_v2": presence,
        "msb_inclusion_vs_discarded": inclusion,
        "text_check": text_check,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in summary if k not in ("sources",)}, indent=2)[:6000])


if __name__ == "__main__":
    main()
