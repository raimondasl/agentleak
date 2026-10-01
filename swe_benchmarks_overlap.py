"""Case 4: overlap between SWE benchmarks themselves (benchmark vs benchmark).

Case 3 found the same pull requests in a training set and in three multilingual SWE benchmarks. Here we compare the
benchmarks with each other: Multi-SWE-bench (with its Kotlin extension), SWE-PolyBench, SWE-bench Multilingual,
SWE-bench and SWE-bench Pro. A task is a pull request in a repo at a base commit. We join on exact and
case-insensitive (repo, PR), on (base commit, PR), and on the base commit alone (SWE-bench Pro has no PR numbers),
and compare fix patches by git blobs, as in cases 2 and 3.

Multi-SWE-bench's python/ folder is a copy of SWE-bench Verified, which Multi-SWE-bench states; it is left out here,
as in case 3.

Run:  uv run swe_benchmarks_overlap.py
Writes everything to out/swe_benchmarks/. Loaders and pinned revisions come from the case-3 script.
"""

import csv
import itertools
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from huggingface_hub import hf_hub_download

from mimo_cybergym import longest_common_run, words
from secbench_cybergym import blob_eq, patch_blobs
from swerebench_v2 import (MSB, MULTILINGUAL, POLY, POLY_VERIFIED, SWEBENCH, SWEBENCH_PRO, SWEBENCH_VERIFIED,
                           load_csv_bench, load_msb, load_multilingual, pr_number)

OUT = Path(__file__).parent / "out" / "swe_benchmarks"
PRO_FILES = ["data/default/test-00000-of-00001.parquet", "data/hard/test-00000-of-00001.parquet",
             "data/v1/test-00000-of-00001.parquet"]
NAMES = ["Multi-SWE-bench", "Multi-SWE-bench (Kotlin extension)", "SWE-PolyBench", "SWE-bench Multilingual",
         "SWE-bench", "SWE-bench Pro"]


def row(bench, iid, repo, pr, base, text, patch):
    return {"bench": bench, "id": iid, "repo": repo, "pr": pr, "base": (base or "").lower(), "text": text or "",
            "patch": patch or ""}


def load_swebench() -> list:
    path = hf_hub_download(SWEBENCH[0], "data/test-00000-of-00001.parquet", repo_type="dataset", revision=SWEBENCH[1])
    return [row("SWE-bench", r["instance_id"], r["repo"], pr_number(r["instance_id"]), r["base_commit"],
                r["problem_statement"], r["patch"]) for r in pq.read_table(path).to_pylist()]


def load_ids(repo_rev, f) -> set:
    path = hf_hub_download(repo_rev[0], f, repo_type="dataset", revision=repo_rev[1])
    return set(pq.read_table(path, columns=["instance_id"]).column("instance_id").to_pylist())


def load_pro() -> list:
    """All public configs (default, hard, v1), one row per instance_id. Pro names tasks by commit, not by PR."""
    rows = {}
    for f in PRO_FILES:
        path = hf_hub_download(SWEBENCH_PRO[0], f, repo_type="dataset", revision=SWEBENCH_PRO[1])
        for r in pq.read_table(path, columns=["instance_id", "repo", "base_commit", "problem_statement", "patch"]).to_pylist():
            rows.setdefault(r["instance_id"], row("SWE-bench Pro", r["instance_id"], r["repo"], None, r["base_commit"],
                                                  r["problem_statement"], r["patch"]))
    return list(rows.values())


def as_row(r):
    return row(r["bench"], r["id"], r["repo"], r["pr"], r["base"], r["text"], r["patch"])


KEYS = {
    "exact_repo_pr": lambda r: (r["repo"], r["pr"]) if r["pr"] is not None else None,
    "case_insensitive_repo_pr": lambda r: (r["repo"].lower(), r["pr"]) if r["pr"] is not None else None,
    "base_commit_and_pr": lambda r: (r["base"], r["pr"]) if r["pr"] is not None and r["base"] else None,
    "base_commit": lambda r: r["base"] or None,
}


def fix_relation(a, b):
    ba, bb = patch_blobs(a["patch"]), patch_blobs(b["patch"])
    shared = set(ba) & set(bb)
    same = sum(blob_eq(ba[f][0], bb[f][0]) and blob_eq(ba[f][1], bb[f][1]) for f in shared)
    return ("not_comparable" if not (ba and bb and shared) else "identical" if same == len(shared)
            else "partly_identical" if same else "different")


def changed_lines(patch: str) -> dict:
    """Per file, the sorted removed and added lines (whitespace-trimmed). A fallback for patches without
    'index a..b' lines, such as most of SWE-PolyBench's."""
    files, cur = {}, None
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            cur = line.split(" b/", 1)[-1]
            files[cur] = ([], [])
        elif cur and not line.startswith(("---", "+++")) and line[:1] in "-+":
            files[cur][line[0] == "+"].append(line[1:].strip())
    return {f: (tuple(sorted(r)), tuple(sorted(a))) for f, (r, a) in files.items()}


def fix_lines_relation(a, b):
    la, lb = changed_lines(a["patch"]), changed_lines(b["patch"])
    shared = set(la) & set(lb)
    same = sum(la[f] == lb[f] for f in shared)
    return ("not_comparable" if not shared else "identical" if same == len(shared)
            else "partly_identical" if same else "different")


def kind(p):
    """How a matched pair is related. The same PR (by name or by base commit) is the overlap; same PR at a different
    base commit is split by whether the fix blobs are identical. Same base commit with a different PR is a different
    task, reported but not counted."""
    j = p["joins"]
    if "base_commit_and_pr" in j:
        return "same PR, same base commit"
    if "case_insensitive_repo_pr" in j:
        return ("same PR, different base commit, identical fix" if p["fix"] == "identical"
                else f"same PR, different base commit, fix {p['fix']}")
    if p["a"]["pr"] is None or p["b"]["pr"] is None:
        return ("same base commit and identical fix (no PR number)" if p["fix"] == "identical"
                else "same base commit, fix not identical (no PR number)")
    return "same base commit, different PR"


def is_overlap(p):
    return p["kind"].startswith("same PR") or p["kind"] == "same base commit and identical fix (no PR number)"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    rows = ([as_row(r) for r in load_msb()] + [as_row(r) for r in load_csv_bench("SWE-PolyBench", POLY)]
            + [as_row(r) for r in load_multilingual()] + load_swebench() + load_pro())
    for r in rows:
        r["pr"] = int(r["pr"]) if r["pr"] is not None else None
    by_bench = {n: [r for r in rows if r["bench"] == n] for n in NAMES}
    subsets = {"SWE-PolyBench Verified": {r["id"] for r in load_csv_bench("SWE-PolyBench Verified", POLY_VERIFIED)},
               "SWE-bench Verified": load_ids(SWEBENCH_VERIFIED, "data/test-00000-of-00001.parquet")}

    # 1. Pairwise joins. Multi-SWE-bench and its own Kotlin extension are not compared with each other.
    pairs = {}
    for na, nb in itertools.combinations(NAMES, 2):
        if {na, nb} == {"Multi-SWE-bench", "Multi-SWE-bench (Kotlin extension)"}:
            continue
        idx = {k: defaultdict(list) for k in KEYS}
        for b in by_bench[nb]:
            for k, f in KEYS.items():
                if f(b) is not None:
                    idx[k][f(b)].append(b)
        for a in by_bench[na]:
            for k, f in KEYS.items():
                if f(a) is not None:
                    for b in idx[k].get(f(a), []):
                        pairs.setdefault((a["id"], b["id"]), {"a": a, "b": b, "joins": set()})["joins"].add(k)

    # 2. Same task? Fix patches by git blobs, base commit, and the relation kind.
    for p in pairs.values():
        p["fix"] = fix_relation(p["a"], p["b"])
        p["fix_lines"] = fix_lines_relation(p["a"], p["b"])
        p["same_base"] = bool(p["a"]["base"]) and p["a"]["base"] == p["b"]["base"]
        p["kind"] = kind(p)
        p["text_run"] = longest_common_run(words(p["a"]["text"]), words(p["b"]["text"]))

    # 3. Per benchmark pair: counts, shares, how the joins differ, fix and text.
    per_pair = {}
    for (na, nb) in itertools.combinations(NAMES, 2):
        ps = [p for p in pairs.values() if p["a"]["bench"] == na and p["b"]["bench"] == nb]
        if not ps:
            continue
        same = [p for p in ps if is_overlap(p)]
        runs = sorted(p["text_run"] for p in same)
        per_pair[f"{na} x {nb}"] = {
            "pairs_by_kind": dict(Counter(p["kind"] for p in ps)),
            "overlap_pairs": len(same),
            "overlap_items": {na: len({p["a"]["id"] for p in same}), nb: len({p["b"]["id"] for p in same})},
            "share_of_benchmark": {na: round(len({p["a"]["id"] for p in same}) / len(by_bench[na]), 4),
                                   nb: round(len({p["b"]["id"] for p in same}) / len(by_bench[nb]), 4)},
            "overlap_found_by_join": {k: sum(k in p["joins"] for p in same) for k in KEYS},
            "overlap_fix_by_blobs": dict(Counter(p["fix"] for p in same)),
            "overlap_fix_by_changed_lines_where_blobs_not_comparable": dict(
                Counter(p["fix_lines"] for p in same if p["fix"] == "not_comparable")),
            "overlap_in_subsets": {s: sum(p["a"]["id"] in ids or p["b"]["id"] in ids for p in same)
                                   for s, ids in subsets.items()},
            "overlap_by_repo": dict(Counter(p["a"]["repo"].lower() for p in same).most_common()),
            "overlap_longest_shared_text_run": {"median": statistics.median(runs) if runs else None,
                                                "min": runs[0] if runs else None,
                                                "pairs_ge_13": sum(x >= 13 for x in runs),
                                                "pairs_lt_13": [f"{p['a']['id']} / {p['b']['id']}: {p['text_run']}"
                                                                for p in same if p["text_run"] < 13]},
        }

    #    Per benchmark: tasks that are in at least one other benchmark (union over pairs), and tasks in all three
    #    multilingual benchmarks.
    others = defaultdict(lambda: defaultdict(set))
    for p in pairs.values():
        if is_overlap(p):
            others[p["a"]["bench"]][p["a"]["id"]].add(p["b"]["bench"])
            others[p["b"]["bench"]][p["b"]["id"]].add(p["a"]["bench"])
    in_any_other = {n: {"items": len(others[n]), "share": round(len(others[n]) / len(by_bench[n]), 4),
                        "in_two_other_benchmarks": sum(len(v) >= 2 for v in others[n].values())}
                    for n in NAMES}

    # 4. Shared repos (case-insensitive names) per benchmark pair, and renames revealed by same-task pairs.
    repos = {n: {r["repo"].lower() for r in by_bench[n]} for n in NAMES}
    renames = sorted({(p["a"]["repo"], p["b"]["repo"]) for p in pairs.values()
                      if is_overlap(p) and p["a"]["repo"].lower() != p["b"]["repo"].lower()})
    alias = {}
    for x, y in renames:
        alias[x.lower()] = y.lower()
    norm = lambda s: {alias.get(r, r) for r in s}
    shared_repos = {f"{na} x {nb}": sorted(norm(repos[na]) & norm(repos[nb]))
                    for na, nb in itertools.combinations(NAMES, 2) if norm(repos[na]) & norm(repos[nb])}
    #    Per shared repo: tasks in each benchmark and how many are the same PR. There is no common pool of PRs to draw
    #    a chance baseline from, so this is descriptive only.
    shared_repo_detail = {}
    for na, nb in itertools.combinations(NAMES, 2):
        for repo in sorted(norm(repos[na]) & norm(repos[nb])):
            ov = [p for p in pairs.values() if is_overlap(p) and p["a"]["bench"] == na and p["b"]["bench"] == nb
                  and alias.get(p["a"]["repo"].lower(), p["a"]["repo"].lower()) == repo]
            shared_repo_detail.setdefault(f"{na} x {nb}", {})[repo] = {
                na: sum(alias.get(r["repo"].lower(), r["repo"].lower()) == repo for r in by_bench[na]),
                nb: sum(alias.get(r["repo"].lower(), r["repo"].lower()) == repo for r in by_bench[nb]),
                "same_pr": len(ov)}

    # Outputs
    with open(OUT / "overlap_pairs.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["benchmark_a", "instance_a", "benchmark_b", "instance_b", "repo_a", "repo_b", "pr_a", "pr_b",
                    "joins", "kind", "same_base", "same_fix", "same_changed_lines", "longest_shared_text_run", "in_subsets"])
        for (ia, ib), p in sorted(pairs.items(), key=lambda kv: (kv[1]["a"]["bench"], kv[1]["b"]["bench"], kv[0])):
            subs = [s for s, ids in subsets.items() if ia in ids or ib in ids]
            w.writerow([p["a"]["bench"], ia, p["b"]["bench"], ib, p["a"]["repo"], p["b"]["repo"], p["a"]["pr"], p["b"]["pr"],
                        ";".join(sorted(p["joins"])), p["kind"], p["same_base"], p["fix"], p["fix_lines"], p["text_run"],
                        ";".join(subs)])

    summary = {
        "sources": {"multi_swe_bench": f"{MSB[0]}@{MSB[1]}", "swe_polybench": f"{POLY[0]}@{POLY[1]}",
                    "swe_polybench_verified": f"{POLY_VERIFIED[0]}@{POLY_VERIFIED[1]}",
                    "swe_bench_multilingual": f"{MULTILINGUAL[0]}@{MULTILINGUAL[1]}",
                    "swe_bench": f"{SWEBENCH[0]}@{SWEBENCH[1]} (test split)",
                    "swe_bench_verified": f"{SWEBENCH_VERIFIED[0]}@{SWEBENCH_VERIFIED[1]}",
                    "swe_bench_pro": f"{SWEBENCH_PRO[0]}@{SWEBENCH_PRO[1]} (default, hard and v1 configs, deduplicated by instance_id)"},
        "notes": ["Multi-SWE-bench's python/ folder (a copy of SWE-bench Verified, as Multi-SWE-bench states) is left out.",
                  "overlap = the same PR (any base commit; split by base commit and fix), or for SWE-bench Pro, which has no PR numbers, "
                  "the same base commit with identical fix blobs. Same base commit with a different PR is a different task and is not counted.",
                  "longest_shared_text_run compares the two benchmarks' problem texts (Multi-SWE-bench: resolved issues, title + body)."],
        "benchmark_items": {n: len(by_bench[n]) for n in NAMES},
        "patches_without_index_lines": {n: sum(not patch_blobs(r["patch"]) for r in by_bench[n]) for n in NAMES},
        "subset_items": {s: len(ids) for s, ids in subsets.items()},
        "benchmark_pairs": per_pair,
        "items_in_any_other_benchmark": in_any_other,
        "renames_found_by_same_task_pairs": renames,
        "shared_repos": {k: {"count": len(v), "repos": v} for k, v in shared_repos.items()},
        "shared_repo_detail": shared_repo_detail,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("benchmark_items", "items_in_any_other_benchmark",
                                              "renames_found_by_same_task_pairs")},
                     indent=2)[:9000])
    print("shared repos:", {k: v["count"] for k, v in summary["shared_repos"].items()})


if __name__ == "__main__":
    main()
