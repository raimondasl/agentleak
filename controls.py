"""Controls: open datasets that say they excluded a benchmark. Does the exclusion hold at the source level?

The cases found overlap where no exclusion was made. As a control, we check sets that state an exclusion:
- jm-rt/arvo-cybergym-2000, an ARVO-derived set in CyberGym's format whose card says its second half was "built
  outside the original CyberGym set": OSS-Fuzz ID joins against CyberGym, plain and after ID translation (case 1).
- SWE-Gym, R2E-Gym (Subset) and SWE-smith, which say they kept SWE-bench's test repositories out: repo presence
  against SWE-bench, and, for SWE-Gym (which has PR numbers), the case-3 PR joins.
Each control is also matched against the benchmarks it did not exclude, to show what a targeted exclusion leaves.

Run:  uv run controls.py
Writes everything to out/controls/. Loaders and pinned benchmark revisions come from the case scripts.
"""

import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import pyarrow.parquet as pq
from huggingface_hub import HfApi, hf_hub_download

from mimo_cybergym import CYBERGYM_REPO, CYBERGYM_REV, load_cybergym, load_mapping
from secbench_cybergym import SECBENCH_REPO, SECBENCH_REV, crash_grade, load_secbench, patch_blobs, same_fix
from swe_benchmarks_overlap import changed_lines
from swe_benchmarks_overlap import load_pro, load_swebench
from swerebench_v2 import (MSB, MULTILINGUAL, POLY, SWEBENCH, SWEBENCH_PRO, load_csv_bench, load_msb,
                           load_multilingual, pr_number)

OUT = Path(__file__).parent / "out" / "controls"
# Pinned control datasets: (HF dataset repo, revision).
JMRT = ("jm-rt/arvo-cybergym-2000", "75a80a9f1f534b26e31a502a5f7b0824565dfac1")
SWE_GYM = ("SWE-Gym/SWE-Gym", "bb94ed9e39bbeb96a7fcbfb533b80f25a7fd59cb")
R2E_GYM = ("R2E-Gym/R2E-Gym-Subset", "2e8108ff942f24fcb5686badfaf7f9a8808566d5")
SWE_SMITH = ("SWE-bench/SWE-smith", "ea6d7173829c7ec8fa16c22055699ff2e9188091")

STATED_EXCLUSIONS = {
    "jm-rt/arvo-cybergym-2000": "Dataset card: combines jm-rt/arvo-cybergym-1000 with a second 1000-task ARVO batch "
                                "'built outside the original CyberGym set'.",
    "SWE-Gym": "Paper (Pan et al., ICML 2025): its 11 repositories 'are separate from those used in SWE-Bench to avoid "
               "contamination'.",
    "R2E-Gym (Subset)": "Paper (Jain et al., COLM 2025): decontaminated by 'removing repositories overlapping with "
                        "SWE-Bench test-set repositories'.",
    "SWE-smith": "Paper (Yang et al., NeurIPS 2025): removed 'all 12 SWE-bench test repositories from consideration'.",
}


def parquet_rows(repo_rev, columns):
    files = sorted(f for f in HfApi().list_repo_files(repo_rev[0], repo_type="dataset", revision=repo_rev[1])
                   if f.endswith(".parquet"))
    rows = []
    for f in files:
        path = hf_hub_download(repo_rev[0], f, repo_type="dataset", revision=repo_rev[1])
        rows += pq.read_table(path, columns=columns).to_pylist()
    return rows


def sanitizer(report: str) -> str:
    for name in ("AddressSanitizer", "MemorySanitizer", "UndefinedBehaviorSanitizer", "LeakSanitizer"):
        if name in report:
            return name
    return "UndefinedBehaviorSanitizer" if "runtime error:" in report else ""


def cyber_control():
    """jm-rt/arvo-cybergym-2000 vs CyberGym (the benchmark it says it was built outside of) and SEC-bench."""
    path = hf_hub_download(JMRT[0], "tasks.json", repo_type="dataset", revision=JMRT[1])
    jm = json.load(open(path, encoding="utf-8"))
    old2new = load_mapping()
    canon = lambda i: old2new.get(i, i)
    jm_nums = {int(t["task_id"].split(":")[1]) for t in jm}
    cg = load_cybergym(CYBERGYM_REV)
    cg_nums = {t["num"] for t in cg}
    sb = [r for r in load_secbench() if r["split"] == "oss"]
    sb_oss = {r["ossfuzz_id"] for r in sb}
    jm_canon = {canon(i) for i in jm_nums}
    # Corroborate the SEC-bench ID matches. jm-rt ships each task's patch.diff and error.txt, but its patch.diff
    # diffs the vulnerable and fixed build trees, which can span more than the fix commit. So besides case 2's
    # strict blob test we check whether SEC-bench's fix lines are contained in jm-rt's diff, and compare crashes
    # (type + top project frame), with a control: same-project cross pairs of different matched bugs.
    jm_by_canon = {canon(i): i for i in jm_nums}
    fix, contained, crash, pairs, match_rows = Counter(), Counter(), Counter(), [], []
    for r in sb:
        c = canon(r["ossfuzz_id"])
        if c not in jm_by_canon:
            continue
        get = lambda name: Path(hf_hub_download(JMRT[0], f"data/arvo/{jm_by_canon[c]}/{name}", repo_type="dataset",
                                                revision=JMRT[1])).read_text(errors="replace")
        jp, err = get("patch.diff"), get("error.txt")
        # Paths look like tmp/arvo-hf-<N>-<x>/src-fix/<project dir>/<path>; reduce them to <path> in the project repo.
        a = patch_blobs(r["patch"] or "")
        b = {re.sub(r"^.*?/src-fix/[^/]+/", "", k): v for k, v in patch_blobs(jp).items() if "/src-fix/" in k}
        fix_kind = "not_comparable" if not (a and b) else "same_blob_pairs" if same_fix(a, b) else "different_blob_pairs"
        fix[fix_kind] += 1
        la = changed_lines(r["patch"] or "")
        lb = {re.sub(r"^.*?/src-fix/[^/]+/", "", k): v for k, v in changed_lines(jp).items()}
        shared = set(la) & set(lb)
        contained_kind = "not_comparable" if not shared else "contained" if all(
            not (Counter(la[f][0]) - Counter(lb[f][0])) and not (Counter(la[f][1]) - Counter(lb[f][1])) for f in shared
        ) else "not_contained"
        contained[contained_kind] += 1
        grade = crash_grade(r.get("sanitizer_report") or "", err)
        crash[grade] += 1
        pairs.append((r["project"], r.get("sanitizer_report") or "", err))
        match_rows.append({"secbench_instance": r["instance_id"], "jm_rt_task": f"arvo:{jm_by_canon[c]}",
                           "canonical_id": c, "strict_blob_test": fix_kind,
                           "fix_lines_contained": contained_kind,
                           "crash_check": grade, "secbench_sanitizer": sanitizer(r.get("sanitizer_report") or ""),
                           "jm_rt_sanitizer": sanitizer(err)})
    control = Counter(crash_grade(sa, eb) for (pa, sa, _), (pb, _, eb) in
                      ((x, y) for i, x in enumerate(pairs) for j, y in enumerate(pairs) if i != j and x[0] == y[0]))
    return {
        "tasks": len(jm), "distinct_ids": len(jm_nums),
        "task_id_kinds": dict(Counter(t["task_id"].split(":")[0] for t in jm)),
        "vs_cybergym": {"cybergym_tasks": len(cg), "plain_id_join": len(jm_nums & cg_nums),
                        "translated_id_join": len(jm_canon & {canon(i) for i in cg_nums})},
        "vs_secbench_oss": {"secbench_oss_instances": len(sb_oss), "plain_id_join": len(jm_nums & sb_oss),
                            "translated_id_join": len(jm_canon & {canon(i) for i in sb_oss}),
                            "translated_matches_strict_blob_test": dict(fix),
                            "translated_matches_crash_type_differs_by_sanitizers": dict(Counter(
                                f"jm-rt {m['jm_rt_sanitizer']} vs SEC-bench {m['secbench_sanitizer']}" for m in match_rows
                                if m["crash_check"] in ("no_match", "frame_only", "no_match_no_frame"))),
                            "translated_matches_fix_lines_contained": dict(contained),
                            "translated_matches_crash_check": dict(crash),
                            "crash_check_control_same_project_cross_pairs": dict(control),
                            "control_pairs_by_project": dict(Counter(
                                x[0] for i, x in enumerate(pairs) for j, y in enumerate(pairs) if i != j and x[0] == y[0])),
                            "ids": sorted(jm_canon & {canon(i) for i in sb_oss})},
        "jm_projects": len({t["project_name"] for t in jm}),
        "_rows": match_rows,
    }


def swe_controls():
    benches = {"SWE-bench (test)": load_swebench(), "SWE-bench Pro": load_pro()}
    for name, rows in (("Multi-SWE-bench", load_msb()), ("SWE-PolyBench", load_csv_bench("SWE-PolyBench", POLY)),
                       ("SWE-bench Multilingual", load_multilingual())):
        for r in rows:
            r["pr"] = int(r["pr"])
        benches[name] = rows
    for r in benches["Multi-SWE-bench"]:
        if r["bench"] != "Multi-SWE-bench":
            r["kotlin"] = True
    repos = {n: {r["repo"].lower() for r in rows} for n, rows in benches.items()}
    short = {n: {r.split("/")[-1] for r in rs} for n, rs in repos.items()}

    gym = [{"id": r["instance_id"], "repo": r["repo"], "pr": pr_number(r["instance_id"]), "base": (r["base_commit"] or "").lower()}
           for r in parquet_rows(SWE_GYM, ["instance_id", "repo", "base_commit"])]
    r2e = parquet_rows(R2E_GYM, ["repo_name", "commit_hash"])
    smith = parquet_rows(SWE_SMITH, ["instance_id"])
    smith_repos = {re.sub(r"__", "/", r["instance_id"].split(".")[0], count=1).lower() for r in smith}

    controls = {
        "SWE-Gym": {"tasks": len(gym), "repos": {r["repo"].lower() for r in gym}, "match": "owner/name"},
        "R2E-Gym (Subset)": {"tasks": len(r2e), "repos": {r["repo_name"].lower() for r in r2e},
                             "match": "repository name only (R2E-Gym lists no owners)"},
        "SWE-smith": {"tasks": len(smith), "repos": smith_repos, "match": "owner/name"},
    }
    # SWE-smith is mostly synthetic bugs, but its PR-mirror tasks (instance IDs '<owner>__<repo>.<commit>.pr_<N>')
    # revert real upstream PRs. Count them, and how many fall in repos shared with a benchmark.
    all_bench_repos = set().union(*repos.values())
    mirrors = [r["instance_id"] for r in smith if re.search(r"\.pr_\d+$", r["instance_id"])]
    mirror_repo = lambda iid: re.sub(r"__", "/", iid.split(".")[0], count=1).lower()
    smith_mirrors = {"pr_mirror_tasks": len(mirrors), "pr_mirror_repos": len({mirror_repo(i) for i in mirrors}),
                     "pr_mirror_tasks_in_repos_shared_with_a_benchmark": sum(mirror_repo(i) in all_bench_repos for i in mirrors),
                     "tasks_in_shared_repos": {repo: sum(re.sub(r"__", "/", r["instance_id"].split(".")[0], count=1).lower() == repo
                                                         for r in smith)
                                               for repo in sorted(smith_repos & all_bench_repos)}}
    presence = {}
    for c, info in controls.items():
        presence[c] = {"tasks": info["tasks"], "repos": len(info["repos"]), "repo_match": info["match"], "shared_repos": {}}
        for n in benches:
            shared = (info["repos"] & short[n]) if c.startswith("R2E") else (info["repos"] & repos[n])
            presence[c]["shared_repos"][n] = sorted(shared)

    # SWE-Gym has PR numbers: case-3 joins against every benchmark.
    pr_pairs = []
    for n, rows in benches.items():
        if n == "SWE-bench Pro":
            continue  # no PR numbers
        idx = defaultdict(list)
        for b in rows:
            idx[(b["repo"].lower(), b["pr"])].append(b)
        for g in gym:
            for b in idx.get((g["repo"].lower(), g["pr"]), []):
                pr_pairs.append({"swe_gym": g["id"], "benchmark": b["bench"], "benchmark_instance": b["id"],
                                 "same_base": bool(g["base"]) and g["base"] == b["base"]})
    gym_bases = {g["base"] for g in gym if g["base"]}
    base_only = {n: sum(b["base"] in gym_bases for b in rows) for n, rows in benches.items()}
    presence["SWE-smith"]["pr_mirrors"] = smith_mirrors
    return presence, pr_pairs, base_only, {n: len(rows) for n, rows in benches.items()}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    cyber = cyber_control()
    rows = cyber.pop("_rows")
    with open(OUT / "jm_rt_secbench_matches.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    presence, pr_pairs, base_only, bench_sizes = swe_controls()
    with open(OUT / "swe_gym_pr_matches.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["swe_gym", "benchmark", "benchmark_instance", "same_base"])
        w.writeheader()
        w.writerows(pr_pairs)
    summary = {
        "sources": {"jm_rt_arvo_cybergym_2000": f"{JMRT[0]}@{JMRT[1]}", "swe_gym": f"{SWE_GYM[0]}@{SWE_GYM[1]}",
                    "r2e_gym_subset": f"{R2E_GYM[0]}@{R2E_GYM[1]}", "swe_smith": f"{SWE_SMITH[0]}@{SWE_SMITH[1]}",
                    "cybergym": f"{CYBERGYM_REPO}@{CYBERGYM_REV}", "sec_bench": f"{SECBENCH_REPO}@{SECBENCH_REV}",
                    "swe_bench": f"{SWEBENCH[0]}@{SWEBENCH[1]}", "swe_bench_pro": f"{SWEBENCH_PRO[0]}@{SWEBENCH_PRO[1]}",
                    "multi_swe_bench": f"{MSB[0]}@{MSB[1]}", "swe_polybench": f"{POLY[0]}@{POLY[1]}",
                    "swe_bench_multilingual": f"{MULTILINGUAL[0]}@{MULTILINGUAL[1]}"},
        "stated_exclusions": STATED_EXCLUSIONS,
        "notes": ["Multi-SWE-bench excludes its python/ folder (a copy of SWE-bench Verified) and includes the Kotlin extension.",
                  "SWE-smith tasks are mostly synthetic bugs; its PR-mirror tasks (instance IDs ending .pr_N) revert real "
                  "upstream PRs, and swe_repo_presence.SWE-smith.pr_mirrors counts how many are in repos shared with a benchmark.",
                  "R2E-Gym tasks are commits without PR numbers; R2E-Gym lists repository names without owners."],
        "cyber_control": cyber,
        "swe_benchmark_sizes": bench_sizes,
        "swe_repo_presence": presence,
        "swe_gym_pr_join": {"pairs": len(pr_pairs), "by_benchmark": dict(Counter(p["benchmark"] for p in pr_pairs)),
                            "same_base": sum(p["same_base"] for p in pr_pairs)},
        "swe_gym_base_commit_in_benchmark": base_only,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: summary[k] for k in ("cyber_control", "swe_gym_pr_join", "swe_gym_base_commit_in_benchmark")}, indent=2))
    for c, v in presence.items():
        print(c, v["tasks"], "tasks,", v["repos"], "repos | shared:", {n: len(s) for n, s in v["shared_repos"].items()})
        for n, s in v["shared_repos"].items():
            if s:
                print("    ", n, s)


if __name__ == "__main__":
    main()
