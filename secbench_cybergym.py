"""Overlap between two vulnerability-reproduction benchmarks: SEC-bench and CyberGym.

SEC-bench's `oss` split names OSS-Fuzz bugs by their new issue-tracker IDs, while CyberGym's ARVO tasks use
the old (Monorail) IDs, so we translate with ARVO's old->new mapping, as in case 1. Independently of IDs, we
compare fix patches: two tasks share a fix if every file both patches touch has the same git blob pair
(pre and post image). This also covers SEC-bench's `cve` split, which has no OSS-Fuzz IDs.

Run:  uv run secbench_cybergym.py
Writes everything to out/secbench_cybergym/. Shared helpers come from the case-1 script.
"""

import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path

from huggingface_hub import hf_hub_download

from mimo_cybergym import (ARVO_MAPPING, ARVO_V1_META_TREE, CYBERGYM_REPO, CYBERGYM_REV, NGRAM_SIZES,
                           bare_function_name, crash_type, fetch, first_stack, hypergeom, load_cybergym, load_mapping,
                           load_v1_pool, longest_common_run, ngrams, trailing_int, words)

SECBENCH_REPO, SECBENCH_REV = "SEC-bench/SEC-bench", "11422e774857272b8f5460c699dca7a64046308b"
SECBENCH_SPLITS = {"oss": "data/eval-oss.jsonl", "cve": "data/eval-cve.jsonl"}
# OSS-Fuzz project of each ARVO bug (keyed by new tracker ID), from ARVO at the same commit as the ID mapping.
ARVO_TRACKER_META = ("https://raw.githubusercontent.com/n132/ARVO/"
                     "bc2a373c6b32fb3d9e7f86c516b1844885dcec51/arvo/NewTracker/metadata.jsonl")

OUT = Path(__file__).parent / "out" / "secbench_cybergym"

# Text an agent sees in SEC-bench's current harness (poc-san and patch prompts) and in the paper-era harnesses.
SECBENCH_TEXT_FIELDS = {"bug_description + sanitizer_report": ("bug_description", "sanitizer_report"),
                        "sanitizer_report": ("sanitizer_report",), "bug_report": ("bug_report",)}
RUNTIME_PREFIXES = ("__asan", "__interceptor", "__sanitizer", "__msan", "__ubsan", "__lsan", "__hwasan")
BOILERPLATE_FILES = 3  # a 13-gram in this many CyberGym sanitizer reports is treated as sanitizer boilerplate
BOILERPLATE_SENSITIVITY = (2, 5)


def load_secbench() -> list:
    rows = []
    for split, path in SECBENCH_SPLITS.items():
        local = hf_hub_download(SECBENCH_REPO, path, repo_type="dataset", revision=SECBENCH_REV)
        for line in open(local, encoding="utf-8"):
            r = json.loads(line)
            r["split"] = split
            r["project"] = r["instance_id"].split(".", 1)[0]  # OSS-Fuzz project name, same as CyberGym's project_name
            r["ossfuzz_id"] = trailing_int(r["instance_id"]) if split == "oss" else None
            rows.append(r)
    return rows


def cybergym_file(task_id: str, name: str) -> str:
    kind, n = task_id.split(":")
    return Path(hf_hub_download(CYBERGYM_REPO, f"data/{kind}/{n}/{name}", repo_type="dataset",
                                revision=CYBERGYM_REV)).read_text(errors="replace")


def patch_blobs(patch: str) -> dict:
    """{path: (pre_blob, post_blob)} from the `index` lines of a git diff."""
    files, cur = {}, None
    for line in patch.splitlines():
        m = re.match(r"diff --git a/\S+ b/(\S+)", line)
        if m:
            cur = m.group(1)
            continue
        m = re.match(r"index ([0-9a-f]+)\.\.([0-9a-f]+)", line)
        if m and cur:
            files[cur] = (m.group(1), m.group(2))
            cur = None
    return files


def blob_eq(a: str, b: str) -> bool:
    """Abbreviated blob hashes differ in length between the datasets; compare on the common prefix."""
    n = min(len(a), len(b))
    return n >= 7 and a[:n] == b[:n]


def same_fix(a: dict, b: dict) -> bool:
    """Same fix if the patches share a file and every shared file has the same pre and post blob."""
    shared = set(a) & set(b)
    return bool(shared) and all(blob_eq(a[f][0], b[f][0]) and blob_eq(a[f][1], b[f][1]) for f in shared)


def top_project_frame(report: str) -> str:
    """Bare function name of the first symbolized stack frame outside the sanitizer runtime and libc;
    '' if the report has none (some SEC-bench reports are unsymbolized)."""
    for frame in first_stack(report):
        m = re.match(r"#\d+ 0x[0-9a-f]+ in (.+?) (\S+)\s*$", frame)  # last token: file:line or (module+offset)
        if not m:
            continue
        func, where = m.groups()
        if (func.startswith(RUNTIME_PREFIXES) or func.startswith("__libc") or "compiler-rt" in where
                or "llvm-project" in where or "glibc" in where or where.startswith("(")
                or "/lib/x86_64-linux-gnu/" in where):
            continue
        return bare_function_name(func)
    return ""


def crash_grade(a: str, b: str) -> str:
    """Compare two sanitizer reports by crash type and top project frame."""
    ta, tb = crash_type(a).lower(), crash_type(b).lower()
    fa, fb = top_project_frame(a), top_project_frame(b)
    same_type = bool(ta) and ta == tb
    if not (fa and fb):
        return "type_only_no_frame" if same_type else "no_match_no_frame"
    return {(True, True): "type_and_frame", (False, True): "frame_only",
            (True, False): "type_only", (False, False): "no_match"}[(same_type, fa == fb)]


def load_arvo_projects() -> dict:
    """New tracker ID -> OSS-Fuzz project, for ARVO's bugs."""
    rows = (json.loads(line) for line in fetch(ARVO_TRACKER_META).splitlines() if line.strip())
    return {int(r["localId"]): r["project"] for r in rows}


def stratified_hypergeom(strata: list, observed: int) -> dict:
    """Overlap expected if, within each stratum (pool N, benchmark items K, sample n), the sample were drawn
    uniformly at random. Exact one-sided p from the convolution of the per-stratum hypergeometrics."""
    mean = var = 0.0
    pmf = [1.0]
    for N, K, n in strata:
        if not n:
            continue
        mean += n * K / N
        var += n * (K / N) * (1 - K / N) * (N - n) / max(N - 1, 1)
        denom = math.comb(N, n)
        p = [math.comb(K, k) * math.comb(N - K, n - k) / denom for k in range(min(K, n) + 1)]
        pmf = [sum(pmf[i] * p[j - i] for i in range(len(pmf)) if 0 <= j - i < len(p)) for j in range(len(pmf) + len(p) - 1)]
    return {"strata": sum(1 for s in strata if s[2]), "expected": round(mean, 1), "sd": round(math.sqrt(var), 1),
            "observed": observed, "z": round((observed - mean) / math.sqrt(var), 2) if var else None,
            "p_ge_observed": round(sum(pmf[observed:]), 4)}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    sb, cg = load_secbench(), load_cybergym(CYBERGYM_REV)
    old2new, v1 = load_mapping(), load_v1_pool()
    canon = lambda i: old2new.get(i, i)
    cg_by_project = defaultdict(list)
    for t in cg:
        cg_by_project[t["project"]].append(t)
    cg_by_task = {t["task_id"]: t for t in cg}
    oss = [r for r in sb if r["split"] == "oss"]

    # 1. ID join for the oss split: plain (same number) and translated (same canonical OSS-Fuzz bug).
    cg_nums = {t["num"]: t for t in cg}
    cg_canon = defaultdict(list)
    for t in cg:
        cg_canon[canon(t["num"])].append(t)
    id_plain = {r["instance_id"]: [cg_nums[r["ossfuzz_id"]]["task_id"]] for r in oss if r["ossfuzz_id"] in cg_nums}
    id_translated = {r["instance_id"]: [t["task_id"] for t in cg_canon[canon(r["ossfuzz_id"])]]
                     for r in oss if canon(r["ossfuzz_id"]) in cg_canon}

    # 2. Same-fix join for both splits, against every CyberGym task in the same OSS-Fuzz project.
    candidates = sorted({t["task_id"] for r in sb for t in cg_by_project.get(r["project"], [])})
    cg_patch = {tid: patch_blobs(cybergym_file(tid, "patch.diff")) for tid in candidates}
    sb_patch = {r["instance_id"]: patch_blobs(r["patch"]) for r in sb}
    fix_match = {}
    for r in sb:
        hits = [t["task_id"] for t in cg_by_project.get(r["project"], [])
                if same_fix(sb_patch[r["instance_id"]], cg_patch[t["task_id"]])]
        if hits:
            fix_match[r["instance_id"]] = hits

    # 3. Crash check on every matched pair (either join): crash type and top project frame of SEC-bench's
    #    sanitizer report vs CyberGym's ground-truth report. Control: same-project pairs of different bugs.
    pairs = sorted({(s, c) for d in (id_translated, fix_match) for s, cs in d.items() for c in cs})
    report = {c: cybergym_file(c, "error.txt") for _, c in pairs}
    sb_by_id = {r["instance_id"]: r for r in sb}
    grade = {(s, c): crash_grade(sb_by_id[s]["sanitizer_report"], report[c]) for s, c in pairs}
    matched_cg = {c for _, c in pairs}
    control_pairs = {(s, c2) for s, c in pairs for c2 in matched_cg
                     if cg_by_task[c2]["project"] == cg_by_task[c]["project"] and (s, c2) not in grade}
    control = Counter(crash_grade(sb_by_id[s]["sanitizer_report"], report[c2]) for s, c2 in control_pairs)

    # 4. Chance baseline (oss split): if SEC-bench's bugs that are in ARVO's first release were a uniform draw
    #    from that pool, how many would be CyberGym tasks?
    v1_canon = {canon(i) for i in v1}
    cg_arvo_canon = {canon(t["num"]) for t in cg if t["task_id"].startswith("arvo")}
    sb_in_pool = {canon(r["ossfuzz_id"]) for r in oss if canon(r["ossfuzz_id"]) in v1_canon}
    observed = len(sb_in_pool & cg_arvo_canon)
    baseline = hypergeom(len(v1_canon), len(cg_arvo_canon), len(sb_in_pool), observed)
    #    Both benchmarks may favour the same projects, so also draw within each OSS-Fuzz project.
    arvo_project = load_arvo_projects()
    cg_project = {canon(t["num"]): t["project"] for t in cg}
    pool_project = {b: arvo_project.get(b) or cg_project.get(b) or "unknown" for b in v1_canon}
    by_project = defaultdict(lambda: [0, 0, 0])  # pool N, CyberGym K, SEC-bench n
    for b, p in pool_project.items():
        by_project[p][0] += 1
        by_project[p][1] += b in cg_arvo_canon
        by_project[p][2] += b in sb_in_pool
    baseline_by_project = {**stratified_hypergeom([tuple(v) for v in by_project.values()], observed),
                           "pool_bugs_without_project": sum(p == "unknown" for p in pool_project.values()),
                           "strata_with_secbench_bugs": {
                               p: {"pool": v[0], "cybergym": v[1], "secbench": v[2],
                                   "shared": sum(b in cg_arvo_canon for b in sb_in_pool if pool_project[b] == p)}
                               for p, v in sorted(by_project.items(), key=lambda kv: -kv[1][2]) if v[2]}}

    # 5. Text check, as in case 1: would a word n-gram filter between what a SEC-bench agent sees and CyberGym's
    #    level-1 text (vulnerability_description) flag the overlapping instances?
    overlap_ids = {s for s, _ in pairs}
    cg_words = {t["task_id"]: words(t["description"]) for t in cg}
    text = {}
    for label, fields in SECBENCH_TEXT_FIELDS.items():
        sb_words = {r["instance_id"]: words(" ".join(r[f] or "" for f in fields)) for r in sb}
        view = {}
        for n in NGRAM_SIZES:
            gram_to_cg = defaultdict(set)
            for tid, ws in cg_words.items():
                for g in ngrams(ws, n):
                    gram_to_cg[g].add(tid)
            hit = {i: set().union(*(gram_to_cg.get(g, set()) for g in ngrams(ws, n))) for i, ws in sb_words.items()}
            view[str(n)] = {"overlap_flagged": sum(bool(hit[s]) for s in overlap_ids),
                            "overlap_flagged_by_own_cybergym_task": sum(any(c in hit[s] for c in matched_cg if (s, c) in grade)
                                                                       for s in overlap_ids),
                            "overlap": len(overlap_ids),
                            "other_flagged": sum(bool(h) for i, h in hit.items() if i not in overlap_ids),
                            "other": len(sb) - len(overlap_ids)}
        runs = sorted(longest_common_run(sb_words[s], cg_words[c]) for s, c in pairs)
        text[label] = {"filter_view": view,
                       "pair_longest_shared_run": {"pairs": len(runs), "max": runs[-1], "median": runs[len(runs) // 2],
                                                   **{f"pairs_ge_{n}": sum(x >= n for x in runs) for n in NGRAM_SIZES}}}

    # 5b. CyberGym also publishes each bug's sanitizer report (error.txt, given to agents at levels 2-3). SEC-bench
    #     agents see the same kind of text (sanitizer_report). Compare those by 13-grams, raw and with sanitizer
    #     boilerplate removed (13-grams found in >= BOILERPLATE_FILES of the candidate error.txt files).
    cg_err_words = {tid: words(cybergym_file(tid, "error.txt")) for tid in candidates}
    err_grams = {tid: ngrams(ws, 13) for tid, ws in cg_err_words.items()}
    gram_files = Counter(g for gs in err_grams.values() for g in gs)
    sb_san = {r["instance_id"]: ngrams(words(r["sanitizer_report"] or ""), 13) for r in sb}
    other_same_project = {(s, c) for s, _ in pairs for c in candidates
                          if cg_by_task[c]["project"] == sb_by_id[s]["project"] and (s, c) not in grade}
    in_cg_projects = {r["instance_id"] for r in sb if r["project"] in cg_by_project}

    def err_view(min_files):
        boilerplate = {g for g, k in gram_files.items() if k >= min_files} if min_files else set()
        shares = lambda s, c: bool((sb_san[s] & err_grams[c]) - boilerplate)
        flagged = {r["instance_id"] for r in sb if any(shares(r["instance_id"], t["task_id"]) for t in cg_by_project.get(r["project"], []))}
        return {"same_bug_pairs_flagged": sum(shares(s, c) for s, c in pairs), "same_bug_pairs": len(pairs),
                "other_same_project_pairs_flagged": sum(shares(s, c) for s, c in other_same_project),
                "other_same_project_pairs": len(other_same_project),
                "filter_overlap_flagged": len(flagged & overlap_ids),
                "filter_overlap_flagged_by_own_cybergym_task": sum(any(shares(s, c) for c in matched_cg if (s, c) in grade)
                                                                  for s in overlap_ids),
                "filter_overlap": len(overlap_ids),
                "filter_other_flagged": len(flagged - overlap_ids), "filter_other": len(sb) - len(overlap_ids),
                "filter_other_in_cybergym_projects": len(in_cg_projects - overlap_ids)}

    err_check = {"scope": f"the {len(candidates)} CyberGym error.txt files in SEC-bench's projects (not all {len(cg)})",
                 "raw": err_view(0),
                 "without_boilerplate": {"boilerplate": f"13-grams found in at least {BOILERPLATE_FILES} of those files",
                                         **err_view(BOILERPLATE_FILES)},
                 "boilerplate_threshold_sensitivity": {str(k): err_view(k) for k in BOILERPLATE_SENSITIVITY}}

    # Outputs
    with open(OUT / "overlap.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["secbench_instance_id", "secbench_split", "cybergym_task_id", "project", "id_match",
                    "same_fix", "crash_check"])
        for s, c in pairs:
            idm = ("plain" if c in id_plain.get(s, []) else "translated" if c in id_translated.get(s, []) else "")
            w.writerow([s, sb_by_id[s]["split"], c, cg_by_task[c]["project"], idm, c in fix_match.get(s, []), grade[(s, c)]])

    def split_counts(ids):
        return dict(Counter(sb_by_id[s]["split"] for s in ids))

    no_index = [r["instance_id"] for r in sb if not sb_patch[r["instance_id"]]]
    empty_patch = [i for i in no_index if "diff --git" not in (sb_by_id[i]["patch"] or "")]
    (OUT / "secbench_not_in_cybergym.txt").write_text(
        "\n".join(r["instance_id"] for r in sb if r["instance_id"] not in overlap_ids) + "\n")
    # Does CyberGym's patch.diff cover every file of SEC-bench's gold patch, for the pairs that share a fix?
    fix_pairs = [(s, c) for s, cs in fix_match.items() for c in cs]
    covered = sum(set(sb_patch[s]) <= set(cg_patch[c]) for s, c in fix_pairs)
    summary = {
        "sources": {"secbench": f"{SECBENCH_REPO}@{SECBENCH_REV} " + " ".join(SECBENCH_SPLITS.values()),
                    "cybergym": f"{CYBERGYM_REPO}@{CYBERGYM_REV} split=tasks + data/*/*/patch.diff, error.txt",
                    "arvo_mapping": ARVO_MAPPING, "arvo_v1_pool": ARVO_V1_META_TREE,
                    "arvo_projects": ARVO_TRACKER_META},
        "counts": {"secbench_instances": dict(Counter(r["split"] for r in sb)), "cybergym_tasks": len(cg),
                   "secbench_projects": len({r["project"] for r in sb}),
                   "secbench_projects_in_cybergym": len({r["project"] for r in sb if r["project"] in cg_by_project}),
                   "cybergym_tasks_in_secbench_projects": len(candidates),
                   "secbench_patches_without_index_lines": split_counts(no_index),
                   "secbench_patches_with_no_diff": split_counts(empty_patch),
                   "cybergym_patches_without_index_lines": sorted(t for t in candidates if not cg_patch[t]),
                   "secbench_reports_without_symbolized_frame": split_counts(
                       [r["instance_id"] for r in sb if not top_project_frame(r["sanitizer_report"] or "")])},
        "id_join_oss": {"plain_instances": len(id_plain), "translated_instances": len(id_translated),
                        "translated_cybergym_tasks": len({c for cs in id_translated.values() for c in cs}),
                        "translated_by_cybergym_kind": dict(Counter(c.split(":")[0] for cs in id_translated.values() for c in cs))},
        "same_fix_join": {"instances": split_counts(fix_match),
                          "cybergym_tasks": len({c for cs in fix_match.values() for c in cs}),
                          "oss_id_overlaps_with_same_fix": sum(any(c in fix_match.get(s, []) for c in cs) for s, cs in id_translated.items()),
                          "oss_same_fix_without_id_match": sorted(s for s in fix_match if sb_by_id[s]["split"] == "oss" and s not in id_translated),
                          "cybergym_tasks_found_only_by_same_fix": sorted({c for s, cs in fix_match.items() for c in cs}
                                                                         - {c for cs in id_translated.values() for c in cs}),
                          "pairs": len(fix_pairs), "pairs_where_cybergym_patch_covers_every_secbench_file": covered},
        "overlap_union": {"instances": split_counts(overlap_ids), "cybergym_tasks": len(matched_cg),
                          "cybergym_share": round(len(matched_cg) / len(cg), 4)},
        "crash_check": {"pairs": len(pairs), "result": dict(Counter(grade.values())),
                        "result_by_join": {"id_translated": dict(Counter(grade[(s, c)] for s, cs in id_translated.items() for c in cs)),
                                           "same_fix_cve": dict(Counter(grade[(s, c)] for s, cs in fix_match.items() for c in cs
                                                                        if sb_by_id[s]["split"] == "cve"))},
                        "control_same_project_other_bug": {"pairs": sum(control.values()), **dict(control),
                                                           "type_and_frame_rate": round(control["type_and_frame"] / max(sum(control.values()), 1), 3)}},
        "chance_baseline_oss": {"uniform": baseline, "within_project": baseline_by_project,
                                "note": "SEC-bench oss bugs in ARVO's first release vs CyberGym ARVO tasks"},
        "text_check": text,
        "text_check_vs_cybergym_sanitizer_reports": err_check,
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
