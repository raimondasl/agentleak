# agentleak

Source-level overlap audits between open agentic training data and agentic benchmarks.

## Case 1: MiMo-V2.6-RL-oss (cyber) vs CyberGym

[MiMo-V2.6-RL-oss](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss) is Xiaomi's open set of RL environments. Its `cyber` config has 1,000 vulnerability-reproduction tasks: the agent must craft an input that triggers a specific known bug.

[CyberGym](https://huggingface.co/datasets/sunblaze-ucb/cybergym) is a benchmark for the same skill, with 1,507 tasks. 1,368 of them come from [ARVO](https://github.com/n132/ARVO), a public collection of reproducible OSS-Fuzz bugs, and 139 are newer bugs taken from OSS-Fuzz directly. MiMo's cyber tasks also come from ARVO.

Because both sets draw on the same pool, some bugs appear in both:

| | Count |
|---|---|
| MiMo cyber tasks sharing a bug number with a CyberGym task (`arvo_N` / `arvo:N`) | 139 (135 `arvo:`, 4 that CyberGym labels `oss-fuzz:`) |
| **CyberGym tasks whose bug is in the MiMo cyber set, after ID translation** | **223 of 1,507 (14.8%)** |
| MiMo cyber tasks whose bug is in CyberGym | 278 of 1,000 |
| Distinct OSS-Fuzz issues among the 1,000 MiMo cyber tasks | 836 (164 issues appear twice; 163 of those pairs have identical prompts) |

**Why ID translation matters.** OSS-Fuzz moved to a new issue tracker and its bugs got new IDs. The same bug can therefore carry an old ID (e.g. `54839`) and a new one (e.g. `42519792`). CyberGym's ARVO tasks use old IDs. MiMo's cyber tasks mix both: 445 old and 555 new. A plain ID join finds 139 of the 223 overlaps (62%). We translate with ARVO's old→new mapping (`arvo/oss_fuzz_mappings.csv`, 71,768 one-to-one pairs). The same translation also shows the 164 duplicated issues inside MiMo's cyber set.

**Is it the same crash?** Bug identity comes from the ID mapping. As a cross-check, we compare MiMo's task prompt (crash type, function, file) with CyberGym's ground-truth sanitizer report (`error.txt`):
- **215 of 223:** both the crash function and the crash type match. As a control, pairs from the same project but different bugs match this way only 7.7% of the time.
- **3:** match on file and crash type, but not on the exact function string.
- **4:** the MiMo prompt is "ABRT in function `LLVMFuzzerInitialize`". That is a fuzzer entry point, not the crash CyberGym records.
- **1 (libxslt 17171):** MiMo asks for a SEGV in the fuzz harness, while CyberGym records a heap-buffer-overflow in `xsltFormatNumberConversion`.

**How does this compare with chance?** All of CyberGym's 1,368 ARVO tasks come from ARVO's first release, a pool of 4,993 bugs.
- **Distinct bugs:** 710 of MiMo's distinct bugs fall in that pool. A uniform random draw of 710 would share about **195 ± 11** bugs with CyberGym. We observe **219**: z = 2.2, one-sided p = 0.015. 4 more overlaps are in CyberGym's newer OSS-Fuzz slice.
- **Exact old-scheme IDs:** 122 ± 9 expected, 135 observed (p = 0.08).
- **What it means:** the overlap is what you get when neither set is filtered against the other. The modest excess could come from both sets preferring similar bugs; we don't know. This is no evidence of targeting.

**Would an n-gram text filter have caught it?** Common decontamination filters drop a training item that shares a 13-word sequence (a 13-gram) with a benchmark item. We ran that test on two texts, both lowercased and split into words:
- MiMo's full task prompt;
- CyberGym's vulnerability description (`vulnerability_description`). Agents get this text at level 1, CyberGym's primary setting.

Results:
- **13-gram filter:** it flags **0 of the 278** overlapping MiMo tasks, and 0 of the other 722.
- **8-gram filter:** it flags 1 overlapping and 9 other tasks. All 10 match the same CyberGym task (`arvo:58770`), not their own bug, through the C++ type name `std::__1::basic_string<…>`.
- **Same-bug pairs:** for each of the 223 overlapping bugs, the CyberGym description and the MiMo prompt share at most 5 words in a row (median 2). So no exact n-gram filter with n of 6 or more can flag a same-bug pair, whatever it does with short items. (32 of the 223 descriptions are shorter than 13 words.)
- **Against the sanitizer report:** CyberGym also ships each bug's sanitizer report (`error.txt`), which agents get only at levels 2 and 3. MiMo's one-line crash spec (sanitizer, crash type, function, file) looks taken from such a report. Even so, only 6 of the 223 same-bug pairs share a 13-word sequence with it, and 19 share 8 or more words. Of the 6, four are long C++ function signatures and two are the same fuzzer file path. This compares same-bug pairs only; no filter was run against all 1,507 reports.

### What this does and does not show
- **Does:** about one in seven CyberGym tasks is a bug in this released training set, with the same project code and a grader that rewards triggering that crash. A model RL-trained on the `cyber` config and then evaluated on CyberGym is partly tested on bugs it practised on.
- **Does not:** show that any published score is inflated.
  - The task rows contain no reference PoCs. This README does not yet report on the Docker images.
  - It is not stated whether these 1,000 tasks were used to train the MiMo-V2.6 models.
  - The tech report's own RL runs on the released environments (§7.2, Table 6) evaluate cyber only on the in-house MiMo Cyber Bench (mini), not on CyberGym.
- **Does not:** cover other overlaps.
  - 223 counts identical OSS-Fuzz issues, so it is a lower bound. Re-reports of the same crash under a different issue ID are not checked.
  - Other ARVO/OSS-Fuzz-based benchmarks are not checked yet.
- **Does not:** cover other text filters. Only exact word n-grams were tested. Fuzzy, identifier-based or embedding-based matching was not tested and may catch part of the overlap. For 61 of the 219 overlapping bugs where MiMo's prompt names a target function, CyberGym's description names the same function.

### Other observation
26 MiMo cyber tasks name "ABRT in function `LLVMFuzzerInitialize`" as the target crash (`out/mimo_suspect_specs.csv`). That is the fuzzer's setup function, so these look like environment defects.

### Filtered split
`out/mimo_cyber_clean_ids.txt` lists **594** MiMo cyber tasks. Starting from 1,000, we removed:
- the 278 tasks whose bug is in CyberGym;
- duplicate copies, keeping one task per remaining issue and preferring a prompt that names a real crash site (108 removed);
- 20 tasks whose only prompt names `LLVMFuzzerInitialize`.

The split is filtered against CyberGym only.

### Reproduce
```
uv run mimo_cybergym.py --signatures
```
Pinned sources:
- `XiaomiMiMo/MiMo-V2.6-RL-oss@639865fd` `cyber.parquet`
- `sunblaze-ucb/cybergym@bde190de`, `tasks` split, plus `data/*/*/error.txt` for the crash check
- ARVO mapping @ `bc2a373c`
- ARVO-Meta first-release metadata tree @ `7e1a64f5`

Outputs in `out/`:
- `overlap.csv`: canonical issue ID, CyberGym task IDs, project, MiMo instance IDs, and match type (exact or translated)
- `mimo_duplicates.csv`
- `mimo_suspect_specs.csv`
- `mimo_cyber_clean_ids.txt`
- `text_overlap.csv`: per overlapping bug, the longest word sequence shared with CyberGym's task text and with its sanitizer report, and whether CyberGym's text names MiMo's target function
- `summary.json`: all counts, chance baselines, the crash check and its control, and the text check

## Case 2: SEC-bench vs CyberGym

[SEC-bench](https://huggingface.co/datasets/SEC-bench/SEC-bench) has two tasks, PoC generation and patching. CyberGym has one, PoC generation. Both are built from real vulnerabilities in C/C++ projects. SEC-bench has two splits:
- `cve`: 200 CVE instances, described in its paper.
- `oss`: 100 OSS-Fuzz bugs, added to the dataset in November 2025, after both versions of the paper.

Unlike case 1, this compares two benchmarks, not training data with a benchmark. Benchmarks sharing items is not a defect. It does mean that results on the shared bugs are not independent evidence. As in case 1, a plain ID join misses part of the overlap. Here it misses most of it: it finds 3 of 33.

| | Count |
|---|---|
| SEC-bench `oss` instances whose bug is a CyberGym task, plain ID join | 3 |
| ... after ID translation | **33 of 100** (30 `arvo:`, 3 `oss-fuzz:`) |
| SEC-bench `cve` instances that share a fix with a CyberGym task | 2 of 200 |
| CyberGym tasks involved | 36 of 1,507 (2.4%) |

**IDs.** SEC-bench names OSS-Fuzz bugs by their new tracker IDs, e.g. `php.ossfuzz-42491394`. CyberGym's ARVO tasks use the old IDs: the same bug is `arvo:29271`. A plain ID join finds only the 3 that CyberGym lists under new `oss-fuzz:` IDs.

**Same fix.** Independently of IDs, we compare fix patches. Two tasks share a fix when their patches touch at least one common file, and every common file has the same git blob before and after the change. Each SEC-bench instance is compared with every CyberGym task in its OSS-Fuzz project: 336 tasks across the 27 projects the two benchmarks share.
- All 33 ID overlaps share the fix, and no other `oss` instance does. In the `cve` split, 2 instances do: `jq.cve-2023-50246` (`arvo:64574`) and `libredwg.cve-2022-45332` (`arvo:54839`).
- One fix can cover more than one bug. `mupdf.ossfuzz-42537171` shares its fix with two CyberGym tasks, `oss-fuzz:42537171` and `oss-fuzz:42537168`.
- In all 36 pairs, CyberGym's `patch.diff` contains every file of SEC-bench's gold patch (its `patch` field), with the same blobs.

**Same crash?** As in case 1, we compare SEC-bench's sanitizer report with CyberGym's ground-truth report (`error.txt`) by crash type and top project frame (function name).
- In 27 of 36 pairs, both match. For same-project pairs of different bugs, this happens 1.0% of the time (2 of 202).
- Of the other 9: 6 match on crash type only (in 5 of them SEC-bench's report has no symbolized project frame), 2 on frame only, and 1 on neither.

**How does this compare with chance?** 79 of the 100 `oss` bugs are in ARVO's first release, the pool that all of CyberGym's ARVO tasks come from.
- **Uniform draw of 79 from that pool:** 21.6 ± 3.9 shared bugs expected. We observe **30**: z = 2.1, one-sided p = 0.025. The other 3 overlaps are in CyberGym's newer OSS-Fuzz slice, outside this pool.
- **Draw within each OSS-Fuzz project** (projects from ARVO's tracker metadata): 27.7 ± 3.6 expected, 30 observed, z = 0.6, p = 0.31.
- **What it means:** with each project's counts held fixed, the overlap is consistent with chance. The excess over a uniform draw comes from the project mix.
  - SEC-bench's pool bugs are concentrated in libxml2 (19), mruby (17), php (16), mupdf (7) and upx (5).
  - In four of these, CyberGym includes more than its overall 27% of ARVO's bugs: libxml2 34 of 87, mruby 38 of 83, mupdf 32 of 82, upx 12 of 14. php is the exception, at 20 of 101.
  - The baseline does not show how either benchmark chose bugs within a project.

**Would an n-gram text filter have caught it?** It depends on which CyberGym text the filter is run against.
- **Against CyberGym's vulnerability descriptions** (`vulnerability_description`, also shipped as `description.txt`; agents get it at level 1): no. We ran case 1's 13-gram test on the text SEC-bench shows agents:
  - `bug_description` + `sanitizer_report`, as in the current harness;
  - `sanitizer_report` (PoC task) or `bug_report` (patch task), as in the paper-era OpenHands harness.

  For each of these texts, the filter flags none of the 35 overlapping instances and none of the other 265. Same-bug pairs share at most 4 words in a row.
- **Against CyberGym's sanitizer reports** (`error.txt`, given to agents at levels 2 and 3): it flags most overlapping instances, plus extra flags. SEC-bench's `sanitizer_report` is the same kind of text.
  - We ran this filter only against the 336 CyberGym reports in SEC-bench's projects, not all 1,507.
  - We first dropped sanitizer boilerplate, defined as 13-grams found in at least 3 of those 336 reports.
  - It flags **29 of the 35** overlapping instances, 27 of them through their own bug's CyberGym report.
  - It also flags 40 of the other 265 instances, which neither join links to a CyberGym task. We did not check these further.
  - Per pair, a SEC-bench report shares a 13-gram with its own bug's CyberGym report in 28 of 36 cases, and with another CyberGym report in its project in 23 of 1,056.
  - With a boilerplate threshold of 2 or 5 reports instead of 3, the filter flags 25 or 30 of the 35 overlapping instances, and 33 or 53 of the other 265.

### What this does and does not show
- **Does:**
  - A third of SEC-bench's OSS-Fuzz split (33 of 100) are also CyberGym tasks, with the same fix.
  - For these bugs, results on the two benchmarks are not independent evidence.
  - CyberGym publishes each task's fix (`patch.diff` and `repo-fix`, which agents get at level 3). For these 35 instances, `patch.diff` contains SEC-bench's gold patch. A model trained on either benchmark's published files and then evaluated on the other would be tested partly on bugs whose fix and crash report it has seen. That is 35 of SEC-bench's 300 instances, or 36 of CyberGym's 1,507 tasks.
- **Does not:**
  - Show how either benchmark selected its bugs. Within projects, the overlap is consistent with chance, and the dataset card does not say how the `oss` bugs were chosen.
  - Say anything about any model's scores.
- **Does not:** cover every overlap.
  - Bugs that share neither an OSS-Fuzz ID nor a fix commit are not found, e.g. the same bug fixed by different commits.
  - Some patches cannot be compared because they have no `index` lines: 5 SEC-bench `oss` patches (2 of them have no diff at all) and 3 CyberGym patches.
- **Does not:** cover other text filters. Only exact word n-grams with case 1's word splitting were tested. Other word splitting, other boilerplate rules, and a filter against all 1,507 sanitizer reports may change the result against sanitizer reports.

### Filtered list
`out/secbench_cybergym/secbench_not_in_cybergym.txt` lists the **265** SEC-bench instances (both splits) that neither join finds in CyberGym.

### Reproduce
```
uv run secbench_cybergym.py
```
Pinned sources:
- `SEC-bench/SEC-bench@11422e77`: `data/eval-oss.jsonl` and `data/eval-cve.jsonl`
- `sunblaze-ucb/cybergym@bde190de`: `tasks` split, plus `patch.diff` and `error.txt` for the tasks in SEC-bench's projects
- ARVO @ `bc2a373c`: old→new mapping, and tracker metadata for each bug's project
- `n132/ARVO-Meta@7e1a64f5`, `archive_data/meta` (tree `df107a1b`): the first-release pool

Outputs in `out/secbench_cybergym/`:
- `overlap.csv`: one row per SEC-bench/CyberGym pair, with ID match (plain or translated), same fix and crash check
- `secbench_not_in_cybergym.txt`
- `summary.json`: all counts, both chance baselines with per-project counts, the crash check and its control, and both text checks with threshold sensitivity
