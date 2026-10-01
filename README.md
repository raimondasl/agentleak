# agentleak

Source-level overlap audits between open agentic training data and agentic benchmarks, and between benchmarks. Each case is one script with pinned inputs. It matches items on their source (the OSS-Fuzz bug or the GitHub pull request), not on their text.

| Case | Pair | Shared items | Found by a plain ID or name join | Flagged by a 13-gram filter against the benchmark's task description |
|---|---|---|---|---|
| [1](#case-1-mimo-v26-rl-oss-cyber-vs-cybergym) | MiMo-V2.6-RL-oss cyber (training) vs CyberGym | 223 CyberGym tasks (278 MiMo tasks) | 139 of 223 | 0 of 278 |
| [2](#case-2-sec-bench-vs-cybergym) | SEC-bench vs CyberGym (benchmark vs benchmark) | 35 SEC-bench instances (36 CyberGym tasks) | 3 of the 33 `oss` matches | 0 of 35 |
| [3](#case-3-swe-rebench-v2-vs-multilingual-swe-benchmarks) | SWE-rebench-V2 (training) vs Multi-SWE-bench, SWE-PolyBench, SWE-bench Multilingual | 348 V2 tasks (+20 V2-PRs tasks) | 320 of 348 | 347 of 348 (V2-PRs: none of 20 pairs shares a 13-gram) |
| [4](#case-4-the-swe-benchmarks-themselves) | Multi-SWE-bench, SWE-PolyBench, SWE-bench Multilingual, SWE-bench, SWE-bench Pro, with each other (benchmark vs benchmark) | 132 same-PR pairs: 128 Multi-SWE-bench, 113 SWE-PolyBench and 23 SWE-bench Multilingual tasks | 130 of 132 pairs | 130 of 132 pairs share a 13-gram |

Against richer benchmark files the result can change. In case 2, a 13-gram filter against CyberGym's sanitizer reports flags 29 of 35, plus 40 of the other 265. In case 1, only 6 of 223 same-bug pairs share a 13-gram with CyberGym's report. Each section says what its finding does and does not show. None of them is a claim about any model's scores.

As a check on the method, the [controls](#controls-datasets-that-excluded-a-benchmark) section matches four datasets that say they excluded a benchmark. [Data and licenses](#data-and-licenses) lists what this repo publishes and each source's license.

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
- **Exact old-scheme IDs:** 122 ± 9 expected, 135 observed (z = 1.5, p = 0.08).
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

## Case 3: SWE-rebench-V2 vs multilingual SWE benchmarks

[SWE-rebench-V2](https://huggingface.co/datasets/nebius/SWE-rebench-V2) is an open training set of 32,079 software-engineering tasks built from GitHub pull requests in 20 languages. It was released in early 2026 for agent training, mainly RL. Its companion [SWE-rebench-V2-PRs](https://huggingface.co/datasets/nebius/SWE-rebench-V2-PRs) (126,300 rows) adds PRs that V2's pipeline did not link to an issue; for these, an LLM writes the problem statement from the PR ([paper](https://arxiv.org/abs/2602.23866), §3.6).

We compare both with three multilingual benchmarks built from the same kind of source, GitHub PRs that resolve an issue and come with tests that fail before the fix and pass after:
- **Multi-SWE-bench:** 1,632 tasks in 7 languages. A further 105 Kotlin tasks were contributed to its dataset repo in July 2026, after V2's release; below they are the "Kotlin extension".
- **SWE-PolyBench:** 2,110 tasks, with a 382-task Verified subset.
- **SWE-bench Multilingual:** 300 tasks.

A task is a PR in a repo at a base commit, so we match on the PR itself.

| Benchmark (tasks) | Shared with V2: exact repo + PR | case-insensitive repo + PR | base commit + PR | Share |
|---|---|---|---|---|
| Multi-SWE-bench (1,632) | 82 | 82 | **83** | 5.1% |
| Multi-SWE-bench, Kotlin extension (105) | 14 | 14 | **14** | 13.3% |
| SWE-PolyBench (2,110) | 224 | 224 | **239** | 11.3% |
| ... Verified subset (382) | 37 | 37 | **41** | 10.7% |
| SWE-bench Multilingual (300) | 0 | 12 | **12** | 4.0% |

**Names.** Repo names are not stable keys.
- **Letter case:** SWE-bench Multilingual stores every repo name in lowercase. All 12 of its overlaps are in 3 repos whose GitHub names have capitals (`briannesbitt/Carbon`, `PHP-CS-Fixer/PHP-CS-Fixer`, `PHPOffice/PhpSpreadsheet`), so an exact join finds none of them.
- **Renames:** V2 lists one matching clap PR under the old name `kbknapp/clap-rs`, and its prettier PRs under `jlongster/prettier`.
- **The fix:** the (base commit, PR) key needs no names and finds all of these.

In total, 348 of V2's 32,079 tasks (1.1%) match a benchmark task.

**Same task?** The name joins find no pair with a different base commit. Comparing fix patches by git blobs, as in case 2:
- 307 have the same blobs on every file both patches touch. 253 of them touch exactly the same files; in most of the rest, V2's diff also touches extra files.
- 9 are partly identical.
- 10 differ in every shared file despite the same PR and base commit; we did not check why.
- 22 cannot be compared, because those SWE-PolyBench patches have no blob hashes.

**Where the overlap is.** It is concentrated in a few repos:
- **SWE-PolyBench:** 202 of the 239 are `serverless/serverless`; keras has 21, prettier 15, transformers 1.
- **SWE-bench Multilingual:** all 12 are in three PHP repos: Carbon 6, PHP-CS-Fixer 3, PhpSpreadsheet 3.

**Were benchmark PRs filtered out?** For Multi-SWE-bench there is a reference set: its authors published 830 PRs that their pipeline collected and then removed (in Multi-SWE-RL). If V2 did not filter benchmark PRs, then within each repo that V2 shares with Multi-SWE-bench, benchmark PRs should be in V2 at about the same rate as removed ones.
- **Result:** 83 are in V2, against 77.4 expected (sd 4.1; z = 1.4; one-sided p = 0.93 for a shortfall). So we see no sign that V2 filtered Multi-SWE-bench PRs.
- **Dates:** the test ignores PR dates. Restricting each repo to the PR range V2 covers gives the same answer: 80.3 expected, z = 0.7, p = 0.81.
- **Power:** it has little power, because most PRs in these repos are benchmark PRs, so it would only detect heavy filtering.
- **A possible bias:** the removed PRs were discarded by Multi-SWE-bench's pipeline. V2's own quality filters may drop them more often, which could hide mild filtering.
- **Other benchmarks:** there is no comparable reference set for SWE-PolyBench or SWE-bench Multilingual, so we do not test those.

**Which benchmark repos are in V2 at all?** Repos are matched case-insensitively, with the two renames above.

| Benchmark | Repos | Also in V2 |
|---|---|---|
| SWE-bench (test) | 12 | 0 |
| SWE-bench Verified | 12 | 0 |
| SWE-bench Pro (public) | 11 | 0 |
| SWE-bench (dev split, not a test set) | 6 | 3 |
| Multi-SWE-bench | 39 | 16 |
| Multi-SWE-bench, Kotlin extension | 8 | 2 |
| SWE-PolyBench | 21 | 6 |
| SWE-bench Multilingual | 41 | 15 |

None of the 12 SWE-bench test repos (the same 12 as in Verified) is in V2. By contrast, each multilingual benchmark, including the Kotlin extension, shares a quarter or more of its repos with V2.

V2's authors explained this after our heads-up ([discussion #5](https://huggingface.co/datasets/nebius/SWE-rebench-V2/discussions/5), 2026-10-01):
- They excluded all repositories of the original SWE-bench, filtering by repository.
- They did not explicitly filter against the other benchmarks listed here.
- They said they will update the dataset card to explain this, add a warning about the overlaps, and link to this analysis and its ID lists.

Their answer covers the original SWE-bench only. For SWE-bench Pro, V2's paper says it keeps only repos with permissive licenses, which may explain why none of Pro's public repos, which are GPL or AGPL, is in V2.

**Would an n-gram text filter have caught it?** For V2, yes. V2 keeps each PR's original issue text, so 347 of the 348 overlapping tasks share a 13-gram with their own benchmark task (median longest shared run: 194.5 words). The last one has identical but very short text.
- The same filter also flags 1,249 of the other 31,731 V2 tasks (benchmark text includes the Kotlin extension). We did not classify these; a shared 13-gram alone does not make a task an overlap.
- 3 of them have word-for-word the same issue text as a benchmark task, but a different PR:
  - `valkey-io/valkey` #809 (SWE-bench Multilingual: #790);
  - `zeromicro/go-zero` #2041 (Multi-SWE-bench: #2032);
  - `briannesbitt/Carbon` #2667 (Multilingual: #2665, which is already among the 348).

For V2-PRs, whose problem statements are written by an LLM, no. None of its 20 overlapping PRs shares even an 8-gram with the benchmark text; the longest shared run is 6 words.

### What this does and does not show
- **Does:**
  - 348 SWE-rebench-V2 tasks are the same PR at the same base commit as a benchmark task.
  - A model trained on V2 and then evaluated on one of these benchmarks is partly evaluated on its own training tasks: 4.0% of SWE-bench Multilingual, 5.1% of Multi-SWE-bench and 11.3% of SWE-PolyBench (10.7% of its Verified subset). It is 13.3% of the Kotlin extension.
  - V2-PRs adds a few more by repo and PR: Multi-SWE-bench 3, SWE-PolyBench 6, SWE-bench Multilingual 11. 6 of the 11 Multilingual ones have the same base commit.
- **Does not:**
  - Show that V2's builders chose benchmark PRs or broke a rule they stated. V2's authors say they excluded the original SWE-bench's repositories and did not explicitly filter against these benchmarks. Multi-SWE-bench PRs are in V2 at about the rate of the PRs Multi-SWE-bench's pipeline removed.
  - Mean that V2's builders could have avoided the Kotlin overlap. Those tasks were added to Multi-SWE-bench after V2 was released.
  - Say anything about any model's scores.
  - Cover every overlap.
    - Only PR-level matches are counted. The same issue fixed in a different PR is not counted; the text check found 3 such V2 tasks.
    - Repo presence uses names, and renames are resolved only where a PR match reveals them.
- **Unlike cases 1 and 2:** a 13-gram filter on the problem statements would catch V2's overlap. It would not catch V2-PRs', whose statements are rewritten.

### Filtered list
`out/swerebench_v2/v2_not_in_benchmarks.txt` lists the **31,731** V2 tasks that no join matched to these benchmarks. It removes only PR-level matches with these benchmarks at the pinned revisions. It is not a general decontamination, and there is no such list for V2-PRs.

### Reproduce
```
uv run swerebench_v2.py
```
The script downloads V2's parquet file (430 MB) and reads only the key columns of V2-PRs (2.7 GB). It streams Multi-SWE-bench's 1.8 GB of JSONL once and caches a slim copy in `~/.cache/agentleak/`.

Pinned sources:
- `nebius/SWE-rebench-V2@475dd5e8`, `nebius/SWE-rebench-V2-PRs@fbf0ecf5`
- `ByteDance-Seed/Multi-SWE-bench@56ff018c` (the `kotlin/` folder is the Kotlin extension; `python/` is a copy of SWE-bench Verified and is left out)
- `ByteDance-Seed/Multi-SWE-RL@97776489`: Multi-SWE-bench's removed PRs
- `AmazonScience/SWE-PolyBench@d56445f9`, `AmazonScience/SWE-PolyBench_Verified@b3fca77b`
- `SWE-bench/SWE-bench_Multilingual@846e647b`
- `SWE-bench/SWE-bench@c6fe717f`, `SWE-bench/SWE-bench_Verified@78f471bf`, `ScaleAI/SWE-bench_Pro@2d52cb3d`: repo names only

Outputs in `out/swerebench_v2/`:
- `overlap_v2.csv`, `overlap_v2_prs.csv`: one row per benchmark/training pair, with the joins that matched, same base commit and same fix
- `v2_not_in_benchmarks.txt`
- `summary.json`: all counts, joins, same-task checks, per-repo overlap, repo presence, the inclusion test with per-repo counts and the PR-range variant, and the text check

## Case 4: the SWE benchmarks themselves
Case 3 matched a training set against three multilingual SWE benchmarks. Here the benchmarks are matched against each other, and against SWE-bench (test split, 2,294 tasks) and SWE-bench Pro (731 public tasks), with case 3's joins.

As in case 2, this compares benchmarks, not training data with a benchmark. Benchmarks sharing tasks is not a defect. It does mean that results on the shared tasks are not independent evidence.

A pair counts when both tasks are the same PR in the same repo, with repo names compared case-insensitively, at any base commit. SWE-bench Pro names its tasks by commit and has no PR numbers, so a pair with it would need the same base commit and an identical fix. Multi-SWE-bench's `python/` folder is a copy of SWE-bench Verified, as Multi-SWE-bench says, and is left out as in case 3.

| Benchmark pair | Same PR | ... at the same base commit | ... at a different base commit | Share of each benchmark |
|---|---|---|---|---|
| Multi-SWE-bench (1,632) × SWE-PolyBench (2,110) | **109** | 109 | 0 | 6.7% / 5.2% |
| Multi-SWE-bench × SWE-bench Multilingual (300) | **19** | 9 | 10 | 1.2% / 6.3% |
| SWE-PolyBench × SWE-bench Multilingual | **4** | 2 | 2 | 0.2% / 1.3% |
| Any of these × SWE-bench, SWE-bench Pro or the Multi-SWE-bench Kotlin extension | 0 | | | |

**In total**, these tasks are the same PR as a task in at least one other of these benchmarks:
- 128 of Multi-SWE-bench's 1,632 (7.8%);
- 113 of SWE-PolyBench's 2,110 (5.4%);
- 23 of SWE-bench Multilingual's 300 (7.7%).

No task is in all three. SWE-bench and SWE-bench Pro share no repo with the other benchmarks, so their zero is structural.

**Same task?** Every one of the 132 pairs has the same fix.
- **Multi-SWE-bench × Multilingual:** all 19 pairs have identical git blobs on every file both patches touch.
- **Pairs with SWE-PolyBench:** blobs cannot be compared, because 1,561 of PolyBench's 2,110 patches have no `index` lines. For its 113 pairs we compare the changed lines in each shared file instead, and all are identical.
- **Different base commits:** 10 Multi-SWE-bench/Multilingual pairs and 2 PolyBench/Multilingual pairs use a different base commit for the same PR. All 12 have the same fix (10 by blobs, 2 by changed lines): same PR and same fix, at a different snapshot.
- **Not counted:** 12 Multi-SWE-bench/PolyBench pairs and 3 Multi-SWE-bench/Multilingual pairs share a base commit but are different PRs. None of them has the same fix.

**Where the overlap is.** It is concentrated in a few repos:
- **Multi-SWE-bench/PolyBench:** 107 of the 109 are `mui/material-ui`, where Multi-SWE-bench has 174 tasks and PolyBench 488. The other 2 are `apache/dubbo` and `google/gson`. The two benchmarks also share `sveltejs/svelte`, with 272 and 496 tasks, but no PR in it.
- **Multi-SWE-bench/Multilingual:** fmt 8, jq 4, ripgrep 2, and gson, axios, nushell, bat and vue 1 each.
- **PolyBench/Multilingual:** all 4 are `google/gson`.
- **SWE-PolyBench Verified:** holds 13 of the 109 and 3 of the 4.

**Names.** An exact repo-name join finds 130 of the 132 pairs. The 2 it misses are `BurntSushi/ripgrep` PRs, which Multilingual stores in lowercase.

**Would an n-gram text filter have caught it?** Mostly yes. Both benchmarks keep the original issue text, so 130 of the 132 pairs share a 13-gram:
- Multi-SWE-bench/PolyBench: median longest shared run 211 words.
- Multi-SWE-bench/Multilingual: median 112.
- PolyBench/Multilingual: runs of 24, 173, 175 and 219 words.

In the other 2 pairs (axios #5085 and nushell #12901), the two benchmarks attached different issues to the same PR. Their texts share at most 3 and 4 words in a row.

### What this does and does not show
- **Does:**
  - 132 task pairs across three multilingual SWE benchmarks are the same PR with the same fix: identical git blobs for the 19 Multi-SWE-bench/Multilingual pairs, and identical changed lines in every shared file for the 113 pairs with SWE-PolyBench.
  - Results on these tasks are not independent across the benchmarks. For example, a model's Multi-SWE-bench and SWE-PolyBench scores share 109 tasks, and an average over the two counts them twice.
- **Does not:**
  - Show how any of these benchmarks chose its tasks, or that one took tasks from another. There is no common pool of PRs to draw a chance baseline from, so we do not test whether the overlap is more than expected for benchmarks built from the same repos.
  - Say anything about any model's scores.
  - Cover every overlap. The same issue fixed in a different PR is not counted. SWE-bench Pro is matched only by base commit and fix.

### Reproduce
```
uv run swe_benchmarks_overlap.py
```
It uses case 3's loaders and pinned revisions, and adds `SWE-bench/SWE-bench@c6fe717f` (test split, full rows) and `ScaleAI/SWE-bench_Pro@2d52cb3d` (default, hard and v1 configs, deduplicated by instance ID). Multi-SWE-bench is read from case 3's slim cache in `~/.cache/agentleak/`, which is built on the first run of either script.

Outputs in `out/swe_benchmarks/`:
- `overlap_pairs.csv`: one row per matched pair, with the joins that matched, the kind of match, same base commit, same fix (by blobs and by changed lines), the longest shared text run, and Verified-subset membership
- `summary.json`: per benchmark pair, the counts, shares, fix and text checks and per-repo detail; also shared repos, tasks in any other benchmark, and patches without `index` lines

## Controls: datasets that excluded a benchmark
The cases above found overlap between sets that do not say they excluded each other. As a control, we checked four open datasets that say they kept a benchmark out, using the same joins.

| Dataset | Says it excluded | Overlap with that benchmark | Overlap with benchmarks it did not exclude |
|---|---|---|---|
| `jm-rt/arvo-cybergym-2000`: 2,000 ARVO tasks in CyberGym's format | CyberGym. Its card says the second half was "built outside the original CyberGym set". | **0** of CyberGym's 1,507 tasks, by plain and by translated ID | **35** of SEC-bench's 100 OSS-Fuzz instances, all found only after ID translation |
| SWE-Gym: 2,438 tasks, 11 repos | SWE-bench's repos ([paper](https://arxiv.org/abs/2412.21139)) | **0** shared repos, 0 shared PRs | none with Multi-SWE-bench, SWE-PolyBench, SWE-bench Multilingual or SWE-bench Pro |
| R2E-Gym Subset: 4,578 tasks, 10 repos | SWE-bench's test repos ([paper](https://arxiv.org/abs/2504.07164)) | **0** shared repo names | none |
| SWE-smith: 59,136 synthetic tasks, 222 repos | all 12 SWE-bench test repos ([paper](https://arxiv.org/abs/2504.21798)) | **0** shared repos | shared repos, not tasks (below) |

**SWE-smith's shared repos.** SWE-smith shares `google/gson` with Multi-SWE-bench, SWE-PolyBench and SWE-bench Multilingual, and `caddyserver/caddy` and `gin-gonic/gin` with Multilingual. Its tasks in these three repos (656 in all) are synthetic bugs, LM-written or procedural edits. None is one of SWE-smith's 2,481 PR-mirror tasks, which revert real upstream PRs, so here a shared repo is not a shared task. None of the PR-mirror tasks is in any repo shared with these benchmarks.

**Are the 35 jm-rt/SEC-bench matches the same bug?** By ARVO's ID mapping, they are the same OSS-Fuzz issue.
- **Fix:** jm-rt's `patch.diff` diffs the whole vulnerable and fixed build trees, including build outputs and other checked-out repos. So it usually spans much more than the fix commit.
  - Case 2's strict test (same git blobs before and after) confirms the same fix for 10 of the 35.
  - A looser test asks whether every line that SEC-bench's patch removes or adds also appears, for the same file, in jm-rt's diff. It passes for 28 and fails for 7.
  - Because jm-rt's diffs are large, the looser test is weaker evidence than the blob test.
- **Crash:** the crash type and top project frame match for 22 of the 35. As a control, the same comparison matches 15 of 304 (4.9%) same-project pairs of different matched bugs; these pairs are clustered, with 210 of them in libxml2. All 7 pairs where the crash type differs compare a jm-rt MemorySanitizer or UndefinedBehaviorSanitizer build with SEC-bench's AddressSanitizer report.

### What this does and does not show
- **Does:**
  - Where a dataset says it excluded a benchmark, the exclusion holds at the source level. None of the four shares an OSS-Fuzz issue (after ID translation) or a repository with the benchmark it excluded.
  - A targeted exclusion covers only its target. `jm-rt/arvo-cybergym-2000`, whose card says its second half was built outside CyberGym, holds 35 of SEC-bench's 100 OSS-Fuzz bugs by ARVO's ID mapping. A plain ID join finds none of them, because the matched jm-rt tasks use ARVO's old IDs and SEC-bench uses the new ones (the mismatch described in case 2).
- **Does not:**
  - Show that these datasets are free of other overlap or leakage. Only the benchmarks named here were checked.
    - R2E-Gym has no PR numbers and lists no owners, so it was matched by repository name alone.
    - SWE-smith was compared by repository. Its PR-mirror tasks carry PR numbers, but none is in a repo it shares with a benchmark.
  - Say how `jm-rt/arvo-cybergym-2000` is meant to be used, or that its builders missed anything they set out to do. Its card describes it only as CyberGym-format tasks for Harbor's CyberGym adapter, and does not mention SEC-bench.

### Reproduce
```
uv run controls.py
```
Pinned sources:
- `jm-rt/arvo-cybergym-2000@75a80a9f`
- `SWE-Gym/SWE-Gym@bb94ed9e`
- `R2E-Gym/R2E-Gym-Subset@2e8108ff`
- `SWE-bench/SWE-smith@ea6d7173`, the combined dataset; its card now recommends the per-language `SWE-smith-[lang]` datasets

The benchmarks are read at the revisions of cases 1–4.

Outputs in `out/controls/`:
- `summary.json`: stated exclusions, the jm-rt joins with the fix and crash checks, repo presence for every control and benchmark, and SWE-Gym's PR joins
- `jm_rt_secbench_matches.csv`: the 35 jm-rt/SEC-bench matches, with the strict blob test, fix-line containment, crash check and each side's sanitizer
- `swe_gym_pr_matches.csv`: SWE-Gym/benchmark PR matches (empty)

## Data and licenses
**This repo.** The code is MIT-licensed (`LICENSE`). From the datasets it publishes only identifiers: task, instance, OSS-Fuzz and PR IDs, repository names and PR numbers. It also publishes counts, flags and ID lists derived from them.
- It does not redistribute task text, patches, Docker images or project code.
- There are two exceptions, both MiMo-V2.6-RL-oss text (Apache-2.0):
  - `out/mimo_suspect_specs.csv` quotes the one-line crash spec of 26 MiMo cyber tasks.
  - The signature check in `out/summary.json` quotes the same kind of spec for 8 matched bugs.

**Sources.** Each dataset's license as it states it at the revision we read:

| Dataset | Revision | License as stated |
|---|---|---|
| XiaomiMiMo/MiMo-V2.6-RL-oss | `639865fd` | Apache-2.0 (dataset card) |
| sunblaze-ucb/cybergym | `bde190de` | none on the dataset card; the GitHub code repo is Apache-2.0 |
| n132/ARVO (mapping and tracker metadata) | `bc2a373c` | BSD-2-Clause (repo) |
| n132/ARVO-Meta | `7e1a64f5` | none stated |
| SEC-bench/SEC-bench | `11422e77` | MIT (dataset card) |
| nebius/SWE-rebench-V2, SWE-rebench-V2-PRs | `475dd5e8`, `fbf0ecf5` | CC-BY-4.0 (dataset cards) |
| ByteDance-Seed/Multi-SWE-bench, Multi-SWE-RL | `56ff018c`, `97776489` | "other"; the card says CC0, subject to ByteDance's IP rights, with the adapted project data under those projects' licenses |
| AmazonScience/SWE-PolyBench, SWE-PolyBench_Verified | `d56445f9`, `b3fca77b` | MIT (dataset cards) |
| SWE-bench/SWE-bench_Multilingual | `846e647b` | MIT (dataset card) |
| SWE-bench/SWE-bench, SWE-bench_Verified | `c6fe717f`, `78f471bf` | none on the dataset cards; the GitHub harness is MIT |
| ScaleAI/SWE-bench_Pro | `2d52cb3d` | per its card, the harness is MIT and task content is under the source repos' licenses |
| jm-rt/arvo-cybergym-2000 | `75a80a9f` | none stated |
| SWE-Gym/SWE-Gym | `bb94ed9e` | MIT (dataset card) |
| R2E-Gym/R2E-Gym-Subset | `2e8108ff` | Apache-2.0 (dataset card) |
| SWE-bench/SWE-smith | `ea6d7173` | MIT (dataset card) |

The tasks in all of these come from open-source projects under their own licenses; this repo refers to them only by ID.

**Intended use.** The lists are for removing overlapping items from training data and for reading benchmark results correctly. They contain no exploits, PoCs or task solutions. The same lists could in principle be used to pick overlapping items on purpose. The overlaps are already derivable from the public datasets, though; we publish them so they can be filtered out.
