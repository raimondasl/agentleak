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
- **Distinct bugs:** 710 of MiMo's distinct bugs fall in that pool. A uniform random draw of 710 would share about **195 ± 11** bugs with CyberGym. We observe **219**: z = 2.2, one-sided p = 0.015, about 12% above a uniform draw. 4 more overlaps are in CyberGym's newer OSS-Fuzz slice.
- **Exact old-scheme IDs:** 122 ± 9 expected, 135 observed (p = 0.08).
- **What it means:** the overlap is what you get when neither set is filtered against the other. The modest excess could come from both sets preferring similar bugs; we don't know. This is no evidence of targeting.

### What this does and does not show
- **Does:** about one in seven CyberGym tasks is a bug in this released training set, with the same project code and a grader that rewards triggering that crash. A model RL-trained on the `cyber` config and then evaluated on CyberGym is partly tested on bugs it practised on.
- **Does not:** show that any published score is inflated.
  - The task rows contain no reference PoCs. The Docker images were not inspected.
  - It is not stated whether these 1,000 tasks were used to train the MiMo-V2.6 models.
  - The tech report's own RL runs on the released environments (§7.2, Table 6) evaluate cyber only on the in-house MiMo Cyber Bench (mini), not on CyberGym.
- **Does not:** cover other overlaps.
  - 223 counts identical OSS-Fuzz issues, so it is a lower bound. Re-reports of the same crash under a different issue ID are not checked.
  - Other ARVO/OSS-Fuzz-based benchmarks are not checked yet.

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
- `summary.json`: all counts, chance baselines, the crash check and its control
