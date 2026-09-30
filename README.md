# agentleak

Source-level overlap audits between open agentic training data and agentic benchmarks.

## Case 1: MiMo-V2.6-RL-oss (cyber) vs CyberGym

[MiMo-V2.6-RL-oss](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss) is an open set of RL environments. Its `cyber` config has 1,000 vulnerability-reproduction tasks. [CyberGym](https://huggingface.co/datasets/sunblaze-ucb/cybergym) is a benchmark for the same skill, with 1,507 tasks. Both are built from [ARVO](https://github.com/n132/ARVO), a public set of reproducible OSS-Fuzz bugs, so some bugs appear in both.

| | Count |
|---|---|
| Exact ID matches (`arvo_N` = `arvo:N`) | 135 |
| … counting 4 new-tracker IDs that CyberGym labels `oss-fuzz:N` | 139 |
| **CyberGym tasks whose bug is in the MiMo cyber set, after ID translation** | **223 of 1,507 (14.8%)** |
| MiMo cyber tasks whose bug is in CyberGym | 278 of 1,000 |
| Distinct bugs among the 1,000 MiMo cyber tasks | 836 (164 bugs appear twice) |
| Overlapping pairs where MiMo's crash site is in CyberGym's ground-truth stack trace | 223 of 223 (top project frame matches for 214) |

**Why the ID translation matters.** OSS-Fuzz renumbered its bugs when it moved from the Monorail tracker to issues.oss-fuzz.com, so the same bug can carry an old and a new ID. MiMo uses both schemes, while CyberGym's ARVO tasks use old IDs. Matching raw IDs finds 139 of the 223 overlaps. We translate IDs with ARVO's own mapping (`arvo/oss_fuzz_mappings.csv`). The same translation reveals the 164 duplicated bugs inside MiMo's cyber set.

**How this compares with chance.** CyberGym's 1,368 ARVO tasks all come from the ARVO v1 pool of 4,993 bugs. If MiMo's cyber tasks had been drawn from that pool at random, we would expect about 195 shared bugs (SD 11). We observe 219, plus 4 in CyberGym's newer OSS-Fuzz slice. On exact old-scheme IDs, about 122 are expected and 135 observed. The overlap is therefore about what shared sourcing produces without decontamination. There is no sign of deliberate inclusion.

### What this does and does not show
- **Does:** a model RL-trained on the MiMo `cyber` config has practised about 15% of CyberGym's bugs, on the same project code, with a grader that rewards triggering the same crash. CyberGym results for such a model are partly in-distribution in the strictest sense.
- **Does not:** show that any published score is inflated. The MiMo rows contain no reference PoCs, and the released set is described as a reproduction subset. It is not known which bugs were used for the MiMo-V2.6 models.
- **Does not:** show intent. The overlap is close to chance for two samples of the same public pool.

### Clean split
`out/mimo_cyber_clean_ids.txt` lists **613** MiMo cyber tasks. We removed the 278 tasks whose bug is in CyberGym, and kept one task per remaining duplicated bug (109 removed). Note that this only removes CyberGym bugs; other cyber benchmarks built on ARVO/OSS-Fuzz are not yet checked.

### Reproduce
```
uv run mimo_cybergym.py --signatures
```
Pinned sources:
- `XiaomiMiMo/MiMo-V2.6-RL-oss@639865fd` `cyber.parquet`
- `sunblaze-ucb/cybergym@bde190de`, `tasks` split, plus `data/*/*/error.txt` for the crash-site check
- ARVO mapping @ `bc2a373c`
- ARVO-Meta v1 metadata tree @ `7e1a64f5`

Outputs in `out/`:
- `overlap.csv`: canonical bug ID, CyberGym task IDs, project, MiMo instance IDs, and match type (exact or translated)
- `mimo_duplicates.csv`
- `mimo_cyber_clean_ids.txt`
- `summary.json`: all counts, chance baselines and the crash-site check
