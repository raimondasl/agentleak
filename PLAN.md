# agentleak — plan

**Status (2026-09-30):**
- Case 1 (MiMo-V2.6-RL-oss cyber vs CyberGym) is done and published in this repo.
- The public note is drafted in `drafts/`, which is local only (gitignored). It is not posted yet.
- Origin: idea I-20260929-02 in the private `ai-research` scouting repo.

## Claim we can support
Open agentic RL/SFT releases can overlap agentic benchmarks at the level of the **source item**: the same vulnerability, the same PR. The text can differ while the item is the same. Text-based decontamination misses this, and naive ID joins miss part of it, because upstream IDs get renumbered.

The case-1 numbers are in README.md:
- 223 of CyberGym's 1,507 tasks are in the MiMo cyber set. A plain join finds only 139.
- The MiMo cyber set has 164 duplicated issues.
- The crash function and type match CyberGym's ground truth for 215 of the 223.
- The overlap is modestly above a uniform draw: 219 vs 195 ± 11.

## Claims we will NOT make
- That anyone trained on a benchmark on purpose.
- That any published score is inflated by the overlap. Within the released data, the overlap bounds MiMo-Pro's inflation at ≤ ~0.6pp. The real training pool is unknown.
- That we are the first to check open agentic training sets for overlap. TMax ([2606.23321](https://arxiv.org/abs/2606.23321)) did a text-level check on terminal and SWE sets.

## Phase 1: public note (now)
1. The user posts `drafts/hf_discussion.md` on the MiMo-V2.6-RL-oss discussions page from their own account.
2. Wait for a reply, or 3–7 days. Then publish `drafts/devto.md` and `drafts/social.md`, updated with any reply.
3. Hold `drafts/optional_model_repo_question.md` (Xiaomi's modified CyberGym harness). Post it on the model repo only if the dataset thread goes well.
4. If Xiaomi fixes or annotates the dataset, update README.md and rerun against the new revision.

## Phase 2: audit across releases (weeks 1–3, CPU only, under $50)
Case 1 is the template: one script per case, pinned revisions, outputs in `out/`. Consider moving it to `cases/mimo_cybergym/` once there is a second case.

- **Source-ID joins:**
  - Cyber: other ARVO/OSS-Fuzz-derived training sets vs CyberGym and SEC-bench. Check whether CyberFactory/OpenAegis data is available.
  - SWE, at PR and commit level: SWE-smith, SWE-Gym, R2E-Gym, SWE-rebench train, MiMo `code`, UltraData-SFT-Agent and OpenThoughts-Agent vs SWE-bench Verified, Pro and Multi-SWE.
- **Text check:** 13-gram overlap on the same pairs, to measure what text filters catch vs miss. This is still unmeasured; the drafts only say "likely".
- **Open items from the case-1 review:**
  - 223 is a lower bound. A reviewer found about 19 more CyberGym tasks sharing an exact ClusterFuzz crash signature with a MiMo bug under a different issue ID. Verify these.
  - The Docker images were not inspected for PoCs.

## Gate around Oct 20 → FORGE 2027 Data & Benchmarking (Nov 15, 4+1 pages)
- **Go** if there is a second real source-level overlap outside MiMo, or a clear text-vs-ID gap.
- **Otherwise stop.** The note plus the tool is the right-sized output.
- The effect experiment is optional and runs only if a cheap pilot shows signal. It would run MiMo-Pro via API on overlapping vs matched non-overlapping CyberGym items, with a non-MiMo control. The minimum detectable difference is about 13–15pp, and RL spillover biases the effect toward zero.

## Budget and effort
- Phase 1: about $0 and 3–5 human hours.
- Phase 2: under $50 and 10–15 human hours.
- FORGE paper: 15–20 human hours.
- Coding agents write the scripts and joins.

## Kill criteria
- Someone else publishes the MiMo/CyberGym overlap first → post a short confirmation plus the filtered split and stop phase 1.
- Phase 2 finds nothing new, and text filters would have caught MiMo too → stop after the note.
