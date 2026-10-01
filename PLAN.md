# agentleak — plan

**Status (2026-09-30):**
- Case 1 (MiMo-V2.6-RL-oss cyber vs CyberGym) is done and published in this repo.
- The HF note was posted on 2026-09-30 as [discussion #6](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss/discussions/6). A follow-up was posted on 2026-10-01 with the text-check result and a question about how some images were built. Neither has a reply yet. The dev.to and social drafts in `drafts/` (local only, gitignored) are not posted yet.
- Case 2 (SEC-bench vs CyberGym, benchmark vs benchmark) is done: 33 of SEC-bench's 100 OSS-Fuzz instances are CyberGym bugs, but a plain ID join finds 3. See README.md.
- Origin: idea I-20260929-02 in the private `ai-research` scouting repo.
- Phase-2 scouting notes from 2026-09-30 (unverified, with pinned SHAs) are local only in `drafts/scouting_2026-09-30.md`.
- Text check for case 1 is done and in README.md: a 13-gram filter flags 0 of the 278 overlapping MiMo tasks.
- Docker image check for case 1 is done on a sample. Its results are held until the dataset authors answer the follow-up question (posted 2026-10-01), or until about 2026-10-08. The code is on the local branch `hold/image-check`, and the notes are local in `drafts/fix_binary_notes.md`.

## Claim we can support
Open agentic RL/SFT releases can overlap agentic benchmarks at the level of the **source item**: the same vulnerability, the same PR. The text can differ while the item is the same.
- A text filter against the benchmark's task description misses this (case 1: 0 of 278; case 2: 0 of 35).
- A filter against richer benchmark files, such as sanitizer reports, can catch much of it when the training item contains the same kind of text (case 2: 29 of 35, with extra flags).
- Naive ID joins miss part of it, because upstream IDs get renumbered.

The case-1 numbers are in README.md:
- 223 of CyberGym's 1,507 tasks are in the MiMo cyber set. A plain join finds only 139.
- The MiMo cyber set has 164 duplicated issues.
- The crash function and type match CyberGym's ground truth for 215 of the 223.
- The overlap is modestly above a uniform draw: 219 vs 195 ± 11.
- A 13-gram text filter flags 0 of the 278 overlapping MiMo tasks; same-bug texts share at most 5 words in a row.

## Claims we will NOT make
- That anyone trained on a benchmark on purpose.
- That any published score is inflated by the overlap. Within the released data, the overlap bounds MiMo-Pro's inflation at ≤ ~0.6pp. The real training pool is unknown.
- That we are the first to check open agentic training sets for overlap. TMax ([2606.23321](https://arxiv.org/abs/2606.23321)) did a text-level check on terminal and SWE sets.

## Phase 1: public note (now)
1. ~~The user posts `drafts/hf_discussion.md` on the MiMo-V2.6-RL-oss discussions page from their own account.~~ Done 2026-09-30 (#6).
2. ~~The user posts the follow-up `drafts/hf_followup.md` in #6 (text-filter result plus a question about the images).~~ Done 2026-10-01.
3. Wait for a reply, or until about 2026-10-08. Then add the image results to README.md (merge `hold/image-check`) and publish `drafts/devto.md` and `drafts/social.md`, updated with any reply.
4. Hold `drafts/optional_model_repo_question.md` (Xiaomi's modified CyberGym harness). Post it on the model repo only if the dataset thread goes well.
5. If Xiaomi fixes or annotates the dataset, update README.md and rerun against the new revision.

## Phase 2: audit across releases (weeks 1–3, CPU only, under $50)
Case 1 is the template: one script per case, pinned revisions, outputs in `out/`. Consider moving it to `cases/mimo_cybergym/` once there is a second case.

- **Source-ID joins:**
  - Cyber: ~~SEC-bench vs CyberGym~~ done (case 2; also adds a same-fix join on patch blobs and a within-project chance baseline). Other ARVO/OSS-Fuzz-derived training sets vs CyberGym and SEC-bench. Check whether CyberFactory/OpenAegis data is available.
  - SWE, at PR and commit level: SWE-smith, SWE-Gym, R2E-Gym, SWE-rebench train, MiMo `code`, UltraData-SFT-Agent and OpenThoughts-Agent vs SWE-bench Verified, Pro and Multi-SWE.
- **Text check:** 13-gram overlap on each new pair, to measure what text filters catch vs miss. Done for case 1 (0 of 278 caught) and case 2 (0 of 35 against descriptions; 29 of 35 against same-project sanitizer reports, with extra flags).
- **Open items from the case-1 review:**
  - 223 is a lower bound. A reviewer found about 19 more CyberGym tasks sharing an exact ClusterFuzz crash signature with a MiMo bug under a different issue ID. Verify these.
  - Docker images: a sample of 25 was checked for PoCs. The results are held (see Phase 1).
  - Add case 2's within-project chance baseline to case 1 too (exploratory run done, needs an independent check).
- **Layout:** with two cases, move them into `cases/<name>/` and factor the shared helpers out of `mimo_cybergym.py`. Do this after `hold/image-check` is merged, to avoid conflicts.

## Gate around Oct 20 → FORGE 2027 Data & Benchmarking (Nov 15, 4+1 pages)
- **Go** if there is a second real source-level overlap outside MiMo, or a clear text-vs-ID gap. Case 1's text check shows a clear gap (0 of 278 caught by a 13-gram filter), and case 2 is a second source-level overlap outside MiMo (between benchmarks). In case 2, a 13-gram filter against CyberGym's descriptions catches 0 of 35, but one against CyberGym's sanitizer reports catches 29 of 35, with false positives. So whether text filtering works depends on which benchmark text it is run against. The gate looks met. A training-set case outside MiMo would still make the paper stronger.
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
