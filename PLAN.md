# agentleak — plan

**Status (2026-10-01):**
- Case 1 (MiMo-V2.6-RL-oss cyber vs CyberGym) is done and published in this repo.
- The HF note was posted on 2026-09-30 as [discussion #6](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss/discussions/6). A follow-up was posted on 2026-10-01 with the text-check result and a question about how some images were built. Neither has a reply yet. The dev.to and social drafts in `drafts/` (local only, gitignored) are not posted yet.
- Case 2 (SEC-bench vs CyberGym, benchmark vs benchmark) is done: 33 of SEC-bench's 100 OSS-Fuzz instances are CyberGym bugs, but a plain ID join finds 3. See README.md. A heads-up was posted to the SEC-bench maintainers on 2026-10-01 ([SEC-bench/SEC-bench#4](https://github.com/SEC-bench/SEC-bench/issues/4)).
- Case 3 (SWE-rebench-V2 training set vs Multi-SWE-bench, SWE-PolyBench and SWE-bench Multilingual) is done: 348 V2 tasks are the same PR at the same base commit as a benchmark task: 4–11% of each benchmark, and 13% of the Kotlin set added to Multi-SWE-bench after V2's release. Text filters would catch V2's overlap but not V2-PRs'. See README.md. A heads-up to the V2 maintainers is drafted (`drafts/swerebench_v2_discussion.md`), not posted yet.
- Origin: idea I-20260929-02 in the private `ai-research` scouting repo.
- Phase-2 scouting notes from 2026-09-30 (unverified, with pinned SHAs) are local only in `drafts/scouting_2026-09-30.md`.
- Text check for case 1 is done and in README.md: a 13-gram filter flags 0 of the 278 overlapping MiMo tasks.
- Docker image check for case 1 is done on a sample. Its results are held until the dataset authors answer the follow-up question (posted 2026-10-01), or until about 2026-10-08. The code is on the local branch `hold/image-check-v2`, and the notes are local in `drafts/fix_binary_notes.md`.

## Claim we can support
Open agentic RL/SFT releases can overlap agentic benchmarks at the level of the **source item**: the same vulnerability, the same PR. The text can differ while the item is the same.
- A text filter against the benchmark's task description misses this when the two sides don't carry the same original text (case 1: 0 of 278; case 2: 0 of 35; case 3's V2-PRs, LLM-written: none of 20 pairs).
- It catches it when both sides keep the original issue text (case 3: 347 of 348, plus 1,249 other V2 tasks flagged, unclassified).
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
3. Wait for a reply, or until about 2026-10-08. Then add the image results to README.md (merge `hold/image-check-v2`) and publish `drafts/devto.md` and `drafts/social.md`, updated with any reply.
4. Hold `drafts/optional_model_repo_question.md` (Xiaomi's modified CyberGym harness). Post it on the model repo only if the dataset thread goes well.
5. If Xiaomi fixes or annotates the dataset, update README.md and rerun against the new revision.

## Phase 2: audit across releases (weeks 1–3, CPU only, under $50)
Case 1 is the template: one script per case, pinned revisions, outputs in `out/`. With three cases, move them into `cases/<name>/` (see Layout below).

- **Source-ID joins:**
  - Cyber: ~~SEC-bench vs CyberGym~~ done (case 2; also adds a same-fix join on patch blobs and a within-project chance baseline). Other ARVO/OSS-Fuzz-derived training sets vs CyberGym and SEC-bench. Check whether CyberFactory/OpenAegis data is available.
  - SWE, at PR and commit level: ~~SWE-rebench-V2 vs Multi-SWE-bench, SWE-PolyBench, SWE-bench Multilingual~~ done (case 3). Remaining candidates (scouted, mostly clean or low value): LegoFlow-SWE vs SWE-bench Pro, Multi-SWE-RL vs Multi-SWE-bench (ktlint), MiMo `code`, UltraData-SFT-Agent, OpenThoughts-Agent.
  - Possible follow-up for case 3, held: SWE-bench Multilingual PRs look under-included in V2 outside the 3 repos that hold all 12 V2 overlaps. Multilingual stores every repo name in lowercase; these 3 are among the 4 Multilingual repos in V2 whose GitHub names have capitals (the 4th, BurntSushi/ripgrep, has no overlap). This needs an unpinned GitHub candidate pool and was found post hoc, so it needs an independent check and preferably a question to the V2 authors first.
- **Text check:** 13-gram overlap on each new pair, to measure what text filters catch vs miss. Done for case 1 (0 of 278 caught), case 2 (0 of 35 against descriptions; 29 of 35 against same-project sanitizer reports, with extra flags) and case 3 (347 of 348 caught for V2; 0 of 20 for V2-PRs).
- **Open items from the case-1 review:**
  - 223 is a lower bound. A reviewer found about 19 more CyberGym tasks sharing an exact ClusterFuzz crash signature with a MiMo bug under a different issue ID. Verify these.
  - Docker images: a sample of 25 was checked for PoCs. The results are held (see Phase 1).
  - Add case 2's within-project chance baseline to case 1 too (exploratory run done, needs an independent check).
- **Layout:** with three cases, move them into `cases/<name>/` and factor the shared helpers out of `mimo_cybergym.py`. Do this after `hold/image-check-v2` is merged, to avoid conflicts.

## Gate around Oct 20 → FORGE 2027 Data and Benchmarking Track (Nov 15 AoE, 4+1 pages)
Call for papers checked 2026-10-01:
- IEEE template (IEEEtran, 10pt conference), and appendices count toward the 4 pages.
- Double-anonymous review: reviewers need an anonymized artifact, because this repo identifies the author.
- Submission site: forge2027-benchmarking.hotcrp.com.
- Per the ICSE 2027 rules that FORGE follows, one author registers and presents (Dublin, 26–27 Apr 2027).
- Notification is 2027-01-04.
- **Go** if there is a second real source-level overlap outside MiMo, or a clear text-vs-ID gap. Case 1's text check shows a clear gap (0 of 278 caught by a 13-gram filter), and case 2 is a second source-level overlap outside MiMo (between benchmarks). In case 2, a 13-gram filter against CyberGym's descriptions catches 0 of 35, but one against CyberGym's sanitizer reports catches 29 of 35, with false positives. Case 3 adds a training-set case outside MiMo, and shows where text filters do work. So whether text filtering works depends on whether both sides keep the same original text, and on which benchmark text it is run against. The gate looks met.
- **Otherwise stop.** The note plus the tool is the right-sized output.
- The effect experiment is optional and runs only if a cheap pilot shows signal. It would run MiMo-Pro via API on overlapping vs matched non-overlapping CyberGym items, with a non-MiMo control. The minimum detectable difference is about 13–15pp, and RL spillover biases the effect toward zero.

## Budget and effort
- Phase 1: about $0 and 3–5 human hours.
- Phase 2: under $50 and 10–15 human hours.
- FORGE paper: 15–20 human hours, plus ICSE 2027 registration and travel if accepted.
- Coding agents write the scripts and joins.

## Kill criteria
- Someone else publishes the MiMo/CyberGym overlap first → post a short confirmation plus the filtered split and stop phase 1.
- Phase 2 finds nothing new, and text filters would have caught MiMo too → stop after the note.
