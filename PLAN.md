# agentleak — plan

**Status (2026-10-08):**
- Case 1 (MiMo-V2.6-RL-oss cyber vs CyberGym) is done and published in this repo.
- The HF note was posted on 2026-09-30 as [discussion #6](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss/discussions/6). A follow-up was posted on 2026-10-01 with the text-check result and a question about how some images were built. Neither had a reply by 2026-10-07. A third comment on 2026-10-07 [pointed to the image results](https://huggingface.co/datasets/XiaomiMiMo/MiMo-V2.6-RL-oss/discussions/6#6ac676e5af611a7eb83675f6) and asked how the 135 images were built and which user the harness runs the agent as; no reply as of 2026-10-08.
- Published 2026-10-08 (case 1 leading, short sections on cases 2 and 3): [dev.to write-up](https://dev.to/raimondasl/same-bug-two-ids-an-open-rl-dataset-shares-15-of-cybergyms-bugs-and-a-plain-id-join-misses-38-2b17), [LinkedIn](https://lnkd.in/p/gHmj74BW), [Bluesky](https://bsky.app/profile/raimondas.bsky.social/post/3mxemurvgvk2u).
- Case 2 (SEC-bench vs CyberGym, benchmark vs benchmark) is done: 33 of SEC-bench's 100 OSS-Fuzz instances are CyberGym bugs, but a plain ID join finds 3. See README.md. A heads-up was posted to the SEC-bench maintainers on 2026-10-01 ([SEC-bench/SEC-bench#4](https://github.com/SEC-bench/SEC-bench/issues/4)).
- Case 3 (SWE-rebench-V2 training set vs Multi-SWE-bench, SWE-PolyBench and SWE-bench Multilingual) is done: 348 V2 tasks are the same PR at the same base commit as a benchmark task: 4–11% of each benchmark, and 13% of the Kotlin set added to Multi-SWE-bench after V2's release. Text filters would catch V2's overlap but not V2-PRs'. See README.md. A heads-up was posted to the V2 maintainers on 2026-10-01 ([nebius/SWE-rebench-V2 discussion #5](https://huggingface.co/datasets/nebius/SWE-rebench-V2/discussions/5)). V2's first author replied the same day (README.md, case 3):
  - they excluded all original SWE-bench repos, by repository;
  - they did not explicitly filter against the other benchmarks;
  - they will update the dataset card with a warning and a link to our lists.
  - Done 2026-10-01 17:53 UTC (revision `10483de0`): the card warns about the overlap and links to README case 3. Only the card changed; the data files are identical to `475dd5e8`. Our reply with the exact file links was posted in #5. If they release a filtered revision, rerun case 3 against it.
- Case 4 (the SWE benchmarks vs each other, benchmark vs benchmark) is done:
  - 132 task pairs are the same PR with the same fix. 109 are Multi-SWE-bench/SWE-PolyBench, 107 of them in `mui/material-ui`; 19 Multi-SWE-bench/Multilingual; 4 PolyBench/Multilingual.
  - Per benchmark: 7.8% of Multi-SWE-bench, 5.4% of SWE-PolyBench and 7.7% of SWE-bench Multilingual are in another of these benchmarks.
  - There is no overlap with SWE-bench or SWE-bench Pro: they share no repos.
  - Both sides keep the issue text, so a 13-gram filter catches 130 of the 132.
  - See README.md. Numbers re-derived independently on 2026-10-01 (all 132 pairs matched row for row).
- Heads-ups to the other four benchmarks were posted on 2026-10-01, after case 4 was merged (#8):
  - CyberGym, cases 1 and 2: [sunblaze-ucb/cybergym#24](https://github.com/sunblaze-ucb/cybergym/issues/24).
  - Multi-SWE-bench, cases 3 and 4: [multi-swe-bench/multi-swe-bench#107](https://github.com/multi-swe-bench/multi-swe-bench/issues/107).
  - SWE-PolyBench, cases 3 and 4: [amazon-science/SWE-PolyBench#43](https://github.com/amazon-science/SWE-PolyBench/issues/43). A contributor acknowledged it on 2026-10-08, noting the overlap is not surprising given the strict task filtering; no change announced.
  - SWE-bench Multilingual, cases 3 and 4, posted on the SWE-bench tracker because Multilingual has none of its own: [SWE-bench/SWE-bench#673](https://github.com/SWE-bench/SWE-bench/issues/673).
  - With these, the maintainers of all seven datasets with overlaps have been told.
- A short note on the MiMo cyber overlap was posted on Prime Intellect's open port of the MiMo tasksets on 2026-10-01 ([PrimeIntellect-ai/prime-envs#843](https://github.com/PrimeIntellect-ai/prime-envs/pull/843#issuecomment-5934239337)). No reply as of 2026-10-07. On 2026-10-06 the port's README switched its data source to a Prime Intellect mirror that, by the README's description, drops 70 tasks a trivial input already solves (930 remain). Whether the 930-task mirror still holds the overlapping tasks was not checked.
- Origin: idea I-20260929-02 in the private `ai-research` scouting repo.
- Phase-2 scouting notes from 2026-09-30 (unverified, with pinned SHAs) are local only in `drafts/scouting_2026-09-30.md`.
- Text check for case 1 is done and in README.md: a 13-gram filter flags 0 of the 278 overlapping MiMo tasks.
- The held case-1 batch went into README.md on 2026-10-07, since #6 had no reply: the image check (26 images listed, plus build steps for all 1,000: 135 images hold a fixed build, exactly the tasks whose ID is a CyberGym `arvo:` ID; the in-image grader never mentions it in the 26 listed images, 5 of them with a fixed build), related bugs (20 CyberGym tasks), MiMo vs SEC-bench (15 shared bugs) and a within-project chance baseline for case 1 (219 vs 199 ± 9, z = 2.2, p = 0.017). The new numbers were re-derived independently on 2026-10-07, and the related-bug and SEC-bench outputs are identical to the versions checked on 2026-10-01. The local branch `hold/image-check-v2` is superseded.

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
3. ~~Wait for a reply, or until about 2026-10-08. Then add the image results to README.md.~~ Done 2026-10-07 (no reply, #13). The #6 update was posted on 2026-10-07 and the write-up and social posts on 2026-10-08 (see Status). Scope (agreed 2026-10-01): one post led by case 1, with a short section on cases 2 and 3, including case 3's result that text filters work when both sides keep the original issue text.
4. Hold `drafts/optional_model_repo_question.md` (Xiaomi's modified CyberGym harness). Post it on the model repo only if the dataset thread goes well.
5. If Xiaomi fixes or annotates the dataset, update README.md and rerun against the new revision.

## Phase 2: audit across releases (weeks 1–3, CPU only, under $50)
Case 1 is the template: one script per case, pinned revisions, outputs in `out/`. With four cases, move them into `cases/<name>/` (see Layout below).

- **Source-ID joins:**
  - Cyber: ~~SEC-bench vs CyberGym~~ done (case 2; also adds a same-fix join on patch blobs and a within-project chance baseline). Other ARVO/OSS-Fuzz-derived training sets vs CyberGym and SEC-bench. Check whether CyberFactory/OpenAegis data is available.
  - ~~Controls: datasets that say they excluded a benchmark~~ done (`controls.py`, README "Controls"):
    - **The exclusions hold.** `jm-rt/arvo-cybergym-2000` has 0 overlap with CyberGym. SWE-Gym, R2E-Gym and SWE-smith have 0 shared repos with SWE-bench test.
    - **A targeted exclusion covers only its target.** jm-rt (whose card says its second half was built outside CyberGym) holds 35 of SEC-bench's 100 OSS-Fuzz bugs, 0 of them found by a plain ID join. Corroboration: crash type and frame match for 22 of 35 (control 4.9%). The strict same-fix test confirms 10; SEC-bench's fix lines are contained in jm-rt's much larger build-tree diff for 28.
    - The README now also has a "Data and licenses" section.
  - SWE, at PR and commit level: ~~SWE-rebench-V2 vs Multi-SWE-bench, SWE-PolyBench, SWE-bench Multilingual~~ done (case 3). ~~The SWE benchmarks vs each other, plus SWE-bench and SWE-bench Pro~~ done (case 4). Remaining candidates (scouted, mostly clean or low value): LegoFlow-SWE vs SWE-bench Pro, Multi-SWE-RL vs Multi-SWE-bench (ktlint), MiMo `code`, UltraData-SFT-Agent, OpenThoughts-Agent.
  - ~~Possible follow-up for case 3: SWE-bench Multilingual PRs looked under-included in V2 outside the 3 repos with capitalized GitHub names, which hinted at a name-based filter that failed on lowercase names.~~ Dropped 2026-10-01: V2's authors say they did not explicitly filter against Multilingual. Any remaining pattern would need another explanation and isn't worth an unpinned check.
- **Text check:** 13-gram overlap on each new pair, to measure what text filters catch vs miss. Done for case 1 (0 of 278 caught), case 2 (0 of 35 against descriptions; 29 of 35 against same-project sanitizer reports, with extra flags), case 3 (347 of 348 caught for V2; 0 of 20 for V2-PRs) and case 4 (130 of 132 benchmark pairs share a 13-gram; in the other 2, the benchmarks attached different issues to the same PR).
- **Open items from the case-1 review:**
  - ~~223 is a lower bound; related bugs under other issue IDs.~~ Done: 20 CyberGym tasks share a fix commit or crash signature with a MiMo bug (listed, not counted).
  - ~~Docker images.~~ Done: 26 listed, build steps for all 1,000.
  - ~~Within-project chance baseline for case 1.~~ Done: the excess remains (z = 2.2, p = 0.017); the exact-ID part is not significantly above chance (z = 0.9, p = 0.19).
- **Layout:** with four cases, move them into `cases/<name>/` and factor the shared helpers out of `mimo_cybergym.py`. Do this after the case-1 batch is merged, to avoid conflicts.
  - Keep the README headings and the `out/` file paths unchanged: SWE-rebench-V2's dataset card and the eight public posts link to them.
  - If paths must move, leave the old ones in place.

## Paper: go (decided 2026-10-01)
The gate was met: case 1 shows a clear text-vs-ID gap (0 of 278 caught by a 13-gram filter), case 2 is a second source-level overlap outside MiMo (between benchmarks), and case 3 adds a training-set case outside MiMo where text filters do work.
- Venue details, the outline, the related-work notes and the draft are local in `drafts/` (gitignored). The review is double-anonymous, so this public file no longer names the venue.
- Done: related-work sweep with every reference checked against its primary source; a draft of all sections (case 1 completed 2026-10-07). Next: an anonymized artifact mirror; an independent check of all numbers and wording before submission.
- The effect experiment stays out. It would run MiMo-Pro via API on overlapping vs matched non-overlapping CyberGym items, with a non-MiMo control. The minimum detectable difference is about 13–15pp, and RL spillover biases the effect toward zero.

## Budget and effort
- Phase 1: about $0 and 3–5 human hours.
- Phase 2: under $50 and 10–15 human hours.
- Paper: 15–20 human hours, plus conference registration and travel if accepted.
- Coding agents write the scripts and joins.

## Kill criteria
- Someone else publishes the MiMo/CyberGym overlap first → post a short confirmation plus the filtered split and stop phase 1.
- Phase 2 finds nothing new, and text filters would have caught MiMo too → stop after the note.
