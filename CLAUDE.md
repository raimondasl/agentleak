# agentleak — instructions for Claude

**Goal:** measure source-level overlap between open agentic training data and agentic benchmarks. Publish reproducible ID lists, filtered splits and neutral write-ups. Current status and next steps are in `PLAN.md`.

## Conventions
- **Python:** use `uv` only (`uv run`, `uv add`); never bare `pip` or `python`.
- **Reproducibility:** every dataset is read at a **pinned revision** (HF commit SHA or git commit). Record the revisions in the script and in `out/summary.json`.
- **One script per audit case.** It writes all outputs (CSV/JSON/TXT) to its output folder. `README.md` reports only numbers that the script produces.
- **Independent check before publishing:** before any number goes into README.md or a post, re-derive it independently, e.g. with a separate agent and its own code, and check the wording for overclaims. Case 1 needed two rounds of this.
- **Wording:**
  - Neutral: the finding is a risk for people who train on the data, not an accusation.
  - Always state what the finding does *not* show.
  - Report chance baselines with z and p; don't call something "close to chance" when it isn't.
- **Posting:** nothing is posted publicly without the user reviewing the exact text. The user posts from their own accounts. Drafts live in `drafts/`, which is gitignored and never committed.
- **Employer sensitivity:** one-off research and posts are fine. Don't turn this into an ongoing public scorecard of frontier model providers.
- Commit after each meaningful step. End commit messages with the Co-Authored-By line from the session's attribution instructions.
