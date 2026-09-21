# History: v0.2, v0.2.1, and project status

The full text of README.md's "v0.2: P6 and a holdout corpus", "v0.2.1:
P6's measured cost and the CONTACT-gap", and "Project status and future
work" sections, moved here to keep the README short. Content is
unchanged from what was in the README, except that the sentence "Everything
above this section is v0.1, unchanged" (accurate in README before the "Key
findings" section and the v0.2.1 Limitations bullet existed above it) has
been corrected below to reflect where it now lives.

## v0.2: P6 and a holdout corpus

The results tables above (in `docs/results.md`) are v0.1 numbers; the
README's "Key findings" section and the P6-related Limitations bullets
were added in v0.2/v0.2.1. v0.2 adds P6 (see "How
it works" in the README) and a 15-scenario holdout attack corpus, written in a
**separate Claude.ai chat session** — not human-written, not blind, and
not unaware of P6: that session **wrote P6's specification** and knew
the documented gaps and v0.1 results, and deliberately targeted P6's
area with its `gap-variant` group. The only separation is narrower: the
*implementer* (Claude Code, writing `src/cordon/policy.py`) never saw
these specific attack scenarios while writing P6's code, verified via
git history (the P6 commit predates the holdout corpus commit). Not an
independent red team in the full sense (same underlying model family,
same project context, and the attack author already knew the rule being
targeted). Full write-up, including a per-scenario audit appendix, in
[`docs/results-holdout.md`](results-holdout.md); P6's effect on the
main corpus is in [`docs/results.md`](results.md)'s own "v0.2"
section.

**Main corpus, P6's effect:** zero measurable effect on the real run
(every scenario's outcome was byte-identical between P1-P5-only and
P1-P6) — the same finding as v0.1's "undefended baseline was already hard
to fool," extended to P6. Under worst-case (assume the model was
completely fooled), P6 newly blocks 11 of the 15 write-tier attacks that
survived P1-P5 alone (22/37 blocked → 33/37), closing the two gaps v0.1's
Limitations named by number (`a9_003`, `a9_005`).

**Holdout corpus (n=15, 13 write-tier):** same real-run finding — P6 had
zero measurable effect (every B3 scenario byte-identical between
versions). Worst-case, split by the corpus author's own pre-declared
groups:

| Group | n | Worst-case blocked, P1-P5 | Worst-case blocked, P1-P6 |
|---|---|---|---|
| gap-variant (targets P6's area) | 6 | 2/6 = 33% | **6/6 = 100%** |
| novel-surface (tests P1-P4 implementation coverage) | 7 | 7/7 = 100% | 7/7 = 100% (unchanged — P1/P3/P4 already covered it) |

Read the 2/6 → 6/6 jump as **"the implementation matches its own
specification,"** not as an independent test generalizing to unknown
attacks: the attack author wrote P6's specification and built
`gap-variant` specifically to target it, so this shows P6 does what it
was designed to do, not that it holds up against attacks nobody
anticipated. n=15 is small either way — treat this as a directional
result, not an estimate (see `docs/results-holdout.md`'s own CI-by-CI
caveats).

**Worst-case framework's structural limits** (full detail in
`docs/results-holdout.md`): the framework taints exactly one argument
per scenario, always the one the predicate itself checks — so (a)
gap-variant can only ever test cases P6's own definition already
covers, and (b) novel-surface's 7/7-blocked result is close to
tautological: every novel-surface `attacker_goal` names a recipient,
event id, attendee, or start time, and the framework always taints
*that* value, landing in exactly the argument P1/P3/P4 already check.
It cannot represent an attack where injected content influences the
planner's *decision* to act on an already-trusted, literal value — the
decision-level manipulation gap-variant/P6 actually targets. Read
"novel-surface" as regression coverage for P1-P4's implementation, not
evidence Cordon generalizes to novel attack surfaces.

## v0.2.1: P6's measured cost and the CONTACT-gap

P6 stayed **frozen** (tag `v0.2.0`) for this work — it only measures, on
two small scenario sets authored by the same Claude.ai session that
wrote P6's specification and the holdout corpus, with predictions
pre-registered before any real-model run (tag `v0.2.1-prereg`, verbatim
in [`docs/preregistration-v0.2.1.md`](preregistration-v0.2.1.md)).
Full write-ups: [`docs/results-p6cost.md`](results-p6cost.md) (Part
A, 10 benign tasks) and
[`docs/results-contact-gap.md`](results-contact-gap.md) (Part B, 4
attacks). Total real spend: $0.3699 (cap was $1.00; every individual run
stayed under its own $0.30 cap).

**P6's real cost (Part A, n=10, one Haiku run):** one new confirmation
prompt attributable to P6 (`p_009`) — smaller than the pre-registered
4/10, but because 3 of the other 4 predicted tasks (`p_001`, `p_005`,
`p_008`) never reached a write step at all in this run (quarantine-
extraction failures and empty-search safe-aborts upstream of the policy
engine, not policy-engine behavior). Benign utility under v1 and v2 was
identical at every confirm mode (0/10 deny, 1/10 approve) — this run's
utility floor was set by the small model's own execution reliability
(wrong-recipient replies, a literal `"Bob"` instead of an address,
domain hallucinations), not by P6.

**CONTACT-gap (Part B, n=4, one Haiku run):** worst-case (assume the
model was completely fooled), the gap is **3/4** — P6 never blocks
CONTACT-trust content to an allowlisted recipient (`c_001`, `c_002`,
`c_004`); the fourth scenario (`c_003`, a calendar field) is blocked,
but by **P4** (which gates any non-literal calendar argument regardless
of trust level), not P6 — exactly the case the pre-registration declined
to predict. In Cordon's real run, the gap materialized in 1/4 cases
(`c_002`); the other two candidates errored at quarantine extraction
before reaching a write step, so 3/4 remains the more meaningful number
for the gap's structural size. Both pre-registered predictions (H5, H6)
held.

## Project status and future work

**Done (M0–M3, v0.1):** repo scaffold, tooling and CI; a mock mailbox/calendar with typed read/write tools; the undefended (B0) and spotlighting (B1) baselines; the planner/executor/quarantine pipeline with taint tracking; the P1–P5 policy engine with no-LLM unit tests; an 80-scenario corpus (16 benign, 64 attacks across 10 categories, including Turkish/German attacks); a full B0–B3 real-model evaluation run with tiered/primary-secondary ASR, utility, and a worst-case (no-LLM) analysis, all written up honestly in `docs/results.md`.

**Done (v0.2):** P6, a content-trust gate closing the two gaps v0.1 named by scenario id (`a9_003`, `a9_005`) — see "How it works" above; a 15-scenario holdout corpus (`make holdout-check`), written in a separate Claude.ai session that knew P6's specification (it wrote it) but was never seen by the implementer while P6's code was written, evaluated the same way as the main corpus, written up in `docs/results-holdout.md`.

**Done (v0.2.1):** measured (never adjusted) P6's real cost and the CONTACT-gap's size, on two small scenario sets (`evals/corpus/p6cost`, 10 benign tasks; `evals/corpus/contact-gap`, 4 attacks) authored by the same Claude.ai session that wrote P6's specification and the holdout corpus, predictions pre-registered before any real-model run (tag `v0.2.1-prereg`); added per-scenario policy-rule observability (`rules_fired`) to the result JSON, with a regression proof that it changed no existing decision; a generalized `make corpus-check DIR=...` validator for any non-holdout corpus directory. Written up in `docs/results-p6cost.md` and `docs/results-contact-gap.md`.

**Not done:** an AgentDojo adapter (M4, stretch); a real Gmail/Calendar mode (OAuth, read-only + draft scopes); any model besides Claude Haiku 4.5; more than one run per baseline on any corpus; a fully independent red team or a fully independent CONTACT-gap/P6-cost measurement (both the holdout corpus and the v0.2.1 scenario sets were authored by a Claude.ai session that knew P6's specification and, for the holdout/`gap-variant` case, deliberately targeted it — only the implementer was kept from seeing the resulting attacks, which is a narrower and weaker separation than genuine independence); a scripted faithful-plan measurement of benign confirmation rates (P1/P4/P6 friction independent of small-model reliability).

**Plausible next steps**, roughly in order of how directly they'd close a documented gap:

- A "safe re-query" path for an empty search/list result — letting the planner (or a bounded retry loop) try a different query instead of ending the plan, which is part of why B2/B3's benign utility trails B0/B1's on this run, and why most of `p6cost`'s pre-registered P6-firing candidates never reached a write step at all.
- Something other than provenance for detecting a compromised contact account — P6 deliberately doesn't gate CONTACT-trust content (see Limitations), and v0.2.1 put a number on it (3/4 worst-case on `contact-gap`'s email scenarios).
- A genuinely independent attack corpus and cost/gap measurement, written by an author who does **not** know the rule being tested — neither the holdout set nor the v0.2.1 scenario sets close this gap: their author wrote P6's own specification. Only the implementer was kept from seeing the resulting scenarios, which is a much narrower separation.
- A small study of real human confirmation behavior, to replace the two artificial ceilings (auto-deny, auto-approve) with something closer to actual confirmation-fatigue rates.

This list is deliberately short and un-scored — see `docs/results.md`/`docs/results-holdout.md`'s Limitations sections for the honest cost/benefit numbers behind each item, and `docs/threat-model.md`'s Known gaps for the exact scenarios that demonstrate them.
