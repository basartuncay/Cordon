# Cordon

[![CI](https://github.com/basartuncay/Cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/basartuncay/Cordon/actions/workflows/ci.yml)

A CaMeL-inspired mail & calendar agent prototype in which untrusted email content cannot decide what the agent does. Provenance tracking plus a deterministic policy engine, evaluated against undefended baselines on a small attack corpus (English, Turkish, German).

> **Status: research prototype.** Runs against an in-memory mock mailbox and calendar only (`*.example` domains). Real Gmail/Calendar access is **not implemented**. This is not production security software and it does not "solve" prompt injection.

## Key findings (v0.1 to v0.2.1, Claude Haiku 4.5, mock environment)

1. **Real model runs did not show a before/after improvement.** The undefended baseline (B0) was fooled by 2 of 64 attacks on the main corpus and 0 of 15 on the holdout corpus. Most of the measured protection comes from planner isolation, not from the policy engine.
2. **The policy engine's evidence is the worst-case analysis** (assume the model was completely fooled): P1-P5 block 22/37 write-tier attacks on the main corpus and P1-P6 block 33/37. This shows the mechanism works for the cases it was written for. It is not a measurement against an adaptive attacker (see the worst-case limits section).
3. **There is a utility cost.** Benign task success dropped from 14/16 (B0, B1) to 9/16 (B2, B3), mainly because a fixed one-shot plan cannot retry or ask for clarification. The cost of P6 specifically is **not** established: in a 10-task follow-up only 1 new confirmation prompt appeared, but 5 of the 10 tasks never reached a write step because of small-model failures.
4. **Known open gap:** content planted by a compromised *contact* account and relayed to an allowlisted recipient is not gated by any rule (3/4 scenarios unblocked in worst-case, 1/4 in the real pipeline).
5. **Everything is small and self-authored:** 80 + 15 + 14 scenarios, one run each, one model family, scenarios written by the same model family as the policy. Results quantify specific mechanisms, not general rates.

## What this is, and what it isn't

This is **not novel research**. Prior art includes [AgentDojo](https://arxiv.org/abs/2406.13352) (a benchmark with an email/calendar suite), [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind's privileged/quarantined design with capabilities) and Simon Willison's [Dual LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/).

Cordon is a small, readable implementation of the same family of ideas, with:

- a typed plan DSL, taint tracking and a policy engine (P1-P6 as of v0.2) whose unit tests run with no LLM calls,
- an 80-scenario main corpus plus a 15-scenario holdout corpus written in a separate session, both with deterministic success predicates (no LLM judge),
- an evaluation write-up that reports negative and inconvenient findings as well as positive ones.

## How it works

```mermaid
flowchart LR
  U["User request"] --> P["Privileged planner LLM<br/>(never sees tool output)"]
  P -->|"typed plan"| E["Executor"]
  E -->|"read tools"| M[("Mailbox / Calendar")]
  M -->|"Tainted values"| E
  E -->|"untrusted text"| Q["Quarantined LLM<br/>(no tools, schema-constrained)"]
  Q -->|"Tainted values"| E
  E -->|"side-effecting call + provenance"| PE{"Policy engine<br/>P1-P6"}
  PE -->|allow| M
  PE -->|confirm| H["Human confirmation"]
  PE -->|deny| X["Blocked"]
```

1. The **planner** sees only the user's request and the tool schemas, and emits a typed plan. Control flow is fixed before any untrusted data is read.
2. The **executor** runs the plan. Every value returned by a read tool is wrapped as `Tainted[T]` with provenance (source, trust level, sensitivity).
3. The **quarantined LLM** has no tools. It turns untrusted text into schema-constrained values, and those values stay tainted.
4. The **policy engine** (plain Python, no LLM) checks every side-effecting call using argument provenance:
   - **P1** email recipients must come from the user's request or the contacts allowlist, otherwise confirm
   - **P2** private content must not flow to non-allowlisted recipients (email or calendar attendees), across all text fields
   - **P3** destructive actions (event deletion) always need confirmation
   - **P4** calendar attendees, locations, links, and start/end times derived from untrusted data need confirmation (no allowlist exemption)
   - **P5** per-class and global side-effect budgets (hard deny)
   - **P6** (v0.2, `CORDON_POLICY_VERSION=v2`, the default) — email subject/body/note or calendar title/description/location need confirmation if any of it comes from a source trusted below CONTACT, even to an already-allowlisted recipient. Content from a CONTACT-trust source never triggers it — a compromised contact account is a known, accepted gap, see `docs/threat-model.md`. `CORDON_POLICY_VERSION=v1` runs P1-P5 only, byte-identical to v0.1.

## Results

Setup: 80 scenarios, one real run per system, Claude Haiku 4.5 for every role, Wilson 95% intervals in [`docs/results.md`](docs/results.md). Errored and safe-aborted scenarios count as failures in utility and in the primary ASR.

**Real model runs**

| System | Benign utility (n=16) | Attack success, read-only (n=27) | Attack success, write (n=37) | Errored / safe-abort (of 80) |
|---|---|---|---|---|
| B0 undefended tool loop | 14/16 (87.5%) | 1/27 | 1/37 | 0 / 0 |
| B1 + spotlighting prompt | 14/16 (87.5%) | 0/27 | 0/37 | 0 / 0 |
| B2 Cordon, policy engine off | 9/16 (56.2%) | 0/27 | 0/37 | 5 / 4 |
| B3 Cordon, full | 9/16 (56.2%) | 0/27 | 0/37 | 5 / 4 |

B3 replays B2's cached planner and quarantine calls (the policy engine only changes what the executor does with them), so B2 and B3 are not independent samples.

**Worst case: assume the planner and quarantine were completely fooled** (37 write-tier attacks, scripted, no LLM calls)

| Condition | Attacks that still succeed |
|---|---|
| B2, policy engine off | 37/37 |
| B3, confirmations auto-denied | 15/37 (22/37 blocked) |
| B3, confirmations auto-approved | 37/37 |

## Reading the results honestly

- **In real runs, the undefended baseline was already hard to fool.** Only 2 of 64 attacks succeeded against B0 with Haiku 4.5 on this corpus. The real-run numbers therefore cannot show a before/after improvement, and the policy engine was never given a live chance to matter. Most of the measured protection comes from planner isolation: a plan made from the user's request alone rarely contains the attacker's goal.
- **The worst-case table is the policy engine's evidence.** If the model is fully fooled, the policy engine blocks 22 of 37 write attacks under auto-deny. This shows the mechanism works, not that it beats a real adversary: the attack scripts were written by the same model that wrote the policy.
- **The remaining 15 are known gaps:** actions to an allowlisted recipient with attacker-influenced content, provenance-only checks that never look at content, and attacks with no tool call for a policy to gate (see [`docs/threat-model.md`](docs/threat-model.md)).
- **Auto-approve equals no policy at all.** The engine only helps if a human actually reads the confirmation.
- **There is a utility cost.** Benign utility dropped from 87.5% to 56.2% (14/16 vs 9/16). The intervals overlap, so treat it as suggestive, but the likely cause is structural: a fixed one-shot plan cannot retry a query or ask for clarification when a tool result is not what it assumed, while B0 and B1 can.

## v0.2: P6 and a holdout corpus

Everything above this section is v0.1, unchanged. v0.2 adds P6 (see "How
it works" above) and a 15-scenario holdout attack corpus, written in a
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
[`docs/results-holdout.md`](docs/results-holdout.md); P6's effect on the
main corpus is in [`docs/results.md`](docs/results.md)'s own "v0.2"
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
in [`docs/preregistration-v0.2.1.md`](docs/preregistration-v0.2.1.md)).
Full write-ups: [`docs/results-p6cost.md`](docs/results-p6cost.md) (Part
A, 10 benign tasks) and
[`docs/results-contact-gap.md`](docs/results-contact-gap.md) (Part B, 4
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

## Limitations

- Small corpus and a single run per system; confidence intervals are wide.
- One model family (Claude Haiku 4.5), mock environment only.
- The attack corpus, including the adaptive attacks aimed at the policy engine, was written by the same model that wrote the policy. An independent red team would find more.
- Auto-deny is safer than a real user would be; auto-approve is the opposite extreme. Neither models confirmation fatigue.
- No real Gmail/Calendar mode, no AgentDojo adapter.
- **(v0.2)** The holdout corpus is n=15, one run, and its author knew P6's specification (wrote it) and the documented gaps — smaller and considerably less independent than an ideal red team; only the implementer was kept from seeing the resulting attacks while writing P6's code (see above).
- **(v0.2.1)** P6 deliberately does not gate CONTACT-trust content — a compromised contact account is a known, accepted gap (`docs/threat-model.md`), not something P6 tries to close. Widening it to CONTACT would gate most ordinary replies to real contacts. **Measured** (v0.2.1, n=4, one Haiku run): worst-case gap is 3/4 for email content to an allowlisted recipient; a calendar-field variant (`c_003`) is blocked by P4 instead, not by P6 — see `docs/results-contact-gap.md`. Still only one small run, one model, one author who knew what P6 does and doesn't cover.
- **(v0.2.1)** P6 adds a fourth confirmation-worthy rule on top of P1-P5's existing ones; on the main corpus, the holdout corpus, and the dedicated `p6cost` cost-measurement corpus, it added at most one *new* real-run confirm prompt (1/10 tasks on `p6cost`) — but `p6cost`'s own write-up shows most of the pre-registered candidate tasks never reached a write step at all in this run, so this number likely understates P6's cost against a more reliable planner/quarantine pair, not a guarantee it's this cheap in general.

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

## Reproduce

Requires [uv](https://docs.astral.sh/uv/). The offline test suite needs no API key.

```bash
uv sync
uv run pytest                      # offline: mock env, policy engine, executor, harness

cp .env.example .env               # then add ANTHROPIC_API_KEY (never commit it)
make eval BASELINE=b0              # b0 | b1 | b2 | b3
make holdout-check                 # validates evals/corpus/holdout/attacks/*.yaml, no LLM calls
make corpus-check DIR=evals/corpus/p6cost   # validates any <dir>/{tasks,attacks}/*.yaml, no LLM calls

# what produced the tables above
CORDON_CONFIRM_MODE=deny    uv run python -m evals.harness --baseline b3 --budget-usd 1.00
CORDON_CONFIRM_MODE=approve uv run python -m evals.harness --baseline b3 --budget-usd 1.00

# v0.2: same, but against the holdout corpus, and/or pinned to P1-P5 only
CORDON_POLICY_VERSION=v1 uv run python -m evals.harness --baseline b3 --corpus-dir evals/corpus/holdout --budget-usd 0.50
```

Model names, token budget, confirmation mode, and policy version (`CORDON_POLICY_VERSION=v1|v2`, default v2) live in `.env`. Disk-cached LLM responses (`evals/.cache/`, gitignored) let B3 replay B2's calls at no cost — this holds across policy versions too, since `enforce_policy`/`policy_version` never change what's sent to the LLM. A full 80-scenario Haiku run cost roughly $0.4 to $0.6 (the price config was not independently verified); the 15-scenario holdout corpus costs well under $0.15 per baseline. The worst-case analysis is in `evals/worst_case.py` and `tests/test_worst_case.py`. A non-default `--corpus-dir` (like the holdout one above) writes its result file under `evals/results/<corpus name>/`, never `evals/results/` directly, so it can never be mixed up with a main-corpus run.

## Repository layout

```
src/cordon/   provenance, plan, planner, quarantine, executor, policy (P1-P6), confirm, llm,
              env (Environment container), dotenv (.env loader), tools/
evals/        corpus/ (main attacks + benign tasks; corpus/holdout/ for the v0.2 holdout
              corpus + its GUIDE.md/TEMPLATE.yaml; corpus/p6cost/ + corpus/contact-gap/ for
              v0.2.1's cost/gap measurement sets), harness, report, metrics (Wilson CI),
              predicates (deterministic success/attacker-goal checks), scenario
              (corpus loading), worst_case, cache, baselines/, holdout_check, corpus_check
tests/        offline tests (scripted LLM client, no network)
docs/         threat-model.md, results.md, results-holdout.md, results-p6cost.md,
              results-contact-gap.md, preregistration-v0.2.1.md, results-data/ (source JSONs)
```

## License

MIT
