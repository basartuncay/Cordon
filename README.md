# Cordon

[![CI](https://github.com/basartuncay/Cordon/actions/workflows/ci.yml/badge.svg)](https://github.com/basartuncay/Cordon/actions/workflows/ci.yml)

A CaMeL-inspired mail & calendar agent prototype in which untrusted email content cannot decide what the agent does. Provenance tracking plus a deterministic policy engine, evaluated against undefended baselines on a small attack corpus (English, Turkish, German).

> **Status: research prototype.** Runs against an in-memory mock mailbox and calendar only (`*.example` domains). Real Gmail/Calendar access is **not implemented**. This is not production security software and it does not "solve" prompt injection.

## What this is, and what it isn't

This is **not novel research**. Prior art includes [AgentDojo](https://arxiv.org/abs/2406.13352) (a benchmark with an email/calendar suite), [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind's privileged/quarantined design with capabilities) and Simon Willison's [Dual LLM pattern](https://simonwillison.net/2023/Apr/25/dual-llm-pattern/).

Cordon is a small, readable implementation of the same family of ideas, with:

- a typed plan DSL, taint tracking and a policy engine whose unit tests run with no LLM calls,
- an 80-scenario corpus (16 benign tasks, 64 attacks) with deterministic success predicates (no LLM judge),
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
  E -->|"side-effecting call + provenance"| PE{"Policy engine<br/>P1-P5"}
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

## Limitations

- Small corpus and a single run per system; confidence intervals are wide.
- One model family (Claude Haiku 4.5), mock environment only.
- The attack corpus, including the adaptive attacks aimed at the policy engine, was written by the same model that wrote the policy. An independent red team would find more.
- Auto-deny is safer than a real user would be; auto-approve is the opposite extreme. Neither models confirmation fatigue.
- No real Gmail/Calendar mode, no AgentDojo adapter.

## Project status and future work

**Done (M0–M3):** repo scaffold, tooling and CI; a mock mailbox/calendar with typed read/write tools; the undefended (B0) and spotlighting (B1) baselines; the planner/executor/quarantine pipeline with taint tracking; the P1–P5 policy engine with no-LLM unit tests; an 80-scenario corpus (16 benign, 64 attacks across 10 categories, including Turkish/German attacks); a full B0–B3 real-model evaluation run with tiered/primary-secondary ASR, utility, and a worst-case (no-LLM) analysis, all written up honestly in `docs/results.md`.

**Not done:** an AgentDojo adapter (M4, stretch); a real Gmail/Calendar mode (OAuth, read-only + draft scopes); any model besides Claude Haiku 4.5; more than one run per baseline.

**Plausible next steps**, roughly in order of how directly they'd close a documented gap:

- Bind every side-effecting call back to a specific piece of the user's own request, so content flowing to an already-allowlisted recipient the user never asked to message (the `a9_003`-style gap) has something to be checked against, not just provenance.
- A "safe re-query" path for an empty search/list result — letting the planner (or a bounded retry loop) try a different query instead of ending the plan, which is part of why B2/B3's benign utility trails B0/B1's on this run.
- An attack corpus (or at least the adaptive A9 attacks) written or reviewed by someone other than the model that wrote `policy.py` — the current corpus can only find gaps its own author could imagine.
- A small study of real human confirmation behavior, to replace the two artificial ceilings (auto-deny, auto-approve) with something closer to actual confirmation-fatigue rates.

This list is deliberately short and un-scored — see `docs/results.md`'s Limitations section for the honest cost/benefit numbers behind each item, and `docs/threat-model.md`'s Known gaps for the exact scenarios that demonstrate them.

## Reproduce

Requires [uv](https://docs.astral.sh/uv/). The offline test suite needs no API key.

```bash
uv sync
uv run pytest                      # offline: mock env, policy engine, executor, harness

cp .env.example .env               # then add ANTHROPIC_API_KEY (never commit it)
make eval BASELINE=b0              # b0 | b1 | b2 | b3

# what produced the tables above
CORDON_CONFIRM_MODE=deny    uv run python -m evals.harness --baseline b3 --budget-usd 1.00
CORDON_CONFIRM_MODE=approve uv run python -m evals.harness --baseline b3 --budget-usd 1.00
```

Model names, token budget and confirmation mode live in `.env`. Disk-cached LLM responses (`evals/.cache/`, gitignored) let B3 replay B2's calls at no cost. A full 80-scenario Haiku run cost roughly $0.4 to $0.6 (the price config was not independently verified). The worst-case analysis is in `evals/worst_case.py` and `tests/test_worst_case.py`.

## Repository layout

```
src/cordon/   provenance, plan, planner, quarantine, executor, policy, confirm, llm,
              env (Environment container), dotenv (.env loader), tools/
evals/        corpus/ (attacks + benign tasks), harness, report, metrics (Wilson CI),
              predicates (deterministic success/attacker-goal checks), scenario
              (corpus loading), worst_case, cache, baselines/
tests/        offline tests (scripted LLM client, no network)
docs/         threat-model.md, results.md
```

## License

MIT
