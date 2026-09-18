# Cordon

A CaMeL-inspired agent for Gmail/Calendar where **untrusted email content can never decide what the agent does**, enforced by provenance tracking and a deterministic policy engine — measured against an undefended baseline.

> Status: early scaffold (M0/M1). Not novel research; see "Positioning" below.

## Why

Prompt injection in email/calendar agents lets attacker-controlled content (email bodies, invite text, sender names) hijack an agent's tool calls — e.g. exfiltrating mail or adding an attacker as a calendar attendee. Cordon's answer is architectural, not a better prompt: a privileged planner that never reads untrusted content, tainted data with provenance, and a deterministic policy engine that gates every side-effecting tool call.

## Positioning

This is **not novel research**. Prior art: [AgentDojo](https://github.com/ethz-spylab/agentdojo), [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind), Simon Willison's Dual-LLM pattern, and various detector-style guardrails. Cordon's value is engineering + evaluation: a small, readable, tested implementation with a real Gmail/Calendar mode, a policy engine with unit tests, a multilingual attack corpus (English/Turkish/German), and an honest results + residual-risk writeup.

We do not claim to "solve prompt injection." We report measured attack success rate reductions on our corpus, at a measured utility/friction cost.

## Architecture (short version)

1. **Planner** (privileged LLM) sees only the user's request + tool schemas, emits a typed plan. Never sees tool outputs.
2. **Executor** runs the plan; every read-tool result is wrapped as `Tainted[T]` with provenance.
3. **Quarantined LLM** (no tools) extracts/summarizes untrusted text into schema-constrained outputs. Outputs stay tainted.
4. **Policy engine** (deterministic, no LLM) checks every side-effecting call against argument provenance before execution.
5. **Confirmation interface** for anything the policy engine flags.

See [docs/threat-model.md](docs/threat-model.md) and [docs/architecture.md](docs/architecture.md) for details.

## Status / milestones

- [x] M0 — repo scaffold, tooling, CI, threat-model stub
- [x] M1 — mock mailbox/calendar, baseline B0, attack corpus v1, eval harness
- [ ] M2 — provenance/plan/policy engine (Cordon proper)
- [ ] M3 — B0–B3 comparison, adaptive red-teaming, `docs/results.md`
- [ ] M4 (stretch) — AgentDojo adapter
- [ ] M5 — polished README, demo, reproducibility
- [ ] Real Gmail/Calendar mode (read-only + draft by default; opt-in, throwaway account only)

## Getting started

```bash
uv sync
make eval BASELINE=b0
```

By default everything runs against an **in-memory mock mailbox/calendar** — no real Gmail/Calendar access. See [Real mode](#real-mode) before ever pointing this at a live account.

## Real mode

Disabled until M3 is complete. When enabled, it uses OAuth with **read-only + draft** scopes; sending requires explicit human confirmation. Use a throwaway Google account — never your personal/primary one.

## Metrics

Benign utility, utility under attack, attack success rate, confirmation-prompt rate, and cost/latency — always reported as counts (k/n) with confidence intervals, since the corpus is small.

## License

MIT — see [LICENSE](LICENSE).
