# Cordon — a prompt-injection-resistant mail & calendar agent (working name)

> **Status at closeout:** M0–M3 are complete (v0.1). v0.2 adds P6 (a
> content-trust gate, `CORDON_POLICY_VERSION=v1|v2`) and a 15-scenario
> holdout corpus written in a separate Claude.ai chat session — not
> human-written, not blind, but closed off from the implementer (Claude
> Code) during P6's design. M4's AgentDojo adapter and a real
> Gmail/Calendar mode were never started. Final, measured results live in
> `docs/results.md` (main corpus) and `docs/results-holdout.md` (holdout),
> not predicted anywhere else in this file. Everything below is the
> **original project plan**, kept as historical context — read it as
> intent at the time, not a current status claim.

## One-line pitch
A CaMeL-inspired agent for Gmail/Calendar where **untrusted email content can never decide what the agent does**, enforced by provenance tracking and a deterministic policy engine, and *measured* against an undefended baseline.

## Honest positioning (read before writing the README)
- This is **not novel research**. Prior art exists: AgentDojo (ETH benchmark with an email/calendar "workspace" suite), CaMeL (Google DeepMind, privileged/quarantined LLM + capabilities), Simon Willison's Dual-LLM pattern, many detector-style guardrails.
- Our value is **engineering + evaluation**: a small, readable, tested, maintainable implementation with a real Gmail/Calendar mode, a policy engine with unit tests, an attack corpus that includes non-English (Turkish/German) attacks, and an honest results + residual-risk section.
- Never claim "solves prompt injection". Claim: "reduces attack success rate from X/N to Y/N on our corpus, at the cost of Z utility / confirmation prompts".

## Threat model (put in docs/threat-model.md)
- **Trusted**: the user's own request text, the policy config, the tool schemas.
- **Untrusted**: everything returned by read tools (email bodies, subjects, sender names, attachments, event descriptions, invite text).
- **Attacker capability**: can send email / calendar invites to the user. Cannot modify the user's request, code, or config.
- **Attacker goals** (checked deterministically against mock env state): exfiltrate mailbox data to an attacker address; send/forward mail as the user; create/modify/delete calendar events; share files/links; poison summaries shown to the user (in-scope but weaker guarantee).
- **Out of scope**: model weights attacks, compromised OAuth tokens, malicious user, side channels.

## Architecture
1. **Planner (privileged LLM)** sees only the trusted user request + tool schemas. Emits a typed plan (JSON, pydantic-validated): steps, tool names, args that are literals or references to earlier step outputs. It never sees tool outputs. Control flow is fixed before any untrusted data is read.
2. **Executor** runs the plan. Every value returned by a read tool is wrapped as `Tainted[T]` with provenance (source id, sender trust level, sensitivity label).
3. **Quarantined LLM** (no tools) is used only for extraction/summarization of untrusted text into **schema-constrained** outputs (enums, dates, ids, bounded strings). Outputs stay tainted.
4. **Policy engine** (deterministic Python, no LLM) checks every side-effecting tool call using argument provenance before execution:
   - P1 Recipient provenance: `send_email/forward/share` recipients must come from the user's request literal or the contacts allowlist; otherwise require human confirmation.
   - P2 Exfiltration: content labeled private must not flow to recipients outside the allowlist without confirmation.
   - P3 Destructive/irreversible actions (delete, share, forwarding rules) always require confirmation.
   - P4 Calendar: attendees/links/dial-ins derived from untrusted data require confirmation.
   - P5 Budget: max N side-effect calls per plan; plan cannot be altered after untrusted data is read.
5. **Confirmation interface**: CLI first (`confirm.py`); Telegram approval bot is a stretch goal.
6. **Model-agnostic** `llm.py` wrapper. Default: a small model for the quarantined LLM, a stronger one for the planner. Keep model names in config, not code.

## Baselines to compare (evals/baselines/)
- B0: naive tool-loop agent (all content in one context).
- B1: B0 + delimiters/"ignore embedded instructions" system prompt (spotlighting-style).
- B2: Cordon without policy engine (ablation).
- B3: Cordon full.

## Repo layout
```
cordon/
  pyproject.toml            # uv, ruff, pytest, mypy(optional)
  src/cordon/{provenance,plan,planner,quarantine,executor,policy,confirm,llm}.py
  src/cordon/tools/{base,mock_mail,mock_calendar,gmail,gcal}.py
  evals/{corpus/attacks/*.yaml,corpus/tasks/*.yaml,harness.py,metrics.py,report.py,baselines/,agentdojo_adapter.py}
  tests/
  docs/{threat-model.md,architecture.md,results.md}
  README.md  LICENSE(MIT)  .github/workflows/ci.yml
```

## Milestones (each ends with tests passing + a commit)
**M0 (30 min)** Scaffold repo, uv project, ruff, pytest, CI, CLAUDE.md, threat-model stub. Commit author email must match the GitHub account email.
**M1 (2-3 h)** In-memory mock mailbox/calendar (fake data, reserved domains only, e.g. `evil.example`). Typed read/write tools. Baseline B0. Attack corpus v1 (≥30 attacks) + benign task set (≥15 tasks). Harness measuring attack success deterministically from env state. **Acceptance:** `make eval BASELINE=b0` prints benign utility and ASR.
**M2 (3-4 h)** `provenance.py`, `plan.py`, `planner.py`, `quarantine.py`, `executor.py`, `policy.py`. Policy engine must have thorough unit tests that run with **no LLM calls** (this is the cheap, high-signal part). **Acceptance:** policy tests green; Cordon runs the benign tasks end-to-end.
**M3 (2 h)** Run B0–B3 on the corpus. Add confirmation-rate and cost/latency metrics. Then red-team our own policies: write ≥10 adaptive attacks aimed at Cordon's weak points and document which succeed. **Acceptance:** `docs/results.md` with table (n shown, Wilson 95% CI) and a "Residual risks" section.
**M4 (stretch, 2 h)** AgentDojo workspace-suite adapter on a **small subset** (cap the cost; use a small model). Report the same metrics.
**M5 (2 h)** README (threat model, architecture diagram, results table, limitations), demo GIF, `make eval` reproducibility, topics/description on GitHub.
**Real mode (after M3, optional)** Gmail/Calendar OAuth with **read-only + draft** scopes by default; send only via confirmation. **Use a throwaway Google account, never the personal/primary one.**

## Attack corpus categories (evals/corpus/attacks/)
A1 direct override in body · A2 exfil via forward/send to attacker · A3 calendar manipulation (add attacker attendee / delete events) · A4 hidden/obfuscated text (HTML comments, zero-width, base64) · A5 multilingual (Turkish, German, mixed) · A6 authority/social engineering ("CEO urgent", fake system message) · A7 attacks on the quarantined extractor's free-text output (poisoned summaries) · A8 multi-step/chained (first email plants, second triggers) · A9 adaptive attacks against Cordon (M3).
Each attack file: id, category, injected email(s), attacker_goal (a predicate over final env state), notes.

## Metrics
Benign utility (no attack) · Utility under attack · Attack success rate (goal predicate true) · Confirmation-prompt rate (friction) · Tokens / cost / latency. Always report counts (k/n) and confidence intervals; corpus is small, avoid overclaiming.

## Working rules for Claude Code
- Mock environment by default. No real mailbox access until M3 is done and the user explicitly says so.
- Never commit secrets; `.env` in `.gitignore`; provide `.env.example`.
- Attack payloads target only the mock env; use reserved domains (`*.example`), never real third-party addresses.
- Prefer deterministic checks over LLM-judged checks everywhere possible.
- Keep modules small and typed (pydantic v2). Write tests first for `policy.py`.
- Track LLM spend: log tokens per run; abort an eval run if a configurable budget is exceeded.
- Do not describe results as better than measured; if the defense fails a case, record it.
