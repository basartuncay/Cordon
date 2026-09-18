# Threat model

Status: stub (M0). Will be expanded as the policy engine (M2) and adaptive
red-teaming (M3) land.

## Trust boundary

- **Trusted**: the user's own request text, the policy config, the tool
  schemas.
- **Untrusted**: everything returned by read tools — email bodies, subjects,
  sender names, attachments, event descriptions, invite text.

## Attacker model

- **Capability**: can send email / calendar invites to the user (i.e. inject
  content that the agent's read tools will later return). Cannot modify the
  user's request, the agent's code, or its config.
- **Goals** (checked deterministically against mock environment state):
  - exfiltrate mailbox data to an attacker-controlled address
  - send/forward mail as the user
  - create/modify/delete calendar events
  - share files/links with an attacker
  - poison summaries shown to the user (in-scope but weaker guarantee — the
    quarantined LLM's free-text output is not policy-checked the same way
    tool arguments are)

## Out of scope

- Attacks on model weights (e.g. training-time poisoning)
- Compromised OAuth tokens
- A malicious user (the user is trusted by definition)
- Side channels (timing, cache, etc.)

## Defense architecture (see docs/architecture.md)

1. Privileged planner never reads untrusted content; control flow is fixed
   before any tool output is read.
2. Every read-tool result is tainted with provenance (source id, sender
   trust level, sensitivity label).
3. A quarantined, tool-less LLM extracts/summarizes untrusted text into
   schema-constrained outputs only; outputs remain tainted.
4. A deterministic policy engine (no LLM) checks every side-effecting tool
   call's argument provenance before execution — see the P1–P5 rules in
   `CLAUDE.md`.
5. Anything the policy engine flags requires human confirmation.

## Honesty note

This project does not claim to "solve" prompt injection. It claims to
reduce measured attack success rate on our corpus, at a measured utility /
confirmation-prompt cost. See `docs/results.md` (added in M3) for numbers.
