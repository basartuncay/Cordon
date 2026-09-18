# Threat model

Status: M2 (provenance/plan/policy/executor + planner/quarantine LLMs
landed). Will be expanded further with adaptive red-teaming (M3).

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

## Known gaps

Residual risks the current policy engine (P1-P5) does **not** close, even
with the M2b fixes (multi-field P2, calendar-attendees-as-P2-recipients,
per-tool-class P5 budgets, reply/forward-original-content coverage). These
are exactly the kind of thing M3's adaptive red-teaming should target
first:

- **Dial-in links / URLs are not content-inspected.** P4 gates a calendar
  `location`/`description` field on its *provenance* (untrusted data needs
  confirmation), but nothing looks at what's actually inside the string. An
  attacker whose suggested location/description is itself literal-from-the-
  user (i.e. the user pastes a link the attacker fed them earlier in
  conversation, outside this agent's turn) would sail through with
  `trust == USER` and no policy signal at all. Same for any URL embedded in
  an email body that passes P2 because the recipient is allowlisted —
  P2 checks *sensitivity*, not *content*, so a malicious link mixed into an
  otherwise-benign message to a legitimate contact is invisible to it.
- **Untrusted content sent to an allowlisted recipient, on the user's
  behalf, without the user asking for it.** P1 allows any allowlisted
  recipient unconditionally; P2 only fires when a recipient is *outside*
  the allowlist. Neither rule catches the case where the *decision to send
  something at all* was manufactured by untrusted content rather than the
  user's actual request — e.g. an attacker's email convinces the agent to
  proactively email a real teammate (in the allowlist) with a fabricated
  status update, forwarded meeting note, or social-engineering message the
  user never asked to send. This is a real gap: the policy engine reasons
  about *where things go*, not about *whether the action itself was ever
  requested by the user*. Closing it would need something like binding
  every side-effecting step back to a piece of the user's own request
  (which the planner *could* do, choosing not to plan an unrequested step
  in the first place — but nothing here verifies that after the fact).
- **The overall P5 budget and the per-class budgets are static per run,**
  not adaptive to how "risky" the plan already looks (e.g. a plan that's
  already triggered three CONFIRMs isn't held to a tighter budget on its
  remaining steps).
- **Quarantine's schema constraint bounds *shape*, not *meaning*.** An
  `email`-kind extraction that returns a syntactically valid address gives
  no signal about whether that address is a real destination the user
  would recognize versus a plausible-looking attacker-controlled one — P1's
  allowlist check is the only thing actually doing that work, and it's a
  simple set-membership test with no fuzzy-matching/typo-domain detection
  (e.g. `alice@compnay.example` would not be caught as "close to but not
  actually" `alice@company.example`).

## Honesty note

This project does not claim to "solve" prompt injection. It claims to
reduce measured attack success rate on our corpus, at a measured utility /
confirmation-prompt cost. See `docs/results.md` (added in M3) for numbers.
