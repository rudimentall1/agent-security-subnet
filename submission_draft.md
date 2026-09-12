# agent-security-subnet — Updated Proposal & Pitch Script (draft)

*Bittensor Global Subnet Hackathon, HackQuest — deadline Oct 19, 2026*

---

## 1. Updated Proposal

### Problem
AI agents are being given real tools — email, admin panels, ticket systems,
credential stores — faster than anyone is verifying the *sequences* of
actions that break their security policy. Prompt-injection scanners and
LLM-judge red-teamers test single-turn behavior; they miss exploits that
only appear after several legitimate-looking steps compound into a
privilege violation. There is no standing, incentive-aligned network that
continuously hunts for these multi-step exploits and produces
*verifiable* proof when it finds one.

### Mechanism
`agent-security-subnet` scores miners for finding attack **traces** —
ordered tool-call sequences — against a deterministic stateful target
agent, where a hidden security policy defines what each final action
*should* return. A validator privately replays the exact same trace
against a fresh clone of the target and only pays when the replay is:

- **reproducible** — replay output matches the miner's claimed output,
- **a genuine policy violation** — the replayed outcome differs from what
  policy allows,
- **novel** — not a duplicate of an already-rewarded trace this epoch.

Because the target is a deterministic finite-state machine rather than an
LLM being judged by another LLM, reproducibility is *exact*, not a
probabilistic judgment call — closing the main way reward-hacking happens
in judge-based security subnets.

Six scenario templates are implemented today: privilege boundary,
policy bypass, tool escalation, state confusion, a safe (non-exploitable)
control, and — added in this development pass — **credential pivot**, a
"confused deputy" scenario where an agent must not treat a
self-declared role claim as real authorization. The pattern is designed
to extend: each new scenario is a new state field + a couple of new
actions on the same FSM/oracle/miner/validator scaffolding, not a redesign.

### Why this is Bittensor-native, not just "a Web2 security tool with a token"
The mechanism produces a **verifiable digital commodity** — a
(trace, reproduction_key, verdict) triple that anyone can independently
replay and check — which is exactly what Yuma consensus is good at
weighting honestly. It doesn't rely on subjective LLM judging, which is
the part of most "AI agent security" subnets that's easiest to farm.

### Portable proof: OAA-signed findings
A `VERIFIED` finding can be signed as an
[OAA (open-agent-attestation)](https://github.com/rudimentall1/open-agent-attestation)
token — a small Ed25519-JWT standard already used independently by two
other projects from this author (agent-guardrail, agentic-wallet-guardian-v3).
Anyone holding only the public key can verify a finding without any access
to this subnet's validator or database. Stated honestly: `agent-guardrail`'s
own policy schema has no concept of blocking a multi-step sequence (it
gates one tool call at a time), so this does not claim automatic downstream
enforcement — `scripts/oaa_to_guardrail_suggestion.py` produces a
*suggested* rule for a human to review, not an auto-applied one. This is
new in this development pass and is currently unit-tested (mocked chain
calls), not yet exercised against a live testnet run.

### Evidence to date
- 106/106 unit tests passing (`pytest -q`, pure Python, no chain
  dependency — bittensor calls are mocked). This count includes the core
  scoring/validator/miner logic, the chain-discovery layer, and the OAA
  attestation bridge added in this pass.
- A real testnet cycle on netuid 557 (`test` network): 3 miners
  discovered, HTTP-signed queries, verification, reward calculation,
  `SetWeights`.
- A confirmed on-chain `TimelockedWeightsCommitted` extrinsic (block
  7979794, reveal_round 32100223). A later live chain read at block
  7983401 showed `timelocked_weight_commits={}` (the pending commit had
  resolved) with revealed weights containing validator UID 4 — the
  commit-reveal path completed and the validator's weights were applied
  on-chain, not just submitted.
- A quantified economic-attack analysis (`docs/economics/`) showing
  brute-force search budget scaling ×50 only yields ×1.96 verified
  findings, with ROI going negative past a search-budget threshold —
  i.e., the mechanism resists "just add more compute" gaming by
  construction, not by a manually-tuned cap. Stated in that same doc: this
  is a deterministic expected-value model, not proof of economic security
  under live adversarial conditions.

### Honest current gaps (and what closes them before Oct 19)
- **credential_pivot and the OAA attestation bridge have not yet been run
  against a live testnet cycle** — both are unit-tested only so far. A
  fresh live run covering both would be the strongest single addition to
  this proposal if time allows before the deadline.
- **Duplicate-finding corpus persistence is opt-in, not the default**
  (`VERITENSOR_CORPUS_DB_PATH`). Without it, a validator restart forgets
  previously-paid findings — a real, if bounded, path to re-paying the
  same exploit. Making this the default is a small change, not yet done.
- **Task-space breadth**: 6 scenario templates today. Credible roadmap
  to 15–20 by expanding the same FSM pattern, prioritized by real-world
  tool categories (payments, file access, third-party API calls).
- **Economic model** is currently simulation-based, not measured against
  live adversarial miners at scale; that's the natural next validation
  step post-hackathon.

### Roadmap (post-hackathon)
1. Expand scenario library to cover common agentic-tool categories
   (payments, file systems, third-party APIs).
2. Make the persistent duplicate-finding corpus the default, not opt-in.
3. Run a live testnet cycle covering credential_pivot and OAA attestation
   issuance, and publish that evidence alongside the existing run.
4. Publish the scenario spec as an open format so other teams can
   contribute target agents/policies without touching consensus code.

---

## 2. Pitch Script (~5 minutes, spoken)

**[0:00–0:30] Hook**
"Every company giving an AI agent real tools — email, admin access, a
database — is trusting that agent to never find the one sequence of
normal-looking actions that breaks its rules. Today, nothing is
continuously hunting for that sequence and *proving* it when found.
That's what we built."

**[0:30–1:30] The mechanism**
"Miners probe a stateful agent — not a single prompt, a whole
interaction history — looking for an attack trace: a sequence of tool
calls that ends in a security-policy violation. A validator replays that
exact trace against a fresh copy of the same agent. If the replay
reproduces the same result, and that result violates policy, and it's
not a duplicate someone already found this epoch — the miner gets paid.
If it doesn't replay, or it's a false positive, it gets zero. No LLM
judge in the loop deciding subjectively whether something 'counts.'"

**[1:30–2:15] Why it's hard to fake**
"We ran the actual economics: scaling a miner's search budget 50x only
produced about 2x more verified findings — and past a certain point,
ROI goes negative. So brute-forcing the reward doesn't work by
construction, not because we capped it by hand. And because replay is
deterministic, there's no 'convince the judge model' attack surface —
either the trace reproduces the exact same outcome, or it's worthless."

**[2:15–2:45] Portable proof**
"A verified finding isn't just a number in our own database — it gets
signed as an OAA attestation, a small open standard, so anyone with just
our public key can independently verify it happened, without touching
our servers at all."

**[2:45–3:45] What's live today**
"[Play demo video 1: miner discovery → verification → scoring]
[Play demo video 2: SetWeights → commit → reveal → on-chain weights]
This isn't a simulation — that's a real timelocked commit-reveal cycle on
Bittensor testnet, confirmed by reading the chain state back after the
reveal window closed."

**[3:45–4:30] Why now, why this market**
"As agentic AI moves from chatbots into things that can actually move
money, delete data, or export credentials, the cost of an undetected
multi-step exploit stops being embarrassing and starts being existential
for whoever deployed that agent. A subnet that continuously,
verifiably, and cheaply hunts for those exploits is infrastructure, not
a demo — and it gets more valuable as more of the economy runs on
agents, not less."

**[4:30–5:00] Close**
"We're not claiming this is finished. We're honest in our own docs about
what's still thin — task-space breadth, live adversarial economics at
scale, and our two newest pieces not yet proven live on-chain. What we
are claiming is a mechanism that's provably hard to game, with a real
on-chain cycle behind it, built by a team that writes down its own
limitations instead of hiding them. That's what we're asking you to bet
on."

---

*Notes for delivery: keep both demo video segments back-to-back exactly
as recorded, per the original plan. If a live run covering credential_pivot
and OAA attestation issuance gets done before the deadline, update the
"Honest current gaps" section to move that item to Evidence instead.*
