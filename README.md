# agent-security-subnet

**A Bittensor subnet where miners find security policy violations in stateful,
tool-using agents, and validators independently reproduce and score them.**

Built for the [Bittensor Global Subnet Hackathon](https://www.hackquest.io/hackathons/Bittensor-Global-Subnet-Hackathon).

**Demo video:** [youtu.be/MjzNU8H3D8A](https://youtu.be/MjzNU8H3D8A)

| | |
|---|---|
| SDK | bittensor **11.1.0** (`Subtensor.read`, `SetWeights`, `http_auth`) |
| Tests | 90 passing (`pytest -q`) |
| Chain evidence | real testnet commit — see [`evidence/`](evidence/) |
| Status | prototype; see [Limitations](#limitations) below before trusting any claim |

---

## 1. What this is

A validator asks a miner to explore a stateful agent (ticket system + email
tool + admin controls) and find a sequence of tool calls that violates a
security policy the miner is never shown directly — e.g. sending a
privileged email without the prerequisite approvals. The miner returns an
attack trace. The validator independently replays that exact trace against
its own private copy of the same agent and only pays for findings that are
**reproducible** (the replay matches what the miner reported) and a
**genuine policy violation** (not just any surprising output).

```
Task ─────────────────────────────────────────► Miner
 (public: allowed tools, objective, step budget)   │
                                                     │ attack_trace +
                                                     │ observed_behavior
                                                     ▼
                                            Validator (private replay)
                                                     │
                                    reproducible? + policy_violation?
                                                     │
                                        VERIFIED / DUPLICATE / FALSE_POSITIVE
                                                     │
                                                     ▼
                                     aggregate_scores() ──► set_weights()
```

## 2. Scope: deterministic policy testing, not LLM red-teaming

This subnet tests whether an autonomous tool-calling system can be driven,
through a sequence of otherwise-individually-plausible actions, into
violating a security policy — a failure mode that exists regardless of
what decides the system's next action. The target under test
(`subnet/stateful_target.py`) is a deterministic finite-state machine, not
a language model, and no LLM is anywhere in this subnet's loop. That's a
deliberate design choice, not a placeholder for one: a fully-specified
state machine is what lets the validator's private replay be an *exact*
reproducibility check (the same trace always produces the same observed
behavior) rather than depend on a second model's non-deterministic
judgment call about whether a policy was violated. If you came here
looking for LLM jailbreak/hallucination benchmarking, that's a different
problem — non-deterministic to verify by construction — that this subnet
does not attempt to solve.

The real, still-open limitation is task-space size (6 scenario templates,
11 fixed action names), not the absence of a language model — see
[Limitations](#limitations) and [`docs/economics/`](docs/economics/) for
what that actually constrains.

## 3. Architecture

```
bittensor_subnet/
  miner.py        FastAPI HTTP service, signed-request verification, /generate
  validator.py    Signed HTTP client -> private replay pipeline
  chain.py        Neuron discovery (Subtensor.read) + weight submission (SetWeights)
  run_miner.py    uvicorn entrypoint
  run_validator.py  subnet-mode loop (discover -> evaluate -> aggregate -> set_weights)

subnet/
  protocol.py           SecurityTask / ExploitFinding / VerificationResult, reproduction keys
  stateful_target.py    the FSM being attacked
  stateful_oracle.py    per-scenario expected-behavior policy (validator-only)
  stateful_miner.py     reference miner strategies
  stateful_validator.py replay + verdict + severity + score
  stateful_scoring.py   FindingCorpus (dedup) + reward formula

tests/          90 unit tests, no network required (bittensor calls are mocked)
evidence/       real testnet run logs + on-chain commit record
docs/economics/ reward-mechanism design notes and known attack surfaces
```

`subnet/miner.py`, `subnet/validator.py`, `subnet/scoring.py`, `subnet/target.py`
are an earlier, non-stateful protocol version kept only for their own test
file (`tests/test_scoring_integrity.py`, `test_v13.py`, `test_v14.py`) and are
**not** used by `bittensor_subnet/*`. They are legacy and should not be read
as the current design.

## 4. Running it

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest -q          # 90 passed, no network needed
```

### Local miner + validator (no chain)

```bash
# terminal 1
VERITENSOR_LOCAL_NO_AUTH=1 python3 -m bittensor_subnet.run_miner

# terminal 2
VERITENSOR_VALIDATOR_MODE=benchmark \
VERITENSOR_MINER_URL=http://127.0.0.1:8091 \
VERITENSOR_VALIDATOR_HOTKEY_SS58=<any wallet's hotkey ss58> \
python3 -m bittensor_subnet.run_validator
```

### Against a real Bittensor subnet

```bash
VERITENSOR_VALIDATOR_MODE=subnet \
VERITENSOR_NETUID=<netuid> \
VERITENSOR_NETWORK=test \
VERITENSOR_WALLET=<coldkey name> \
VERITENSOR_VALIDATOR_HOTKEY=<hotkey name> \
python3 -m bittensor_subnet.run_validator
```

Key environment variables (see `ValidatorConfig.from_env` / `MinerConfig.from_env`
for the full list): `VERITENSOR_MINER_HOTKEY_SS58` (miner-side auth),
`VERITENSOR_CORPUS_DB_PATH` (persist the duplicate-finding corpus across
restarts — recommended in production, see below), `VERITENSOR_EPOCH_BLOCKS`
(how many blocks make up one reward epoch, default 360),
`VERITENSOR_REQUIRE_VALIDATOR_PERMIT` + `VERITENSOR_NETUID` (miner rejects
callers that aren't a registered validator on this subnet — off by
default), `VERITENSOR_RATE_LIMIT_MAX` / `VERITENSOR_RATE_LIMIT_WINDOW_SECONDS`
(per-caller rate limit on `/generate`, default 30 req/60s).

## 5. The reward-exhaustion bug, and how it's addressed

The first real testnet run (`evidence/testnet_e2e_2026-09-08.md`) showed the
mechanism working for exactly one cycle, then permanently producing
`set_weights=false` — because the task space was 5 fixed scenarios with a
single reachable solution each, and once solved, the in-memory duplicate
corpus marked that solution as DUPLICATE forever, on every miner, forever.

Two changes address this:

- **Epoch-scoped task IDs** (`subnet/protocol.py::build_task`,
  `bittensor_subnet/validator.py::make_benchmark_tasks`): the wire-visible
  `task_id` is qualified with the current epoch (derived from block height,
  see `EPOCH_BLOCKS` in `run_validator.py`) while `parent_task_id` keeps
  pointing at the unchanged underlying policy. The same winning trajectory
  therefore produces a different `reproduction_key` every epoch — a solved
  scenario still can't be re-paid *within* an epoch (that's a genuine
  duplicate), but starts paying again next epoch instead of being dead
  forever. See `tests/test_epoch_scoped_tasks.py`.
- **Optional persistent duplicate corpus** (`subnet/stateful_scoring.py::FindingCorpus`,
  `VERITENSOR_CORPUS_DB_PATH`): without this, a validator restart forgets
  every previously-paid finding, which is its own (smaller, epoch-bounded)
  exploit. Set the env var in production.
- **`set_weights` respects the chain's own rate limit.** Confirmed live on
  testnet 557: the chain rejects `set_weights` more often than once every
  `weights_rate_limit` blocks (100 on this subnet), and the validator loop
  previously attempted it every cycle regardless, mostly getting a
  `ChainError`. `subnet_cycle` now reads `weights_rate_limit_blocks()` and
  `own_last_weights_update_block()` and skips the attempt (rather than
  submitting a doomed transaction) until the window has passed.

This does not make the task space infinite — 6 scenario templates is still
small. Expanding scenario generation is the next real step, not a solved
problem; see `docs/economics/`.

## Real testnet-557 validation log (2026-09-11)

Beyond unit tests, the following was run live against testnet 557 after the
fixes above (wallet `veritensor`, hotkey `validator2`, UID 4):

- `registered_miners=3` — miner discovery via `sub.read("neurons", ...)`
  works (previously crashed with `AttributeError` on the removed
  `Subtensor.neurons`/`.metagraph()` API).
- Across 11 consecutive cycles with `VERITENSOR_EPOCH_BLOCKS=3`: `state-001`
  paid `VERIFIED reward=0.775` in each new epoch, correctly fell back to
  `DUPLICATE`/`set_weights=false reason=no_positive_scores` only *within*
  the same epoch (cycle 6, epoch unchanged from cycle 5), and paid again
  the moment the epoch rolled over (cycle 7) — the reward-exhaustion
  failure from the original evidence run did not reoccur.
- A real `TimelockedWeightsCommitted` extrinsic was submitted and accepted
  (block 7979794, reveal_round 32100223). A later live read at block 7983401
  showed `timelocked_weight_commits={}` and revealed weights containing
  validator UID 4, confirming that the commit-reveal path completed and the
  validator's weights were applied on-chain.
- Discovered along the way: `verify_request()` had been returning the
  miner's own hotkey instead of the actual caller's (fixed); `active` on
  this subnet is `False` for every neuron including reachable miners, so
  filtering on it silently produced `registered_miners=0` (fixed --
  `miner_endpoints()` now filters on routability, not `active`); the chain
  rate-limits `set_weights` and the loop wasn't accounting for it (fixed).

## Limitations

Written plainly, because a security-testing project that overstates its own
status is not a good look.

- **The task space is small and the target is enumerable.** 6 scenario
  templates, 11 fixed action names, 6-step budgets — the target is fully
  solvable by a fixed strategy (`subnet/stateful_miner.py::BoundarySequenceMiner`).
  Epoch-scoping (above) keeps the mechanism from dying once a scenario is
  solved, but doesn't make finding a solution hard after the first epoch
  it's known. This is the real scaling axis (not adding an LLM — see
  [Scope](#2-scope-deterministic-policy-testing-not-llm-red-teaming)
  above); expanding scenario generation is the next real step, not solved
  here.
- **`FindingCorpus` persistence is opt-in**, not the default. Without
  `VERITENSOR_CORPUS_DB_PATH` set, a validator restart forgets prior
  findings. Two independent validators also don't share a corpus with each
  other — each has its own view of what's a duplicate.
- **Miner-side auth now checks both the request signature and (optionally)
  subnet validator-permit membership**, and is rate-limited per caller.
  Set `VERITENSOR_REQUIRE_VALIDATOR_PERMIT=1` + `VERITENSOR_NETUID=<netuid>`
  to enable the permit check (off by default — it needs a working chain
  connection to refresh the permit list, so it fails closed if the chain is
  unreachable rather than silently accepting every caller). Rate limiting
  (`VERITENSOR_RATE_LIMIT_MAX` / `VERITENSOR_RATE_LIMIT_WINDOW_SECONDS`,
  default 30 req/60s per caller hotkey) is always on. Fixed alongside this:
  `verify_request()` previously returned the miner's *own* configured
  hotkey instead of the actual caller's hotkey (the real return value of
  `bt.http_auth.verify()` was computed and discarded) — every caller was
  indistinguishable from the miner itself to any downstream code.
- **Chain-write paths are unit-tested with mocks; live validation is a
  point-in-time log, not continuous CI.** The mechanics (`set_weights`,
  neuron discovery, the rate-limit skip) were run live against testnet 557
  on 2026-09-11 (see the validation log above) — this isn't untested, but
  it also isn't re-verified against a live chain on every change the way
  the 88 unit tests are. This repository's own CI has no network path to
  a Bittensor node.

## Evidence

- `evidence/testnet_e2e_2026-09-08.md` — real testnet run: signed HTTP
  between validator and live miners, private replay, `VERIFIED` /
  `DUPLICATE` / `FALSE_POSITIVE` verdicts, and a real on-chain
  `TimelockedWeightsCommitted` extrinsic.
- `evidence/evidence_demo.json` — machine-readable run output from
  `scripts/evidence_demo.py` (local miner + benchmark-mode validator, no
  chain required — reproducible by anyone).

## License

MIT — see [`LICENSE`](LICENSE).
