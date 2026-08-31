# Economic Attack Simulation v0.2 — Findings

## Status

v0.2 is a failed baseline, not a validated economic mechanism.

The simulation successfully exposed weaknesses in the preliminary reward model.

## Observations

### 1. Validator-aware reward was not comparable

The classifier attack produced very large positive profits at several dangerous-class distributions.

This exposed a unit mismatch in the simulation: classification rewards were paid per sample, while discovery rewards were paid per verified novel failure.

Conclusion:

Prediction accuracy must not be treated as an independently monetized commodity in the PoNF base reward.

### 2. Collusion remains weakly profitable

Observed results:

- honest explorer: 62.13 profit
- 2 colluding miners: 62.85
- 5 colluding miners: 65.40
- 10 colluding miners: 69.65

The model therefore does not yet eliminate the economic value of manufactured replication.

Conclusion:

Replication rewards must depend on demonstrated independent information gain rather than identity count.

### 3. Sybil attack is currently disincentivized

Observed profit decreases as the number of identities increases.

However, this result depends partly on explicit identity and invalid-claim penalties and therefore is not sufficient to establish Sybil resistance.

### 4. Brute force

Brute force generated substantially higher absolute profit because it used five times the search budget, but lower ROI than the honest baseline.

This suggests diminishing economic efficiency may emerge naturally, but this must be tested over a wider search-budget range.

### 5. Specialist

The specialist strategy achieved higher ROI than the generic honest explorer.

This is considered desirable: the subnet should reward superior domain-specific security research rather than force artificial equality between miners.

## Design conclusions

The current model should not be treated as the final reward mechanism.

The next version should make verified information gain the fundamental reward primitive.

Target:

    reward ≈ verified information gain

not:

    reward ≈ correct classification count

## Next experiment

v0.3 will model:

- bounded discovery reward;
- normalized search budget;
- diminishing returns;
- canonical failure identity;
- independent replication;
- discovery vs replication economics;
- Sybil-neutral accounting;
- collusion resistance;
- validator-aware attacks without direct per-prediction monetization.
