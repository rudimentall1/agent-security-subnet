# Economic Information Market — v0.3 Findings

## Status

PASS with reservations.

The v0.3 experiment demonstrates a useful diminishing-return property:
increasing search budget does not produce proportional increases in verified novel failures.

## Observed results

| Budget | Verified Novel | Reward | Cost | Profit | ROI |
|---:|---:|---:|---:|---:|---:|
| 100 | 0.65 | 6.55 | 1.00 | 5.54 | 5.52 |
| 250 | 1.44 | 14.40 | 2.51 | 11.89 | 4.74 |
| 500 | 2.40 | 24.00 | 5.02 | 18.98 | 3.78 |
| 1000 | 3.60 | 36.00 | 10.03 | 25.98 | 2.59 |
| 2500 | 5.14 | 51.43 | 25.04 | 26.39 | 1.05 |
| 5000 | 6.00 | 60.00 | 50.04 | 9.96 | 0.20 |
| 10000 | 6.55 | 65.45 | 100.05 | -34.59 | -0.35 |
| 50000 | 7.06 | 70.59 | 500.05 | -429.46 | -0.86 |

## Key observation

A 50x increase in search budget, from 1,000 to 50,000, produced only approximately 1.96x more verified novel failures.

The corresponding reward also increased by approximately 1.96x, while search cost increased approximately 50x.

This prevents unlimited compute from translating directly into proportional economic dominance under the current model.

## Economic interpretation

The model produces a natural diminishing-return region.

The highest simulated absolute profit occurs near a budget of approximately 2,500 search units.

This is not yet a protocol constant.

The result depends on the assumed discovery probability, saturation curve, reward value, and search cost.

## Important limitation

This is a deterministic expected-value model.

It does not yet model:

- variance;
- stochastic discovery;
- heterogeneous challenge difficulty;
- different search costs;
- different miner hardware;
- validator sampling;
- concurrent miners;
- emission normalization;
- TAO price;
- subnet weight dynamics.

Therefore this experiment is evidence for a mechanism hypothesis, not proof of economic security.

## Design conclusion

The reward mechanism should preserve diminishing information returns.

Search budget should not be treated as a direct multiplier of reward.

Reward should primarily depend on verified novel security information.

## Next experiment

v0.4 should test parameter sensitivity:

- reward multiplier;
- search cost;
- discovery probability;
- saturation budget;
- duplicate rate;
- verification probability.

The objective is to determine whether the anti-brute-force property survives reasonable parameter changes.

A mechanism that only works for one parameter configuration is not acceptable.
