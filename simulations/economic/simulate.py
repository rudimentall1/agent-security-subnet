from dataclasses import dataclass


@dataclass(frozen=True)
class Environment:
    search_cost: float = 0.01
    claim_cost: float = 0.005
    discovery_probability: float = 0.01
    duplicate_rate: float = 0.20
    verification_probability: float = 0.90
    base_discovery_reward: float = 10.0
    saturation_budget: float = 1000.0


def diminishing_discovery_probability(
    base_probability: float,
    budget: float,
    saturation_budget: float,
) -> float:
    return base_probability / (
        1.0 + budget / saturation_budget
    )


def simulate_discovery(
    budget: int,
    env: Environment,
) -> dict:
    probability = diminishing_discovery_probability(
        env.discovery_probability,
        budget,
        env.saturation_budget,
    )

    raw_discoveries = budget * probability

    duplicates = raw_discoveries * env.duplicate_rate

    novel_discoveries = max(
        0.0,
        raw_discoveries - duplicates,
    )

    verified_novel = (
        novel_discoveries
        * env.verification_probability
    )

    reward = (
        verified_novel
        * env.base_discovery_reward
    )

    search_cost = budget * env.search_cost

    claim_cost = raw_discoveries * env.claim_cost

    total_cost = search_cost + claim_cost

    profit = reward - total_cost

    roi = (
        profit / total_cost
        if total_cost > 0
        else 0.0
    )

    reward_per_search = (
        reward / budget
        if budget > 0
        else 0.0
    )

    return {
        "budget": budget,
        "probability": probability,
        "raw_discoveries": raw_discoveries,
        "duplicates": duplicates,
        "novel_discoveries": novel_discoveries,
        "verified_novel": verified_novel,
        "reward": reward,
        "cost": total_cost,
        "profit": profit,
        "roi": roi,
        "reward_per_search": reward_per_search,
    }


def print_budget_results(results: list[dict]) -> None:
    header = (
        f"{'budget':>10} "
        f"{'p(discovery)':>14} "
        f"{'novel':>12} "
        f"{'verified':>12} "
        f"{'reward':>12} "
        f"{'cost':>12} "
        f"{'profit':>12} "
        f"{'ROI':>10} "
        f"{'reward/search':>15}"
    )

    print(header)
    print("-" * len(header))

    for result in results:
        print(
            f"{result['budget']:10d} "
            f"{result['probability']:14.6f} "
            f"{result['novel_discoveries']:12.2f} "
            f"{result['verified_novel']:12.2f} "
            f"{result['reward']:12.2f} "
            f"{result['cost']:12.2f} "
            f"{result['profit']:12.2f} "
            f"{result['roi']:10.2f} "
            f"{result['reward_per_search']:15.4f}"
        )


def main() -> None:
    env = Environment()

    budgets = (
        100,
        250,
        500,
        1_000,
        2_500,
        5_000,
        10_000,
        50_000,
    )

    print("PoNF Economic Information Market Simulation v0.3")
    print()

    print(
        f"base_probability={env.discovery_probability}, "
        f"saturation_budget={env.saturation_budget}, "
        f"duplicate_rate={env.duplicate_rate}, "
        f"verification={env.verification_probability}"
    )

    print()

    results = [
        simulate_discovery(budget, env)
        for budget in budgets
    ]

    print_budget_results(results)

    print()
    print("Interpretation")
    print(
        "Increasing search budget should produce "
        "diminishing information efficiency."
    )


if __name__ == "__main__":
    main()
