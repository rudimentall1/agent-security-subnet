from dataclasses import dataclass
from itertools import product


@dataclass(frozen=True)
class Environment:
    search_cost: float
    claim_cost: float
    discovery_probability: float
    duplicate_rate: float
    verification_probability: float
    base_discovery_reward: float
    saturation_budget: float


def discovery_probability(
    base_probability: float,
    budget: float,
    saturation_budget: float,
) -> float:
    return base_probability / (
        1.0 + budget / saturation_budget
    )


def evaluate_strategy(
    *,
    budget: int,
    discovery_multiplier: float,
    search_multiplier: float,
    env: Environment,
) -> dict:
    searches = budget * search_multiplier

    probability = discovery_probability(
        env.discovery_probability * discovery_multiplier,
        searches,
        env.saturation_budget,
    )

    raw_discoveries = searches * probability
    duplicates = raw_discoveries * env.duplicate_rate
    novel = max(0.0, raw_discoveries - duplicates)
    verified = novel * env.verification_probability

    revenue = verified * env.base_discovery_reward

    cost = (
        searches * env.search_cost
        + raw_discoveries * env.claim_cost
    )

    profit = revenue - cost

    roi = profit / cost if cost > 0 else 0.0

    return {
        "searches": searches,
        "raw_discoveries": raw_discoveries,
        "novel": novel,
        "verified": verified,
        "revenue": revenue,
        "cost": cost,
        "profit": profit,
        "roi": roi,
    }


def evaluate_environment(env: Environment) -> dict:
    budget = 1000

    honest = evaluate_strategy(
        budget=budget,
        discovery_multiplier=1.0,
        search_multiplier=1.0,
        env=env,
    )

    specialist = evaluate_strategy(
        budget=budget,
        discovery_multiplier=1.5,
        search_multiplier=1.0,
        env=env,
    )

    brute_force = evaluate_strategy(
        budget=budget,
        discovery_multiplier=1.0,
        search_multiplier=5.0,
        env=env,
    )

    return {
        "honest": honest,
        "specialist": specialist,
        "brute_force": brute_force,
    }


def parameter_grid():
    rewards = (5.0, 10.0, 20.0, 50.0)
    search_costs = (0.005, 0.01, 0.02)
    discovery_probabilities = (0.005, 0.01, 0.02)
    saturation_budgets = (250.0, 500.0, 1000.0, 2500.0)
    verification_rates = (0.70, 0.90, 1.00)
    duplicate_rates = (0.10, 0.20, 0.40)

    for values in product(
        rewards,
        search_costs,
        discovery_probabilities,
        saturation_budgets,
        verification_rates,
        duplicate_rates,
    ):
        (
            reward,
            search_cost,
            discovery_probability_value,
            saturation_budget,
            verification_rate,
            duplicate_rate,
        ) = values

        yield Environment(
            search_cost=search_cost,
            claim_cost=search_cost * 0.5,
            discovery_probability=discovery_probability_value,
            duplicate_rate=duplicate_rate,
            verification_probability=verification_rate,
            base_discovery_reward=reward,
            saturation_budget=saturation_budget,
        )


def main() -> None:
    total = 0
    brute_force_dominates = 0
    specialist_dominates = 0
    honest_unprofitable = 0
    attack_beats_honest = 0

    worst_case = None

    for env in parameter_grid():
        total += 1

        results = evaluate_environment(env)

        honest_profit = results["honest"]["profit"]
        specialist_profit = results["specialist"]["profit"]
        brute_profit = results["brute_force"]["profit"]

        if honest_profit <= 0:
            honest_unprofitable += 1

        if specialist_profit > honest_profit:
            specialist_dominates += 1

        if brute_profit > honest_profit:
            brute_force_dominates += 1

        attack_profit = max(
            specialist_profit,
            brute_profit,
        )

        if attack_profit >= honest_profit:
            attack_beats_honest += 1

        advantage = attack_profit - honest_profit

        if worst_case is None or advantage > worst_case["advantage"]:
            worst_case = {
                "advantage": advantage,
                "environment": env,
                "honest": results["honest"],
                "specialist": results["specialist"],
                "brute_force": results["brute_force"],
            }

    print("PoNF Parameter Sensitivity Attack v0.4")
    print()
    print(f"Parameter combinations tested: {total}")
    print(
        f"Honest strategy unprofitable: "
        f"{honest_unprofitable}/{total}"
    )
    print(
        f"Specialist beats honest: "
        f"{specialist_dominates}/{total}"
    )
    print(
        f"Brute force beats honest: "
        f"{brute_force_dominates}/{total}"
    )
    print(
        f"Attack strategy >= honest: "
        f"{attack_beats_honest}/{total}"
    )

    print()
    print("Worst observed attack advantage")

    assert worst_case is not None

    env = worst_case["environment"]

    print(
        f"reward={env.base_discovery_reward}, "
        f"search_cost={env.search_cost}, "
        f"discovery_probability={env.discovery_probability}, "
        f"saturation_budget={env.saturation_budget}, "
        f"verification={env.verification_probability}, "
        f"duplicate_rate={env.duplicate_rate}"
    )

    print(
        f"honest_profit="
        f"{worst_case['honest']['profit']:.4f}"
    )
    print(
        f"specialist_profit="
        f"{worst_case['specialist']['profit']:.4f}"
    )
    print(
        f"brute_force_profit="
        f"{worst_case['brute_force']['profit']:.4f}"
    )
    print(
        f"attack_advantage="
        f"{worst_case['advantage']:.4f}"
    )


if __name__ == "__main__":
    main()
