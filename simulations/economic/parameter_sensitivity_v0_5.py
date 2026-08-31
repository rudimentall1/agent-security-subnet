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

    # v0.5: economic friction against specialization
    specialization_cost: float
    detection_probability: float
    detection_penalty: float


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
    specialization_cost: float = 0.0,
    detection_probability: float = 0.0,
    detection_penalty: float = 0.0,
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

    # v0.5:
    # Specialist must pay an explicit cost.
    # Detection creates an expected economic penalty.
    expected_detection_penalty = (
        detection_probability * detection_penalty
    )

    total_cost = (
        cost
        + specialization_cost
        + expected_detection_penalty
    )

    profit = revenue - total_cost

    roi = profit / total_cost if total_cost > 0 else 0.0

    return {
        "searches": searches,
        "raw_discoveries": raw_discoveries,
        "novel": novel,
        "verified": verified,
        "revenue": revenue,
        "base_cost": cost,
        "specialization_cost": specialization_cost,
        "expected_detection_penalty": expected_detection_penalty,
        "cost": total_cost,
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
        specialization_cost=env.specialization_cost,
        detection_probability=env.detection_probability,
        detection_penalty=env.detection_penalty,
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

    # v0.5 attack-friction parameters.
    specialization_costs = (0.0, 25.0, 50.0, 100.0, 250.0, 500.0)
    detection_probabilities = (0.0, 0.05, 0.10, 0.25)
    detection_penalties = (0.0, 100.0, 250.0, 500.0)

    for values in product(
        rewards,
        search_costs,
        discovery_probabilities,
        saturation_budgets,
        verification_rates,
        duplicate_rates,
        specialization_costs,
        detection_probabilities,
        detection_penalties,
    ):
        (
            reward,
            search_cost,
            discovery_probability_value,
            saturation_budget,
            verification_rate,
            duplicate_rate,
            specialization_cost,
            detection_probability,
            detection_penalty,
        ) = values

        yield Environment(
            search_cost=search_cost,
            claim_cost=search_cost * 0.5,
            discovery_probability=discovery_probability_value,
            duplicate_rate=duplicate_rate,
            verification_probability=verification_rate,
            base_discovery_reward=reward,
            saturation_budget=saturation_budget,
            specialization_cost=specialization_cost,
            detection_probability=detection_probability,
            detection_penalty=detection_penalty,
        )


def main() -> None:
    total = 0

    specialist_dominates = 0
    brute_force_dominates = 0
    attack_beats_honest = 0
    honest_unprofitable = 0

    specialist_profitable = 0
    specialist_not_profitable = 0

    worst_specialist_advantage = None
    worst_attack_advantage = None

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

        if specialist_profit > 0:
            specialist_profitable += 1
        else:
            specialist_not_profitable += 1

        attack_profit = max(
            specialist_profit,
            brute_profit,
        )

        if attack_profit >= honest_profit:
            attack_beats_honest += 1

        specialist_advantage = (
            specialist_profit - honest_profit
        )

        attack_advantage = (
            attack_profit - honest_profit
        )

        if (
            worst_specialist_advantage is None
            or specialist_advantage
            > worst_specialist_advantage["advantage"]
        ):
            worst_specialist_advantage = {
                "advantage": specialist_advantage,
                "environment": env,
                "honest": results["honest"],
                "specialist": results["specialist"],
                "brute_force": results["brute_force"],
            }

        if (
            worst_attack_advantage is None
            or attack_advantage
            > worst_attack_advantage["advantage"]
        ):
            worst_attack_advantage = {
                "advantage": attack_advantage,
                "environment": env,
                "honest": results["honest"],
                "specialist": results["specialist"],
                "brute_force": results["brute_force"],
            }

    assert total > 0
    assert specialist_profitable + specialist_not_profitable == total
    assert worst_specialist_advantage is not None
    assert worst_attack_advantage is not None

    print("PoNF Parameter Sensitivity Attack v0.5")
    print()
    print(f"Parameter combinations tested: {total}")
    print(
        f"Honest strategy unprofitable: "
        f"{honest_unprofitable}/{total} "
        f"({100.0 * honest_unprofitable / total:.2f}%)"
    )
    print(
        f"Specialist beats honest: "
        f"{specialist_dominates}/{total} "
        f"({100.0 * specialist_dominates / total:.2f}%)"
    )
    print(
        f"Brute force beats honest: "
        f"{brute_force_dominates}/{total} "
        f"({100.0 * brute_force_dominates / total:.2f}%)"
    )
    print(
        f"Attack strategy >= honest: "
        f"{attack_beats_honest}/{total} "
        f"({100.0 * attack_beats_honest / total:.2f}%)"
    )
    print(
        f"Specialist profitable: "
        f"{specialist_profitable}/{total} "
        f"({100.0 * specialist_profitable / total:.2f}%)"
    )
    print(
        f"Specialist not profitable: "
        f"{specialist_not_profitable}/{total} "
        f"({100.0 * specialist_not_profitable / total:.2f}%)"
    )

    print()
    print("Worst observed specialist advantage")

    env = worst_specialist_advantage["environment"]

    print(
        f"reward={env.base_discovery_reward}, "
        f"search_cost={env.search_cost}, "
        f"discovery_probability={env.discovery_probability}, "
        f"saturation_budget={env.saturation_budget}, "
        f"verification={env.verification_probability}, "
        f"duplicate_rate={env.duplicate_rate}, "
        f"specialization_cost={env.specialization_cost}, "
        f"detection_probability={env.detection_probability}, "
        f"detection_penalty={env.detection_penalty}"
    )

    print(
        f"honest_profit="
        f"{worst_specialist_advantage['honest']['profit']:.4f}"
    )
    print(
        f"specialist_profit="
        f"{worst_specialist_advantage['specialist']['profit']:.4f}"
    )
    print(
        f"brute_force_profit="
        f"{worst_specialist_advantage['brute_force']['profit']:.4f}"
    )
    print(
        f"specialist_advantage="
        f"{worst_specialist_advantage['advantage']:.4f}"
    )

    print()
    print("Worst observed overall attack advantage")

    env = worst_attack_advantage["environment"]

    print(
        f"reward={env.base_discovery_reward}, "
        f"search_cost={env.search_cost}, "
        f"discovery_probability={env.discovery_probability}, "
        f"saturation_budget={env.saturation_budget}, "
        f"verification={env.verification_probability}, "
        f"duplicate_rate={env.duplicate_rate}, "
        f"specialization_cost={env.specialization_cost}, "
        f"detection_probability={env.detection_probability}, "
        f"detection_penalty={env.detection_penalty}"
    )

    print(
        f"honest_profit="
        f"{worst_attack_advantage['honest']['profit']:.4f}"
    )
    print(
        f"specialist_profit="
        f"{worst_attack_advantage['specialist']['profit']:.4f}"
    )
    print(
        f"brute_force_profit="
        f"{worst_attack_advantage['brute_force']['profit']:.4f}"
    )
    print(
        f"attack_advantage="
        f"{worst_attack_advantage['advantage']:.4f}"
    )


if __name__ == "__main__":
    main()
