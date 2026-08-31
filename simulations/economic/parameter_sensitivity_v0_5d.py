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

    return {
        "revenue": revenue,
        "cost": cost,
        "profit": profit,
    }


def make_environments():
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


def calculate_threshold(
    detection_probability: float,
    detection_penalty: float,
):
    max_unpenalized_advantage = None
    max_case = None

    total = 0

    for env in make_environments():
        total += 1

        honest = evaluate_strategy(
            budget=1000,
            discovery_multiplier=1.0,
            search_multiplier=1.0,
            env=env,
        )

        specialist = evaluate_strategy(
            budget=1000,
            discovery_multiplier=1.5,
            search_multiplier=1.0,
            env=env,
        )

        raw_advantage = (
            specialist["profit"]
            - honest["profit"]
        )

        if (
            max_unpenalized_advantage is None
            or raw_advantage > max_unpenalized_advantage
        ):
            max_unpenalized_advantage = raw_advantage

            max_case = {
                "environment": env,
                "honest": honest,
                "specialist": specialist,
                "raw_advantage": raw_advantage,
            }

    expected_detection_penalty = (
        detection_probability * detection_penalty
    )

    # Total fixed economic friction required to remove
    # Specialist's advantage in every tested environment.
    exact_threshold = (
        max_unpenalized_advantage
        - expected_detection_penalty
    )

    return {
        "total": total,
        "max_unpenalized_advantage": max_unpenalized_advantage,
        "expected_detection_penalty": expected_detection_penalty,
        "exact_threshold": max(0.0, exact_threshold),
        "max_case": max_case,
    }


def verify_threshold(
    specialization_cost: float,
    detection_probability: float,
    detection_penalty: float,
):
    specialist_beats = 0
    total = 0

    for env in make_environments():
        total += 1

        honest = evaluate_strategy(
            budget=1000,
            discovery_multiplier=1.0,
            search_multiplier=1.0,
            env=env,
        )

        specialist = evaluate_strategy(
            budget=1000,
            discovery_multiplier=1.5,
            search_multiplier=1.0,
            env=env,
        )

        specialist_profit = (
            specialist["profit"]
            - specialization_cost
            - detection_probability * detection_penalty
        )

        if specialist_profit > honest["profit"]:
            specialist_beats += 1

    return specialist_beats, total


def main():
    detection_probability = 0.25
    detection_penalty = 250.0

    result = calculate_threshold(
        detection_probability=detection_probability,
        detection_penalty=detection_penalty,
    )

    threshold = result["exact_threshold"]

    print("PoNF Parameter Sensitivity Attack v0.5d")
    print("=" * 50)
    print()
    print(f"Parameter combinations tested: {result['total']}")
    print(f"Detection probability: {detection_probability}")
    print(f"Detection penalty: {detection_penalty}")
    print(
        "Expected detection penalty: "
        f"{result['expected_detection_penalty']:.6f}"
    )
    print()
    print(
        "Maximum unpenalized Specialist advantage: "
        f"{result['max_unpenalized_advantage']:.6f}"
    )
    print(
        "Exact specialization-cost threshold: "
        f"{threshold:.6f}"
    )

    case = result["max_case"]

    print()
    print("Worst-case environment before friction")
    print("-" * 50)

    env = case["environment"]

    print(
        f"reward={env.base_discovery_reward}, "
        f"search_cost={env.search_cost}, "
        f"discovery_probability="
        f"{env.discovery_probability}, "
        f"saturation_budget="
        f"{env.saturation_budget}, "
        f"verification="
        f"{env.verification_probability}, "
        f"duplicate_rate="
        f"{env.duplicate_rate}"
    )

    print(
        f"honest_profit="
        f"{case['honest']['profit']:.6f}"
    )

    print(
        f"specialist_profit_before_friction="
        f"{case['specialist']['profit']:.6f}"
    )

    print(
        f"raw_advantage="
        f"{case['raw_advantage']:.6f}"
    )

    print()
    print("Boundary verification")
    print("-" * 50)

    # Verify slightly below, at, and slightly above threshold.
    epsilon = 0.001

    below = max(0.0, threshold - epsilon)
    at = threshold
    above = threshold + epsilon

    for label, cost in (
        ("below", below),
        ("at", at),
        ("above", above),
    ):
        wins, total = verify_threshold(
            specialization_cost=cost,
            detection_probability=detection_probability,
            detection_penalty=detection_penalty,
        )

        print(
            f"{label:>5}: "
            f"cost={cost:.6f}, "
            f"Specialist>Honest={wins}/{total}"
        )

    print()
    print("Interpretation")
    print("-" * 50)

    print(
        "The reported threshold is the minimum fixed "
        "specialization cost, after accounting for the "
        "expected detection penalty, required to eliminate "
        "Specialist dominance across the tested parameter grid."
    )

    print()
    print("v0.5d completed successfully.")


if __name__ == "__main__":
    main()
