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

    base_cost = (
        searches * env.search_cost
        + raw_discoveries * env.claim_cost
    )

    expected_detection_penalty = (
        detection_probability * detection_penalty
    )

    total_cost = (
        base_cost
        + specialization_cost
        + expected_detection_penalty
    )

    profit = revenue - total_cost

    return {
        "revenue": revenue,
        "base_cost": base_cost,
        "specialization_cost": specialization_cost,
        "expected_detection_penalty": expected_detection_penalty,
        "cost": total_cost,
        "profit": profit,
        "roi": (
            profit / total_cost
            if total_cost > 0
            else 0.0
        ),
    }


def make_base_environments():
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


def evaluate_cost(
    specialization_cost: float,
    detection_probability: float,
    detection_penalty: float,
):
    total = 0
    specialist_beats = 0
    max_advantage = None
    max_case = None

    for env in make_base_environments():
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
            specialization_cost=specialization_cost,
            detection_probability=detection_probability,
            detection_penalty=detection_penalty,
        )

        total += 1

        advantage = (
            specialist["profit"]
            - honest["profit"]
        )

        if advantage > 0:
            specialist_beats += 1

        if max_advantage is None or advantage > max_advantage:
            max_advantage = advantage
            max_case = {
                "environment": env,
                "honest": honest,
                "specialist": specialist,
                "advantage": advantage,
            }

    return {
        "total": total,
        "specialist_beats": specialist_beats,
        "max_advantage": max_advantage,
        "max_case": max_case,
    }


def main():
    detection_probability = 0.25
    detection_penalty = 250.0

    # Fine-grained threshold search.
    costs = range(200, 501, 5)

    results = []

    print("PoNF Parameter Sensitivity Attack v0.5c")
    print("=" * 48)
    print()
    print(
        f"Detection probability: {detection_probability}"
    )
    print(
        f"Detection penalty: {detection_penalty}"
    )
    print()

    print(
        "cost".ljust(10)
        + "specialist>honest".ljust(24)
        + "max advantage"
    )
    print("-" * 60)

    for cost in costs:
        result = evaluate_cost(
            specialization_cost=float(cost),
            detection_probability=detection_probability,
            detection_penalty=detection_penalty,
        )

        results.append(
            (cost, result)
        )

        rate = (
            100.0
            * result["specialist_beats"]
            / result["total"]
        )

        print(
            f"{cost:<10d}"
            f"{result['specialist_beats']:4d}/"
            f"{result['total']} "
            f"({rate:5.2f}%)"
            .ljust(24)
            + f"{result['max_advantage']: .4f}"
        )

    still_positive = [
        (cost, result)
        for cost, result in results
        if result["specialist_beats"] > 0
    ]

    zero_cases = [
        (cost, result)
        for cost, result in results
        if result["specialist_beats"] == 0
    ]

    print()
    print("Threshold analysis")
    print("-" * 60)

    if still_positive:
        last_positive_cost, last_positive = still_positive[-1]

        print(
            "Highest tested cost with at least one "
            "Specialist win: "
            f"{last_positive_cost}"
        )
        print(
            "Remaining winning environments: "
            f"{last_positive['specialist_beats']}/"
            f"{last_positive['total']}"
        )
    else:
        print(
            "No Specialist wins found in the tested range."
        )

    if zero_cases:
        first_zero_cost, first_zero = zero_cases[0]

        print(
            "Lowest tested cost with zero Specialist wins: "
            f"{first_zero_cost}"
        )
        print(
            "Specialist wins at that cost: "
            f"{first_zero['specialist_beats']}/"
            f"{first_zero['total']}"
        )
    else:
        print(
            "No zero-win threshold found in the tested range."
        )

    print()
    print("Critical boundary")
    print("-" * 60)

    if still_positive and zero_cases:
        lower = still_positive[-1][0]
        upper = zero_cases[0][0]

        print(
            f"Threshold lies between {lower} and {upper}."
        )
        print(
            "The exact continuous threshold can be derived "
            "from the maximum Specialist advantage."
        )

    # Report the strongest surviving Specialist case
    surviving = [
        (cost, result)
        for cost, result in results
        if result["max_case"] is not None
        and result["max_case"]["advantage"] > 0
    ]

    if surviving:
        cost, result = max(
            surviving,
            key=lambda item: item[1]["max_case"]["advantage"],
        )

        case = result["max_case"]
        env = case["environment"]

        print()
        print("Strongest surviving Specialist case")
        print("-" * 60)
        print(f"specialization_cost={cost}")
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
            f"{case['honest']['profit']:.4f}"
        )
        print(
            f"specialist_profit="
            f"{case['specialist']['profit']:.4f}"
        )
        print(
            f"specialist_advantage="
            f"{case['advantage']:.4f}"
        )

    print()
    print("v0.5c completed successfully.")


if __name__ == "__main__":
    main()
