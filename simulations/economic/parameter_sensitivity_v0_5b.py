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

    roi = profit / total_cost if total_cost > 0 else 0.0

    return {
        "revenue": revenue,
        "base_cost": base_cost,
        "specialization_cost": specialization_cost,
        "expected_detection_penalty": expected_detection_penalty,
        "cost": total_cost,
        "profit": profit,
        "roi": roi,
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

        yield (
            reward,
            search_cost,
            discovery_probability_value,
            saturation_budget,
            verification_rate,
            duplicate_rate,
        )


def evaluate_case(
    *,
    specialization_cost: float,
    detection_probability: float,
    detection_penalty: float,
):
    total = 0
    specialist_beats = 0
    specialist_profitable = 0

    min_margin = None
    max_margin = None

    for values in make_base_environments():
        (
            reward,
            search_cost,
            discovery_probability_value,
            saturation_budget,
            verification_rate,
            duplicate_rate,
        ) = values

        env = Environment(
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

        margin = specialist["profit"] - honest["profit"]

        if margin > 0:
            specialist_beats += 1

        if specialist["profit"] > 0:
            specialist_profitable += 1

        if min_margin is None or margin < min_margin:
            min_margin = margin

        if max_margin is None or margin > max_margin:
            max_margin = margin

    return {
        "total": total,
        "specialist_beats": specialist_beats,
        "specialist_profitable": specialist_profitable,
        "min_margin": min_margin,
        "max_margin": max_margin,
    }


def print_cost_sweep():
    costs = (0.0, 25.0, 50.0, 100.0, 250.0, 500.0)

    print("Specialization cost sweep")
    print()
    print(
        "cost".ljust(12)
        + "specialist>honest".ljust(22)
        + "specialist profitable"
    )
    print("-" * 58)

    for cost in costs:
        result = evaluate_case(
            specialization_cost=cost,
            detection_probability=0.0,
            detection_penalty=0.0,
        )

        print(
            f"{cost:<12.1f}"
            f"{result['specialist_beats']}/{result['total']}"
            f" ({100.0 * result['specialist_beats'] / result['total']:.1f}%)"
            .ljust(22)
            + f"{result['specialist_profitable']}/{result['total']}"
            f" ({100.0 * result['specialist_profitable'] / result['total']:.1f}%)"
        )


def print_detection_sweep():
    probabilities = (0.0, 0.05, 0.10, 0.25)
    penalty = 250.0

    print()
    print("Detection probability sweep")
    print(f"Fixed detection penalty: {penalty}")
    print()
    print(
        "probability".ljust(15)
        + "specialist>honest".ljust(22)
        + "specialist profitable"
    )
    print("-" * 62)

    for probability in probabilities:
        result = evaluate_case(
            specialization_cost=100.0,
            detection_probability=probability,
            detection_penalty=penalty,
        )

        print(
            f"{probability:<15.2f}"
            f"{result['specialist_beats']}/{result['total']}"
            f" ({100.0 * result['specialist_beats'] / result['total']:.1f}%)"
            .ljust(22)
            + f"{result['specialist_profitable']}/{result['total']}"
            f" ({100.0 * result['specialist_profitable'] / result['total']:.1f}%)"
        )


def print_combined_sweep():
    costs = (0.0, 25.0, 50.0, 100.0, 250.0, 500.0)
    probabilities = (0.0, 0.05, 0.10, 0.25)
    penalty = 250.0

    print()
    print("Combined specialization + detection sweep")
    print(f"Detection penalty: {penalty}")
    print()

    for probability in probabilities:
        print(f"Detection probability = {probability:.2f}")

        for cost in costs:
            result = evaluate_case(
                specialization_cost=cost,
                detection_probability=probability,
                detection_penalty=penalty,
            )

            rate = (
                100.0
                * result["specialist_beats"]
                / result["total"]
            )

            print(
                f"  cost={cost:6.1f}  "
                f"specialist>honest="
                f"{result['specialist_beats']:4d}/"
                f"{result['total']} "
                f"({rate:5.1f}%)"
            )

        print()


def main():
    print("PoNF Parameter Sensitivity Attack v0.5b")
    print("=" * 46)
    print()

    print_cost_sweep()
    print_detection_sweep()
    print_combined_sweep()

    print()
    print("v0.5b completed successfully.")


if __name__ == "__main__":
    main()
