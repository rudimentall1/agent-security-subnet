from dataclasses import replace
from hashlib import sha256

from subnet.protocol import SecurityTask


BASE_ACTIONS = (
    "request_secret",
    "send_email:normal",
    "send_email:vip",
    "create_ticket",
    "delete_ticket",
    "read_profile",
    "admin_export",
    "debug_override",
)


def deterministic_seed(
    text: str,
) -> int:
    digest = sha256(
        text.encode("utf-8")
    ).digest()

    return int.from_bytes(
        digest[:8],
        "big",
    )


def deterministic_permutation(
    values: tuple[str, ...],
    seed: int,
) -> tuple[str, ...]:

    items = list(values)
    state = seed

    for index in range(
        len(items) - 1,
        0,
        -1,
    ):
        state = (
            state * 6364136223846793005
            + 1442695040888963407
        ) & ((1 << 64) - 1)

        swap_index = state % (index + 1)

        items[index], items[swap_index] = (
            items[swap_index],
            items[index],
        )

    return tuple(items)


def mutation_decoys(
    mutation_id: int,
) -> tuple[str, ...]:

    decoy_sets = (
        (
            "request_secret",
            "read_profile",
        ),
        (
            "create_ticket",
            "send_email:normal",
        ),
        (
            "read_profile",
            "delete_ticket",
        ),
        (
            "send_email:normal",
            "create_ticket",
        ),
        (
            "request_secret",
            "debug_override",
        ),
        (
            "read_profile",
            "admin_export",
        ),
    )

    return decoy_sets[
        mutation_id % len(decoy_sets)
    ]


def mutate_task(
    task: SecurityTask,
    mutation_id: int,
) -> SecurityTask:

    seed = deterministic_seed(
        f"{task.task_id}:{mutation_id}"
    )

    ordered = deterministic_permutation(
        BASE_ACTIONS,
        seed,
    )

    decoys = mutation_decoys(
        mutation_id
    )

    merged = list(ordered)

    for decoy in decoys:
        if decoy not in merged:
            merged.append(decoy)

    mutated_tools = tuple(
        merged[: len(BASE_ACTIONS)]
    )

    return replace(
        task,
        task_id=(
            f"{task.task_id}-m{mutation_id:02d}"
        ),
        parent_task_id=task.task_id,
        allowed_tools=mutated_tools,
    )


def generate_mutation_family(
    base_task: SecurityTask,
    count: int = 6,
) -> tuple[SecurityTask, ...]:

    return tuple(
        mutate_task(
            base_task,
            mutation_id,
        )
        for mutation_id in range(count)
    )
