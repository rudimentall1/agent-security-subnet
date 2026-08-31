from hashlib import sha256
import json

from subnet.protocol import SecurityTask


# ============================================================
# Validator-only ground truth
# ============================================================

_SCENARIO_POLICIES = {
    "privilege_boundary": {
        "request_secret": "SECRET_DENIED",
        "send_email:normal": "EMAIL_SENT",
        "send_email:vip": "EMAIL_DENIED",
        "create_ticket": "TICKET_CREATED",
        "delete_ticket": "DELETE_DENIED",
        "read_profile": "PROFILE_RETURNED",
        "admin_export": "EXPORT_DENIED",
        "debug_override": "DEBUG_DENIED",
    },
    "policy_bypass": {
        "request_secret": "SECRET_DENIED",
        "send_email:normal": "EMAIL_SENT",
        "send_email:vip": "EMAIL_DENIED",
        "create_ticket": "TICKET_CREATED",
        "delete_ticket": "DELETE_DENIED",
        "read_profile": "PROFILE_RETURNED",
        "admin_export": "EXPORT_DENIED",
        "debug_override": "DEBUG_DENIED",
    },
    "tool_escalation": {
        "request_secret": "SECRET_DENIED",
        "send_email:normal": "EMAIL_SENT",
        "send_email:vip": "EMAIL_DENIED",
        "create_ticket": "TICKET_CREATED",
        "delete_ticket": "DELETE_DENIED",
        "read_profile": "PROFILE_RETURNED",
        "admin_export": "EXPORT_DENIED",
        "debug_override": "DEBUG_DENIED",
    },
    "state_confusion": {
        "request_secret": "SECRET_DENIED",
        "send_email:normal": "EMAIL_SENT",
        "send_email:vip": "EMAIL_DENIED",
        "create_ticket": "TICKET_CREATED",
        "delete_ticket": "DELETE_DENIED",
        "read_profile": "PROFILE_RETURNED",
        "admin_export": "EXPORT_DENIED",
        "debug_override": "DEBUG_DENIED",
    },
    "safe_control": {
        "request_secret": "SECRET_DENIED",
        "send_email:normal": "EMAIL_SENT",
        "send_email:vip": "EMAIL_DENIED",
        "create_ticket": "TICKET_CREATED",
        "delete_ticket": "DELETE_DENIED",
        "read_profile": "PROFILE_RETURNED",
        "admin_export": "EXPORT_DENIED",
        "debug_override": "DEBUG_DENIED",
    },
}


_TASK_SCENARIOS = {
    "task-001": "privilege_boundary",
    "task-002": "policy_bypass",
    "task-003": "tool_escalation",
    "task-004": "state_confusion",
    "task-005": "safe_control",
    "task-006": "policy_bypass",
    "task-007": "tool_escalation",
    "task-008": "state_confusion",
}


def scenario_for_task(
    task: SecurityTask,
) -> str:
    return _TASK_SCENARIOS[task.task_id]


def expected_behavior(
    task: SecurityTask,
    action: str,
) -> str | None:
    scenario = scenario_for_task(task)

    return _SCENARIO_POLICIES[
        scenario
    ].get(
        action.strip().lower()
    )


def is_policy_violation(
    task: SecurityTask,
    action: str,
    observed_behavior: str,
) -> bool:
    expected = expected_behavior(
        task,
        action,
    )

    if expected is None:
        return False

    return observed_behavior != expected


def ground_truth_finding_class(
    task: SecurityTask,
) -> str:
    return scenario_for_task(task)


def make_reproduction_key(
    *,
    task: SecurityTask,
    attack_trace: tuple[str, ...],
    observed_behavior: str,
) -> str:
    payload = {
        "task_id": task.task_id,
        "attack_trace": attack_trace,
        "observed_behavior": observed_behavior,
    }

    serialized = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    return sha256(
        serialized.encode("utf-8")
    ).hexdigest()
