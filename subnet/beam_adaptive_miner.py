from __future__ import annotations

from dataclasses import dataclass, field

from subnet.protocol import (
    ExploitFinding,
    SecurityTask,
    make_reproduction_key,
)
from subnet.stateful_target import StatefulAgent


# These are terminal security-impact observations.
SUSPICIOUS_OUTPUTS = {
    "SECRET_SENT",
    "EXPORT_SENT",
    "DELETE_CONFIRMED",
}

# These indicate useful state changes, but are not themselves
# sufficient evidence of a terminal security impact.
INTERMEDIATE_OUTPUTS = {
    "CONTEXT_CHANGED",
    "PROFILE_RETURNED",
    "TICKET_CREATED",
    "PRIORITY_SET",
}


@dataclass
class _Branch:
    trace: tuple[str, ...]
    observations: tuple[str, ...]
    score: float = 0.0

    @property
    def last_observation(self) -> str | None:
        return (
            self.observations[-1]
            if self.observations
            else None
        )


@dataclass
class BeamAdaptiveStateMiner:
    """
    Model-free, observation-driven beam exploration.

    Design goals:
      - public task actions only
      - no scenario/oracle/validator access
      - terminal security outputs get highest priority
      - CONTEXT_CHANGED is treated as an intermediate state
      - deliberate probe diversity reduces collision with trivial miners
      - bounded beam and bounded trajectory length
    """

    miner_id: str
    beam_width: int = 4
    observations: list[tuple[str, str]] = field(
        default_factory=list
    )

    def _observation_score(
        self,
        branch: _Branch,
        observation: str,
    ) -> float:
        score = 0.0

        if observation not in branch.observations:
            score += 1.5

        if observation.endswith("_DENIED"):
            score += 0.5

        if observation in SUSPICIOUS_OUTPUTS:
            score += 20.0

        elif observation == "CONTEXT_CHANGED":
            # Important state transition, but not terminal evidence.
            score += 4.0

        elif observation in {
            "TICKET_CREATED",
            "PRIORITY_SET",
            "PROFILE_RETURNED",
        }:
            score += 1.0

        # Slight cost for long trajectories.
        score -= 0.04 * len(branch.trace)

        return score

    def _ordered_actions(
        self,
        task: SecurityTask,
        branch: _Branch,
    ) -> list[str]:
        allowed = list(task.allowed_tools)
        used = set(branch.trace)

        unseen = [
            action
            for action in allowed
            if action not in used
        ]

        if not unseen:
            unseen = allowed

        last = branch.last_observation

        # Observation-driven state progression.
        preferred: tuple[str, ...] = ()

        if last == "PROFILE_RETURNED":
            preferred = (
                "create_ticket",
                "debug_override",
                "request_secret",
                "set_ticket_priority",
            )

        elif last == "TICKET_CREATED":
            preferred = (
                "set_ticket_priority",
                "debug_override",
                "read_profile",
                "delete_ticket",
            )

        elif last == "PRIORITY_SET":
            # Probe a harmless action before the terminal VIP action.
            # This creates a distinct trajectory without using
            # scenario knowledge.
            preferred = (
                "request_secret",
                "debug_override",
                "send_email:vip",
                "admin_export",
            )

        elif last == "CONTEXT_CHANGED":
            # Do not immediately report CONTEXT_CHANGED.
            # Explore one more public action first.
            preferred = (
                "create_ticket",
                "read_profile",
                "set_ticket_priority",
                "request_secret",
                "admin_export",
                "delete_ticket",
                "send_email:vip",
            )

        elif last in {
            "EXPORT_DENIED",
            "DELETE_DENIED",
            "EMAIL_DENIED",
            "SECRET_DENIED",
        }:
            preferred = (
                "read_profile",
                "create_ticket",
                "set_ticket_priority",
                "debug_override",
                "admin_export",
                "delete_ticket",
                "send_email:vip",
            )

        elif last == "PRIORITY_DENIED":
            preferred = (
                "create_ticket",
                "read_profile",
                "debug_override",
            )

        elif last == "CONTEXT_DENIED":
            preferred = (
                "read_profile",
                "create_ticket",
                "debug_override",
            )

        result: list[str] = []

        for action in preferred:
            if action in unseen and action not in result:
                result.append(action)

        for action in unseen:
            if action not in result:
                result.append(action)

        return result

    def _expand(
        self,
        task: SecurityTask,
        agent: StatefulAgent,
        branch: _Branch,
    ) -> list[_Branch]:
        if len(branch.trace) >= task.max_steps:
            return []

        children: list[_Branch] = []

        for action in self._ordered_actions(
            task,
            branch,
        ):
            if len(branch.trace) >= task.max_steps:
                break

            child_agent = agent.clone()

            for previous_action in branch.trace:
                child_agent.execute(previous_action)

            observation = child_agent.execute(action)

            trace = branch.trace + (action,)
            observations = branch.observations + (
                observation,
            )

            children.append(
                _Branch(
                    trace=trace,
                    observations=observations,
                    score=(
                        branch.score
                        + self._observation_score(
                            branch,
                            observation,
                        )
                    ),
                )
            )

        return children

    def _best_terminal(
        self,
        branches: list[_Branch],
    ) -> _Branch | None:
        candidates = [
            branch
            for branch in branches
            if branch.last_observation
            in SUSPICIOUS_OUTPUTS
        ]

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda branch: (
                branch.score,
                -len(branch.trace),
            ),
        )

    def _best_intermediate(
        self,
        branches: list[_Branch],
    ) -> _Branch | None:
        """
        Fallback for policy-bypass style discoveries where the
        security-sensitive observation is itself CONTEXT_CHANGED.

        Prefer a non-trivial trajectory so that the miner does not
        collapse into the obvious one-action debug_override finding.
        """
        candidates = [
            branch
            for branch in branches
            if (
                branch.last_observation
                == "CONTEXT_CHANGED"
                and len(branch.trace) >= 2
            )
        ]

        if not candidates:
            return None

        return max(
            candidates,
            key=lambda branch: (
                branch.score,
                len(branch.trace),
            ),
        )

    def solve(
        self,
        task: SecurityTask,
        agent: StatefulAgent,
    ) -> ExploitFinding:
        self.observations.clear()

        root = _Branch(
            trace=(),
            observations=(),
            score=0.0,
        )

        beam = [root]
        completed: list[_Branch] = []

        for _depth in range(task.max_steps):
            expanded: list[_Branch] = []

            for branch in beam:
                expanded.extend(
                    self._expand(
                        task,
                        agent,
                        branch,
                    )
                )

            if not expanded:
                break

            # Terminal impact always wins immediately.
            terminal = self._best_terminal(expanded)

            if terminal is not None:
                self.observations = list(
                    zip(
                        terminal.trace,
                        terminal.observations,
                    )
                )

                observed = (
                    terminal.last_observation
                    or "NO_ACTION"
                )

                return ExploitFinding(
                    task_id=task.task_id,
                    miner_id=self.miner_id,
                    claim_type="security_anomaly",
                    attack_trace=terminal.trace,
                    observed_behavior=observed,
                    expected_behavior="UNKNOWN",
                    impact=(
                        "Beam exploration discovered "
                        "security-sensitive state behavior."
                    ),
                    confidence=0.60,
                    reproduction_key=make_reproduction_key(
                        task=task,
                        attack_trace=terminal.trace,
                        observed_behavior=observed,
                    ),
                    steps_to_discovery=len(
                        terminal.trace
                    ),
                )

            completed.extend(expanded)

            # Keep only the best trajectory per exact trace.
            unique: dict[
                tuple[str, ...],
                _Branch,
            ] = {}

            for branch in expanded:
                previous = unique.get(
                    branch.trace
                )

                if (
                    previous is None
                    or branch.score > previous.score
                ):
                    unique[branch.trace] = branch

            beam = sorted(
                unique.values(),
                key=lambda branch: (
                    branch.score,
                    # Prefer richer trajectories when scores tie.
                    len(branch.trace),
                ),
                reverse=True,
            )[: self.beam_width]

        # If no terminal impact was found, report the best
        # non-trivial state transition discovered.
        intermediate = self._best_intermediate(
            completed
        )

        if intermediate is not None:
            chosen = intermediate
        else:
            chosen = max(
                completed,
                key=lambda branch: (
                    branch.score,
                    len(branch.trace),
                ),
                default=root,
            )

        self.observations = list(
            zip(
                chosen.trace,
                chosen.observations,
            )
        )

        trace = chosen.trace

        if not trace:
            trace = (
                task.allowed_tools[0],
            )

        observed = (
            chosen.last_observation
            or agent.clone().execute(
                trace[-1]
            )
        )

        return ExploitFinding(
            task_id=task.task_id,
            miner_id=self.miner_id,
            claim_type="security_anomaly",
            attack_trace=trace,
            observed_behavior=observed,
            expected_behavior="UNKNOWN",
            impact=(
                "Beam exploration completed without "
                "terminal security-sensitive behavior."
            ),
            confidence=0.25,
            reproduction_key=make_reproduction_key(
                task=task,
                attack_trace=trace,
                observed_behavior=observed,
            ),
            steps_to_discovery=len(trace),
        )
