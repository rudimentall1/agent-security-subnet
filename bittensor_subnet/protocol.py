from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SecurityTaskRequest(BaseModel):
    """
    Public task sent from validator to miner.

    Ground truth and oracle state are deliberately absent.
    """

    task_id: str
    target_name: str
    target_version: str
    objective: str
    max_steps: int = Field(default=6, ge=1)
    allowed_tools: list[str] = Field(default_factory=list)


class FindingResponse(BaseModel):
    """
    Miner response.

    This contains only the finding produced by the miner.
    Validator-only fields are not part of the network response.
    """

    task_id: str
    miner_id: str
    claim_type: str
    attack_trace: list[str]
    observed_behavior: str
    impact: str
    confidence: float
    reproduction_key: str
    steps_to_discovery: int


class SecurityResponse(BaseModel):
    """
    HTTP response returned by the miner.
    """

    finding: FindingResponse | None = None
    error: str | None = None


def task_to_dict(task: SecurityTaskRequest) -> dict[str, Any]:
    return task.model_dump()


def finding_to_dict(finding: FindingResponse) -> dict[str, Any]:
    return finding.model_dump()
