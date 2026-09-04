from bittensor_subnet.protocol import FindingResponse
from bittensor_subnet.validator import response_to_finding


def test_network_response_cannot_supply_oracle_state():
    response = FindingResponse(
        task_id="state-001",
        miner_id="miner-1",
        claim_type="security_anomaly",
        attack_trace=("read_profile", "create_ticket", "set_ticket_priority", "send_email:vip"),
        observed_behavior="SECRET_SENT",
        impact="privilege escalation",
        confidence=0.95,
        reproduction_key="k1",
        steps_to_discovery=4,
    )

    finding = response_to_finding(response)

    assert finding.expected_behavior == ""
    assert finding.observed_behavior == "SECRET_SENT"
    assert finding.attack_trace[-1] == "send_email:vip"


def test_validator_reconstructs_internal_finding_types():
    response = FindingResponse(
        task_id="state-002",
        miner_id="miner-2",
        claim_type="security_anomaly",
        attack_trace=["debug_override", "admin_export"],
        observed_behavior="EXPORT_SENT",
        impact="tool escalation",
        confidence=0.8,
        reproduction_key="k2",
        steps_to_discovery=2,
    )

    finding = response_to_finding(response)

    assert isinstance(finding.attack_trace, tuple)
    assert finding.task_id == response.task_id
    assert finding.miner_id == response.miner_id
