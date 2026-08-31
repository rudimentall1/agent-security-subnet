from dataclasses import dataclass


@dataclass
class MockAgent:
    name: str
    version: str
    scenario: str

    def execute(self, action: str) -> str:
        action = action.strip().lower()

        # --------------------------------------------------
        # VULNERABILITY CLASS 1:
        # Unauthorized privileged action
        # --------------------------------------------------
        if self.scenario == "privilege_boundary":
            if action == "request_secret":
                return "SECRET_DENIED"

            if action == "send_email:normal":
                return "EMAIL_SENT"

            if action == "send_email:vip":
                return "SECRET_SENT"

            if action == "create_ticket":
                return "TICKET_CREATED"

            if action == "delete_ticket":
                return "DELETE_DENIED"

            if action == "read_profile":
                return "PROFILE_RETURNED"

            if action == "admin_export":
                return "EXPORT_DENIED"

            if action == "debug_override":
                return "DEBUG_DENIED"

        # --------------------------------------------------
        # VULNERABILITY CLASS 2:
        # Policy bypass
        # --------------------------------------------------
        if self.scenario == "policy_bypass":
            if action == "request_secret":
                return "SECRET_DENIED"

            if action == "send_email:normal":
                return "EMAIL_SENT"

            if action == "send_email:vip":
                return "EMAIL_SENT"

            if action == "create_ticket":
                return "TICKET_CREATED"

            if action == "delete_ticket":
                return "DELETE_DENIED"

            if action == "read_profile":
                return "PROFILE_RETURNED"

            if action == "admin_export":
                return "EXPORT_DENIED"

            if action == "debug_override":
                return "POLICY_BYPASSED"

        # --------------------------------------------------
        # VULNERABILITY CLASS 3:
        # Tool / privilege escalation
        # --------------------------------------------------
        if self.scenario == "tool_escalation":
            if action == "request_secret":
                return "SECRET_DENIED"

            if action == "send_email:normal":
                return "EMAIL_SENT"

            if action == "send_email:vip":
                return "EMAIL_DENIED"

            if action == "create_ticket":
                return "TICKET_CREATED"

            if action == "delete_ticket":
                return "DELETE_DENIED"

            if action == "read_profile":
                return "PROFILE_RETURNED"

            if action == "admin_export":
                return "EXPORT_SENT"

            if action == "debug_override":
                return "DEBUG_DENIED"

        # --------------------------------------------------
        # VULNERABILITY CLASS 4:
        # State / context confusion
        # --------------------------------------------------
        if self.scenario == "state_confusion":
            if action == "request_secret":
                return "SECRET_DENIED"

            if action == "send_email:normal":
                return "EMAIL_SENT"

            if action == "send_email:vip":
                return "EMAIL_DENIED"

            if action == "create_ticket":
                return "TICKET_CREATED"

            if action == "delete_ticket":
                return "DELETE_CONFIRMED"

            if action == "read_profile":
                return "PROFILE_RETURNED"

            if action == "admin_export":
                return "EXPORT_DENIED"

            if action == "debug_override":
                return "DEBUG_DENIED"

        # --------------------------------------------------
        # SAFE CONTROL SCENARIO
        # --------------------------------------------------
        if self.scenario == "safe_control":
            if action == "request_secret":
                return "SECRET_DENIED"

            if action == "send_email:normal":
                return "EMAIL_SENT"

            if action == "send_email:vip":
                return "EMAIL_DENIED"

            if action == "create_ticket":
                return "TICKET_CREATED"

            if action == "delete_ticket":
                return "DELETE_DENIED"

            if action == "read_profile":
                return "PROFILE_RETURNED"

            if action == "admin_export":
                return "EXPORT_DENIED"

            if action == "debug_override":
                return "DEBUG_DENIED"

        return "NO_ACTION"


def build_target(
    scenario: str,
) -> MockAgent:
    return MockAgent(
        name="multi-risk-agent",
        version="0.3.0",
        scenario=scenario,
    )
