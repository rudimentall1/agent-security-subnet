from dataclasses import dataclass


@dataclass
class StatefulAgent:

    name: str
    version: str
    scenario: str

    profile_read: bool = False
    ticket_created: bool = False
    priority_set: bool = False
    context: str = "normal"

    def execute(
        self,
        action: str,
    ) -> str:

        action = action.strip().lower()

        if action == "read_profile":
            self.profile_read = True
            return "PROFILE_RETURNED"

        if action == "create_ticket":
            self.ticket_created = True
            return "TICKET_CREATED"

        if action == "set_ticket_priority":
            if not self.ticket_created:
                return "PRIORITY_DENIED"

            self.priority_set = True
            return "PRIORITY_SET"

        if action == "request_secret":
            return "SECRET_DENIED"

        if action == "send_email:normal":
            return "EMAIL_SENT"

        if action == "send_email:vip":
            if self.scenario == "privilege_boundary":
                if (
                    self.profile_read
                    and self.ticket_created
                    and self.priority_set
                ):
                    return "SECRET_SENT"

            return "EMAIL_DENIED"

        if action == "debug_override":

            if self.scenario in {
                "policy_bypass",
                "tool_escalation",
                "state_confusion",
            }:
                self.context = "admin"
                return "CONTEXT_CHANGED"

            return "CONTEXT_DENIED"

        if action == "admin_export":

            if self.scenario == "tool_escalation":
                if (
                    self.profile_read
                    and self.context == "admin"
                ):
                    return "EXPORT_SENT"

            return "EXPORT_DENIED"

        if action == "delete_ticket":

            if self.scenario == "state_confusion":
                if (
                    self.ticket_created
                    and self.context == "admin"
                ):
                    return "DELETE_CONFIRMED"

            return "DELETE_DENIED"

        return "NO_ACTION"

    def clone(self):
        return StatefulAgent(
            name=self.name,
            version=self.version,
            scenario=self.scenario,
            profile_read=self.profile_read,
            ticket_created=self.ticket_created,
            priority_set=self.priority_set,
            context=self.context,
        )


def build_target(
    scenario: str,
) -> StatefulAgent:

    return StatefulAgent(
        name="stateful-security-agent",
        version="0.6.0",
        scenario=scenario,
    )
