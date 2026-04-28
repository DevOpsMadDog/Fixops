from enum import Enum


class KillChainPhase(str, Enum):
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"
    COMMAND_AND_CONTROL = "command_and_control"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"

    def __str__(self) -> str:
        return str(self.value)
