from enum import Enum


class AttackVector(str, Enum):
    ADJACENT = "adjacent"
    LOCAL = "local"
    NETWORK = "network"
    PHYSICAL = "physical"

    def __str__(self) -> str:
        return str(self.value)
