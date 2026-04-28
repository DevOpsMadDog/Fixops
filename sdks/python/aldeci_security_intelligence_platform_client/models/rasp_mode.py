from enum import Enum


class RaspMode(str, Enum):
    BLOCK = "block"
    MONITOR = "monitor"
    REDIRECT = "redirect"

    def __str__(self) -> str:
        return str(self.value)
