from enum import Enum


class ControlFamily(str, Enum):
    AC = "AC"
    AU = "AU"
    CA = "CA"
    CM = "CM"
    CP = "CP"
    IA = "IA"
    IR = "IR"
    MA = "MA"
    MP = "MP"
    PE = "PE"
    PL = "PL"
    PS = "PS"
    RA = "RA"
    SA = "SA"
    SC = "SC"
    SI = "SI"

    def __str__(self) -> str:
        return str(self.value)
