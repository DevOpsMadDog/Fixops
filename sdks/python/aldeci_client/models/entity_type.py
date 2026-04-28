from enum import Enum


class EntityType(str, Enum):
    ASSET = "asset"
    EVIDENCE = "evidence"
    FINDING = "finding"
    INCIDENT = "incident"
    REPORT = "report"
    SBOM = "sbom"
    VENDOR = "vendor"

    def __str__(self) -> str:
        return str(self.value)
