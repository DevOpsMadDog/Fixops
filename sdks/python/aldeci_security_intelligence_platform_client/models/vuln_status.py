from enum import Enum


class VulnStatus(str, Enum):
    CVE_ASSIGNED = "cve_assigned"
    CVE_REQUESTED = "cve_requested"
    DISPUTED = "disputed"
    DRAFT = "draft"
    INTERNAL = "internal"
    PUBLIC = "public"
    REPORTED_VENDOR = "reported_vendor"

    def __str__(self) -> str:
        return str(self.value)
