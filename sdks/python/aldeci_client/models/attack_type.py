from enum import Enum


class AttackType(str, Enum):
    DEPENDENCY_CONFUSION = "dependency_confusion"
    MALICIOUS_VERSION_BUMP = "malicious_version_bump"
    NAMESPACE_HIJACK = "namespace_hijack"
    TYPOSQUATTING = "typosquatting"

    def __str__(self) -> str:
        return str(self.value)
