from enum import Enum


class RelationshipType(str, Enum):
    BACKS_UP_TO = "backs_up_to"
    CONNECTS_TO = "connects_to"
    DEPENDS_ON = "depends_on"
    DEPLOYED_IN = "deployed_in"
    EXPOSED_BY = "exposed_by"
    HOSTED_ON = "hosted_on"
    MANAGED_BY = "managed_by"
    OWNED_BY = "owned_by"
    REPLICATES_TO = "replicates_to"
    RUNS_ON = "runs_on"

    def __str__(self) -> str:
        return str(self.value)
