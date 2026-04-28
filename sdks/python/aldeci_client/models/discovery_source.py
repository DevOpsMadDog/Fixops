from enum import Enum


class DiscoverySource(str, Enum):
    BUG_BOUNTY = "bug_bounty"
    CODE_REVIEW = "code_review"
    FUZZING = "fuzzing"
    PENTEST_AUTOMATED = "pentest_automated"
    PENTEST_MANUAL = "pentest_manual"
    RESEARCH = "research"

    def __str__(self) -> str:
        return str(self.value)
