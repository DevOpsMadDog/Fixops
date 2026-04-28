from enum import Enum


class DRTestResult(str, Enum):
    FAILED = "failed"
    NOT_TESTED = "not_tested"
    PARTIAL = "partial"
    PASSED = "passed"

    def __str__(self) -> str:
        return str(self.value)
