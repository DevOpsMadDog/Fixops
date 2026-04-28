from enum import Enum


class BoardColumn(str, Enum):
    BACKLOG = "backlog"
    DONE = "done"
    IN_PROGRESS = "in_progress"
    IN_REVIEW = "in_review"
    TESTING = "testing"
    TODO = "todo"

    def __str__(self) -> str:
        return str(self.value)
