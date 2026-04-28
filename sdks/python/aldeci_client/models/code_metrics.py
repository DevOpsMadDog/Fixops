from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CodeMetrics")


@_attrs_define
class CodeMetrics:
    """Code quality metrics.

    Attributes:
        lines_of_code (int):
        lines_of_comments (int):
        blank_lines (int):
        cyclomatic_complexity (int):
        cognitive_complexity (int):
        maintainability_index (float):
        function_count (int):
        class_count (int):
        import_count (int):
        max_nesting_depth (int):
    """

    lines_of_code: int
    lines_of_comments: int
    blank_lines: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    maintainability_index: float
    function_count: int
    class_count: int
    import_count: int
    max_nesting_depth: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        lines_of_code = self.lines_of_code

        lines_of_comments = self.lines_of_comments

        blank_lines = self.blank_lines

        cyclomatic_complexity = self.cyclomatic_complexity

        cognitive_complexity = self.cognitive_complexity

        maintainability_index = self.maintainability_index

        function_count = self.function_count

        class_count = self.class_count

        import_count = self.import_count

        max_nesting_depth = self.max_nesting_depth

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "lines_of_code": lines_of_code,
                "lines_of_comments": lines_of_comments,
                "blank_lines": blank_lines,
                "cyclomatic_complexity": cyclomatic_complexity,
                "cognitive_complexity": cognitive_complexity,
                "maintainability_index": maintainability_index,
                "function_count": function_count,
                "class_count": class_count,
                "import_count": import_count,
                "max_nesting_depth": max_nesting_depth,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        lines_of_code = d.pop("lines_of_code")

        lines_of_comments = d.pop("lines_of_comments")

        blank_lines = d.pop("blank_lines")

        cyclomatic_complexity = d.pop("cyclomatic_complexity")

        cognitive_complexity = d.pop("cognitive_complexity")

        maintainability_index = d.pop("maintainability_index")

        function_count = d.pop("function_count")

        class_count = d.pop("class_count")

        import_count = d.pop("import_count")

        max_nesting_depth = d.pop("max_nesting_depth")

        code_metrics = cls(
            lines_of_code=lines_of_code,
            lines_of_comments=lines_of_comments,
            blank_lines=blank_lines,
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=cognitive_complexity,
            maintainability_index=maintainability_index,
            function_count=function_count,
            class_count=class_count,
            import_count=import_count,
            max_nesting_depth=max_nesting_depth,
        )

        code_metrics.additional_properties = d
        return code_metrics

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> Any:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
