from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.condition_operator import ConditionOperator

T = TypeVar("T", bound="WorkflowConditionRequest")


@_attrs_define
class WorkflowConditionRequest:
    """
    Attributes:
        field (str):
        operator (ConditionOperator):
        value (Any):
    """

    field: str
    operator: ConditionOperator
    value: Any
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        field = self.field

        operator = self.operator.value

        value = self.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "field": field,
                "operator": operator,
                "value": value,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        field = d.pop("field")

        operator = ConditionOperator(d.pop("operator"))

        value = d.pop("value")

        workflow_condition_request = cls(
            field=field,
            operator=operator,
            value=value,
        )

        workflow_condition_request.additional_properties = d
        return workflow_condition_request

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
