from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="WorkflowCreate")


@_attrs_define
class WorkflowCreate:
    """
    Attributes:
        workflow_name (str):
        framework (str):
        workflow_type (str):
        owner (str | Unset):  Default: ''.
        due_date (str | Unset):  Default: ''.
    """

    workflow_name: str
    framework: str
    workflow_type: str
    owner: str | Unset = ""
    due_date: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        workflow_name = self.workflow_name

        framework = self.framework

        workflow_type = self.workflow_type

        owner = self.owner

        due_date = self.due_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "workflow_name": workflow_name,
                "framework": framework,
                "workflow_type": workflow_type,
            }
        )
        if owner is not UNSET:
            field_dict["owner"] = owner
        if due_date is not UNSET:
            field_dict["due_date"] = due_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        workflow_name = d.pop("workflow_name")

        framework = d.pop("framework")

        workflow_type = d.pop("workflow_type")

        owner = d.pop("owner", UNSET)

        due_date = d.pop("due_date", UNSET)

        workflow_create = cls(
            workflow_name=workflow_name,
            framework=framework,
            workflow_type=workflow_type,
            owner=owner,
            due_date=due_date,
        )

        workflow_create.additional_properties = d
        return workflow_create

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
