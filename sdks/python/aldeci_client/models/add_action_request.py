from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddActionRequest")


@_attrs_define
class AddActionRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        action_type (str): Containment action type
        resource_id (str | Unset): Affected resource identifier Default: ''.
        description (str | Unset): Action description Default: ''.
        automated (bool | Unset): Whether action was automated Default: False.
        executed_by (str | Unset): Who executed the action Default: ''.
    """

    org_id: str
    action_type: str
    resource_id: str | Unset = ""
    description: str | Unset = ""
    automated: bool | Unset = False
    executed_by: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        action_type = self.action_type

        resource_id = self.resource_id

        description = self.description

        automated = self.automated

        executed_by = self.executed_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "action_type": action_type,
            }
        )
        if resource_id is not UNSET:
            field_dict["resource_id"] = resource_id
        if description is not UNSET:
            field_dict["description"] = description
        if automated is not UNSET:
            field_dict["automated"] = automated
        if executed_by is not UNSET:
            field_dict["executed_by"] = executed_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        action_type = d.pop("action_type")

        resource_id = d.pop("resource_id", UNSET)

        description = d.pop("description", UNSET)

        automated = d.pop("automated", UNSET)

        executed_by = d.pop("executed_by", UNSET)

        add_action_request = cls(
            org_id=org_id,
            action_type=action_type,
            resource_id=resource_id,
            description=description,
            automated=automated,
            executed_by=executed_by,
        )

        add_action_request.additional_properties = d
        return add_action_request

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
