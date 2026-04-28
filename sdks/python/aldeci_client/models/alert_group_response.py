from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.alert_group import AlertGroup


T = TypeVar("T", bound="AlertGroupResponse")


@_attrs_define
class AlertGroupResponse:
    """
    Attributes:
        group_count (int):
        groups (list[AlertGroup]):
    """

    group_count: int
    groups: list[AlertGroup]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        group_count = self.group_count

        groups = []
        for groups_item_data in self.groups:
            groups_item = groups_item_data.to_dict()
            groups.append(groups_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "group_count": group_count,
                "groups": groups,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.alert_group import AlertGroup

        d = dict(src_dict)
        group_count = d.pop("group_count")

        groups = []
        _groups = d.pop("groups")
        for groups_item_data in _groups:
            groups_item = AlertGroup.from_dict(groups_item_data)

            groups.append(groups_item)

        alert_group_response = cls(
            group_count=group_count,
            groups=groups,
        )

        alert_group_response.additional_properties = d
        return alert_group_response

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
