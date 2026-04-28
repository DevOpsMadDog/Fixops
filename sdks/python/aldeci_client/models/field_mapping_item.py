from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FieldMappingItem")


@_attrs_define
class FieldMappingItem:
    """
    Attributes:
        finding_field (str): Field name in the ALDECI finding dict
        jira_field (str): Field name in the Jira issue fields dict
        transform (None | str | Unset): Optional transform key
    """

    finding_field: str
    jira_field: str
    transform: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_field = self.finding_field

        jira_field = self.jira_field

        transform: None | str | Unset
        if isinstance(self.transform, Unset):
            transform = UNSET
        else:
            transform = self.transform

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_field": finding_field,
                "jira_field": jira_field,
            }
        )
        if transform is not UNSET:
            field_dict["transform"] = transform

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_field = d.pop("finding_field")

        jira_field = d.pop("jira_field")

        def _parse_transform(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        transform = _parse_transform(d.pop("transform", UNSET))

        field_mapping_item = cls(
            finding_field=finding_field,
            jira_field=jira_field,
            transform=transform,
        )

        field_mapping_item.additional_properties = d
        return field_mapping_item

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
