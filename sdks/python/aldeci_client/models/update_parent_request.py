from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="UpdateParentRequest")


@_attrs_define
class UpdateParentRequest:
    """
    Attributes:
        parent_org_id (None | str | Unset): New parent org PK (None = promote to root)
    """

    parent_org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        parent_org_id: None | str | Unset
        if isinstance(self.parent_org_id, Unset):
            parent_org_id = UNSET
        else:
            parent_org_id = self.parent_org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if parent_org_id is not UNSET:
            field_dict["parent_org_id"] = parent_org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_parent_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        parent_org_id = _parse_parent_org_id(d.pop("parent_org_id", UNSET))

        update_parent_request = cls(
            parent_org_id=parent_org_id,
        )

        update_parent_request.additional_properties = d
        return update_parent_request

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
