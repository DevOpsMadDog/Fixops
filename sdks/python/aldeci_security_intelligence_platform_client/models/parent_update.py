from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ParentUpdate")


@_attrs_define
class ParentUpdate:
    """
    Attributes:
        new_parent_id (None | str | Unset): New parent surrogate id (None to promote to root)
    """

    new_parent_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_parent_id: None | str | Unset
        if isinstance(self.new_parent_id, Unset):
            new_parent_id = UNSET
        else:
            new_parent_id = self.new_parent_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if new_parent_id is not UNSET:
            field_dict["new_parent_id"] = new_parent_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_new_parent_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        new_parent_id = _parse_new_parent_id(d.pop("new_parent_id", UNSET))

        parent_update = cls(
            new_parent_id=new_parent_id,
        )

        parent_update.additional_properties = d
        return parent_update

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
