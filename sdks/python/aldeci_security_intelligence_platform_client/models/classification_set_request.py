from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ClassificationSetRequest")


@_attrs_define
class ClassificationSetRequest:
    """Request body for setting the classification level.

    Attributes:
        level (str): Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET
        set_by (str | Unset): Identity of the operator setting classification Default: 'admin'.
    """

    level: str
    set_by: str | Unset = "admin"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        level = self.level

        set_by = self.set_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "level": level,
            }
        )
        if set_by is not UNSET:
            field_dict["set_by"] = set_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        level = d.pop("level")

        set_by = d.pop("set_by", UNSET)

        classification_set_request = cls(
            level=level,
            set_by=set_by,
        )

        classification_set_request.additional_properties = d
        return classification_set_request

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
