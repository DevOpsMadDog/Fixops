from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CrownJewelTagRequest")


@_attrs_define
class CrownJewelTagRequest:
    """
    Attributes:
        crown_jewel (bool | Unset):  Default: True.
        business_impact (str | Unset):  Default: 'critical'.
        justification (None | str | Unset):
        tagged_by (None | str | Unset):
    """

    crown_jewel: bool | Unset = True
    business_impact: str | Unset = "critical"
    justification: None | str | Unset = UNSET
    tagged_by: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        crown_jewel = self.crown_jewel

        business_impact = self.business_impact

        justification: None | str | Unset
        if isinstance(self.justification, Unset):
            justification = UNSET
        else:
            justification = self.justification

        tagged_by: None | str | Unset
        if isinstance(self.tagged_by, Unset):
            tagged_by = UNSET
        else:
            tagged_by = self.tagged_by

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if crown_jewel is not UNSET:
            field_dict["crown_jewel"] = crown_jewel
        if business_impact is not UNSET:
            field_dict["business_impact"] = business_impact
        if justification is not UNSET:
            field_dict["justification"] = justification
        if tagged_by is not UNSET:
            field_dict["tagged_by"] = tagged_by

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        crown_jewel = d.pop("crown_jewel", UNSET)

        business_impact = d.pop("business_impact", UNSET)

        def _parse_justification(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        justification = _parse_justification(d.pop("justification", UNSET))

        def _parse_tagged_by(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        tagged_by = _parse_tagged_by(d.pop("tagged_by", UNSET))

        crown_jewel_tag_request = cls(
            crown_jewel=crown_jewel,
            business_impact=business_impact,
            justification=justification,
            tagged_by=tagged_by,
        )

        crown_jewel_tag_request.additional_properties = d
        return crown_jewel_tag_request

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
