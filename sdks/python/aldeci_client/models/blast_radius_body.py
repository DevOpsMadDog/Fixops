from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="BlastRadiusBody")


@_attrs_define
class BlastRadiusBody:
    """
    Attributes:
        analysis_type (str | Unset): downstream (who breaks if I go down) or upstream (what I depend on) Default:
            'downstream'.
    """

    analysis_type: str | Unset = "downstream"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        analysis_type = self.analysis_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if analysis_type is not UNSET:
            field_dict["analysis_type"] = analysis_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        analysis_type = d.pop("analysis_type", UNSET)

        blast_radius_body = cls(
            analysis_type=analysis_type,
        )

        blast_radius_body.additional_properties = d
        return blast_radius_body

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
