from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EnableAirGapRequest")


@_attrs_define
class EnableAirGapRequest:
    """Request body for enabling air-gap mode.

    Attributes:
        classification (None | str | Unset): Classification level: UNCLASSIFIED | CUI | SECRET | TOP SECRET/SCI
    """

    classification: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        classification: None | str | Unset
        if isinstance(self.classification, Unset):
            classification = UNSET
        else:
            classification = self.classification

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if classification is not UNSET:
            field_dict["classification"] = classification

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_classification(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        classification = _parse_classification(d.pop("classification", UNSET))

        enable_air_gap_request = cls(
            classification=classification,
        )

        enable_air_gap_request.additional_properties = d
        return enable_air_gap_request

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
