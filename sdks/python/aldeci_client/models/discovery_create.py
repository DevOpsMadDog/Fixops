from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="DiscoveryCreate")


@_attrs_define
class DiscoveryCreate:
    """
    Attributes:
        data_type (str):
        record_count (int | Unset):  Default: 0.
        sample_path (str | Unset):  Default: ''.
        confidence (int | Unset):  Default: 80.
        risk_level (str | Unset):  Default: 'low'.
        is_classified (bool | Unset):  Default: False.
    """

    data_type: str
    record_count: int | Unset = 0
    sample_path: str | Unset = ""
    confidence: int | Unset = 80
    risk_level: str | Unset = "low"
    is_classified: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data_type = self.data_type

        record_count = self.record_count

        sample_path = self.sample_path

        confidence = self.confidence

        risk_level = self.risk_level

        is_classified = self.is_classified

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "data_type": data_type,
            }
        )
        if record_count is not UNSET:
            field_dict["record_count"] = record_count
        if sample_path is not UNSET:
            field_dict["sample_path"] = sample_path
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if is_classified is not UNSET:
            field_dict["is_classified"] = is_classified

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        data_type = d.pop("data_type")

        record_count = d.pop("record_count", UNSET)

        sample_path = d.pop("sample_path", UNSET)

        confidence = d.pop("confidence", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        is_classified = d.pop("is_classified", UNSET)

        discovery_create = cls(
            data_type=data_type,
            record_count=record_count,
            sample_path=sample_path,
            confidence=confidence,
            risk_level=risk_level,
            is_classified=is_classified,
        )

        discovery_create.additional_properties = d
        return discovery_create

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
