from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestIndicatorRequest")


@_attrs_define
class IngestIndicatorRequest:
    """
    Attributes:
        value (str):
        source_id (str | Unset):  Default: ''.
        indicator_type (str | Unset):  Default: 'ip'.
        confidence (int | Unset):  Default: 50.
        tags (list[str] | Unset):
        expiry_days (int | Unset):  Default: 30.
    """

    value: str
    source_id: str | Unset = ""
    indicator_type: str | Unset = "ip"
    confidence: int | Unset = 50
    tags: list[str] | Unset = UNSET
    expiry_days: int | Unset = 30
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        value = self.value

        source_id = self.source_id

        indicator_type = self.indicator_type

        confidence = self.confidence

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        expiry_days = self.expiry_days

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "value": value,
            }
        )
        if source_id is not UNSET:
            field_dict["source_id"] = source_id
        if indicator_type is not UNSET:
            field_dict["indicator_type"] = indicator_type
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if tags is not UNSET:
            field_dict["tags"] = tags
        if expiry_days is not UNSET:
            field_dict["expiry_days"] = expiry_days

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        value = d.pop("value")

        source_id = d.pop("source_id", UNSET)

        indicator_type = d.pop("indicator_type", UNSET)

        confidence = d.pop("confidence", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        expiry_days = d.pop("expiry_days", UNSET)

        ingest_indicator_request = cls(
            value=value,
            source_id=source_id,
            indicator_type=indicator_type,
            confidence=confidence,
            tags=tags,
            expiry_days=expiry_days,
        )

        ingest_indicator_request.additional_properties = d
        return ingest_indicator_request

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
