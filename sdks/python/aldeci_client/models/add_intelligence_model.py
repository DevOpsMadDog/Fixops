from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AddIntelligenceModel")


@_attrs_define
class AddIntelligenceModel:
    """
    Attributes:
        intel_type (str):
        content (str):
        confidence (float | Unset):  Default: 0.5.
        source (str | Unset):  Default: ''.
        valid_until (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    intel_type: str
    content: str
    confidence: float | Unset = 0.5
    source: str | Unset = ""
    valid_until: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        intel_type = self.intel_type

        content = self.content

        confidence = self.confidence

        source = self.source

        valid_until: None | str | Unset
        if isinstance(self.valid_until, Unset):
            valid_until = UNSET
        else:
            valid_until = self.valid_until

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "intel_type": intel_type,
                "content": content,
            }
        )
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if source is not UNSET:
            field_dict["source"] = source
        if valid_until is not UNSET:
            field_dict["valid_until"] = valid_until
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        intel_type = d.pop("intel_type")

        content = d.pop("content")

        confidence = d.pop("confidence", UNSET)

        source = d.pop("source", UNSET)

        def _parse_valid_until(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        valid_until = _parse_valid_until(d.pop("valid_until", UNSET))

        org_id = d.pop("org_id", UNSET)

        add_intelligence_model = cls(
            intel_type=intel_type,
            content=content,
            confidence=confidence,
            source=source,
            valid_until=valid_until,
            org_id=org_id,
        )

        add_intelligence_model.additional_properties = d
        return add_intelligence_model

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
