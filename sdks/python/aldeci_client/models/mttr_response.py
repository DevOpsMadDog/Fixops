from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MTTRResponse")


@_attrs_define
class MTTRResponse:
    """
    Attributes:
        org_id (str):
        mttr_seconds (float):
        mttr_minutes (float):
    """

    org_id: str
    mttr_seconds: float
    mttr_minutes: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        mttr_seconds = self.mttr_seconds

        mttr_minutes = self.mttr_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "mttr_seconds": mttr_seconds,
                "mttr_minutes": mttr_minutes,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        mttr_seconds = d.pop("mttr_seconds")

        mttr_minutes = d.pop("mttr_minutes")

        mttr_response = cls(
            org_id=org_id,
            mttr_seconds=mttr_seconds,
            mttr_minutes=mttr_minutes,
        )

        mttr_response.additional_properties = d
        return mttr_response

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
