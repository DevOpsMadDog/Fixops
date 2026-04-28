from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ScannerStatusResponse")


@_attrs_define
class ScannerStatusResponse:
    """Response model for scanner status.

    Attributes:
        checkov_available (bool):
        tfsec_available (bool):
        available_scanners (list[str]):
    """

    checkov_available: bool
    tfsec_available: bool
    available_scanners: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        checkov_available = self.checkov_available

        tfsec_available = self.tfsec_available

        available_scanners = self.available_scanners

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "checkov_available": checkov_available,
                "tfsec_available": tfsec_available,
                "available_scanners": available_scanners,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        checkov_available = d.pop("checkov_available")

        tfsec_available = d.pop("tfsec_available")

        available_scanners = cast(list[str], d.pop("available_scanners"))

        scanner_status_response = cls(
            checkov_available=checkov_available,
            tfsec_available=tfsec_available,
            available_scanners=available_scanners,
        )

        scanner_status_response.additional_properties = d
        return scanner_status_response

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
