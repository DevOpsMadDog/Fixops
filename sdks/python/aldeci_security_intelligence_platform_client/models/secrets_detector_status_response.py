from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SecretsDetectorStatusResponse")


@_attrs_define
class SecretsDetectorStatusResponse:
    """Response model for detector status.

    Attributes:
        gitleaks_available (bool):
        trufflehog_available (bool):
        available_scanners (list[str]):
    """

    gitleaks_available: bool
    trufflehog_available: bool
    available_scanners: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        gitleaks_available = self.gitleaks_available

        trufflehog_available = self.trufflehog_available

        available_scanners = self.available_scanners

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "gitleaks_available": gitleaks_available,
                "trufflehog_available": trufflehog_available,
                "available_scanners": available_scanners,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        gitleaks_available = d.pop("gitleaks_available")

        trufflehog_available = d.pop("trufflehog_available")

        available_scanners = cast(list[str], d.pop("available_scanners"))

        secrets_detector_status_response = cls(
            gitleaks_available=gitleaks_available,
            trufflehog_available=trufflehog_available,
            available_scanners=available_scanners,
        )

        secrets_detector_status_response.additional_properties = d
        return secrets_detector_status_response

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
