from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ExposeRequest")


@_attrs_define
class ExposeRequest:
    """
    Attributes:
        secret_type (str): One of: ['api_key', 'password', 'token', 'certificate', 'ssh_key', 'database_credential',
            'oauth_secret']
        exposed_location (str): File path, URL, or commit hash where secret was found
        detection_source (str | Unset): Tool that detected the secret Default: 'scanner'.
        severity (str | Unset): critical | high | medium | low Default: 'high'.
    """

    secret_type: str
    exposed_location: str
    detection_source: str | Unset = "scanner"
    severity: str | Unset = "high"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        secret_type = self.secret_type

        exposed_location = self.exposed_location

        detection_source = self.detection_source

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "secret_type": secret_type,
                "exposed_location": exposed_location,
            }
        )
        if detection_source is not UNSET:
            field_dict["detection_source"] = detection_source
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        secret_type = d.pop("secret_type")

        exposed_location = d.pop("exposed_location")

        detection_source = d.pop("detection_source", UNSET)

        severity = d.pop("severity", UNSET)

        expose_request = cls(
            secret_type=secret_type,
            exposed_location=exposed_location,
            detection_source=detection_source,
            severity=severity,
        )

        expose_request.additional_properties = d
        return expose_request

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
