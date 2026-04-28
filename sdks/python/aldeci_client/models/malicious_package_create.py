from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="MaliciousPackageCreate")


@_attrs_define
class MaliciousPackageCreate:
    """
    Attributes:
        name (str):
        ecosystem (str | Unset):  Default: 'pypi'.
        version (str | Unset):  Default: ''.
        malware_type (str | Unset):  Default: 'backdoor'.
        confidence (float | Unset):  Default: 0.8.
        reported_at (None | str | Unset):
        source (str | Unset):  Default: ''.
    """

    name: str
    ecosystem: str | Unset = "pypi"
    version: str | Unset = ""
    malware_type: str | Unset = "backdoor"
    confidence: float | Unset = 0.8
    reported_at: None | str | Unset = UNSET
    source: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        ecosystem = self.ecosystem

        version = self.version

        malware_type = self.malware_type

        confidence = self.confidence

        reported_at: None | str | Unset
        if isinstance(self.reported_at, Unset):
            reported_at = UNSET
        else:
            reported_at = self.reported_at

        source = self.source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if version is not UNSET:
            field_dict["version"] = version
        if malware_type is not UNSET:
            field_dict["malware_type"] = malware_type
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if reported_at is not UNSET:
            field_dict["reported_at"] = reported_at
        if source is not UNSET:
            field_dict["source"] = source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        ecosystem = d.pop("ecosystem", UNSET)

        version = d.pop("version", UNSET)

        malware_type = d.pop("malware_type", UNSET)

        confidence = d.pop("confidence", UNSET)

        def _parse_reported_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        reported_at = _parse_reported_at(d.pop("reported_at", UNSET))

        source = d.pop("source", UNSET)

        malicious_package_create = cls(
            name=name,
            ecosystem=ecosystem,
            version=version,
            malware_type=malware_type,
            confidence=confidence,
            reported_at=reported_at,
            source=source,
        )

        malicious_package_create.additional_properties = d
        return malicious_package_create

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
