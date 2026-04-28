from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PackageCreateReq")


@_attrs_define
class PackageCreateReq:
    """
    Attributes:
        org_id (str):
        package_name (str):
        ecosystem (str | Unset):  Default: 'npm'.
        version (None | str | Unset):
        source_url (None | str | Unset):
        risk_score (float | Unset):  Default: 0.0.
        attack_type (str | Unset):  Default: 'none'.
        last_scanned (None | str | Unset):
    """

    org_id: str
    package_name: str
    ecosystem: str | Unset = "npm"
    version: None | str | Unset = UNSET
    source_url: None | str | Unset = UNSET
    risk_score: float | Unset = 0.0
    attack_type: str | Unset = "none"
    last_scanned: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        package_name = self.package_name

        ecosystem = self.ecosystem

        version: None | str | Unset
        if isinstance(self.version, Unset):
            version = UNSET
        else:
            version = self.version

        source_url: None | str | Unset
        if isinstance(self.source_url, Unset):
            source_url = UNSET
        else:
            source_url = self.source_url

        risk_score = self.risk_score

        attack_type = self.attack_type

        last_scanned: None | str | Unset
        if isinstance(self.last_scanned, Unset):
            last_scanned = UNSET
        else:
            last_scanned = self.last_scanned

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "package_name": package_name,
            }
        )
        if ecosystem is not UNSET:
            field_dict["ecosystem"] = ecosystem
        if version is not UNSET:
            field_dict["version"] = version
        if source_url is not UNSET:
            field_dict["source_url"] = source_url
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score
        if attack_type is not UNSET:
            field_dict["attack_type"] = attack_type
        if last_scanned is not UNSET:
            field_dict["last_scanned"] = last_scanned

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        package_name = d.pop("package_name")

        ecosystem = d.pop("ecosystem", UNSET)

        def _parse_version(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        version = _parse_version(d.pop("version", UNSET))

        def _parse_source_url(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_url = _parse_source_url(d.pop("source_url", UNSET))

        risk_score = d.pop("risk_score", UNSET)

        attack_type = d.pop("attack_type", UNSET)

        def _parse_last_scanned(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_scanned = _parse_last_scanned(d.pop("last_scanned", UNSET))

        package_create_req = cls(
            org_id=org_id,
            package_name=package_name,
            ecosystem=ecosystem,
            version=version,
            source_url=source_url,
            risk_score=risk_score,
            attack_type=attack_type,
            last_scanned=last_scanned,
        )

        package_create_req.additional_properties = d
        return package_create_req

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
