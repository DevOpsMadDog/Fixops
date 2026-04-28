from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="IngestVulnRequest")


@_attrs_define
class IngestVulnRequest:
    """
    Attributes:
        ecosystem (str): npm|pypi|maven
        package_name (str): Package name (maven uses group/artifact)
        version (str): Affected version
        cve_id (str): CVE identifier
        fixed_in (str): Version where fix is available
    """

    ecosystem: str
    package_name: str
    version: str
    cve_id: str
    fixed_in: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ecosystem = self.ecosystem

        package_name = self.package_name

        version = self.version

        cve_id = self.cve_id

        fixed_in = self.fixed_in

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ecosystem": ecosystem,
                "package_name": package_name,
                "version": version,
                "cve_id": cve_id,
                "fixed_in": fixed_in,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ecosystem = d.pop("ecosystem")

        package_name = d.pop("package_name")

        version = d.pop("version")

        cve_id = d.pop("cve_id")

        fixed_in = d.pop("fixed_in")

        ingest_vuln_request = cls(
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            cve_id=cve_id,
            fixed_in=fixed_in,
        )

        ingest_vuln_request.additional_properties = d
        return ingest_vuln_request

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
