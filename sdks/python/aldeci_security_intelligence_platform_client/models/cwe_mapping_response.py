from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="CWEMappingResponse")


@_attrs_define
class CWEMappingResponse:
    """Response for CWE→CVE mapping lookup.

    Attributes:
        cwe_id (str): Normalized CWE ID (e.g. CWE-89)
        cves (list[str]): Known CVE IDs associated with this CWE
        count (int): Number of matched CVEs
    """

    cwe_id: str
    cves: list[str]
    count: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cwe_id = self.cwe_id

        cves = self.cves

        count = self.count

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "cwe_id": cwe_id,
                "cves": cves,
                "count": count,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cwe_id = d.pop("cwe_id")

        cves = cast(list[str], d.pop("cves"))

        count = d.pop("count")

        cwe_mapping_response = cls(
            cwe_id=cwe_id,
            cves=cves,
            count=count,
        )

        cwe_mapping_response.additional_properties = d
        return cwe_mapping_response

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
