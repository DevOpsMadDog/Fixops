from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.compliance_framework import ComplianceFramework

T = TypeVar("T", bound="MapFindingsRequest")


@_attrs_define
class MapFindingsRequest:
    """Request to map findings to compliance frameworks.

    Attributes:
        finding_ids (list[str]):
        frameworks (list[ComplianceFramework]):
    """

    finding_ids: list[str]
    frameworks: list[ComplianceFramework]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_ids = self.finding_ids

        frameworks = []
        for frameworks_item_data in self.frameworks:
            frameworks_item = frameworks_item_data.value
            frameworks.append(frameworks_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_ids": finding_ids,
                "frameworks": frameworks,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_ids = cast(list[str], d.pop("finding_ids"))

        frameworks = []
        _frameworks = d.pop("frameworks")
        for frameworks_item_data in _frameworks:
            frameworks_item = ComplianceFramework(frameworks_item_data)

            frameworks.append(frameworks_item)

        map_findings_request = cls(
            finding_ids=finding_ids,
            frameworks=frameworks,
        )

        map_findings_request.additional_properties = d
        return map_findings_request

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
