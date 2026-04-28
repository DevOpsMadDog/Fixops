from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.discover_from_findings_request_findings_item import DiscoverFromFindingsRequestFindingsItem


T = TypeVar("T", bound="DiscoverFromFindingsRequest")


@_attrs_define
class DiscoverFromFindingsRequest:
    """
    Attributes:
        findings (list[DiscoverFromFindingsRequestFindingsItem]): Pipeline findings to extract assets from
        org_id (str | Unset):  Default: 'default'.
        discovery_source (str | Unset): Source: cloud_discovery, k8s_scan, container_scan, network_scan, api_scan,
            manual Default: 'scanner'.
    """

    findings: list[DiscoverFromFindingsRequestFindingsItem]
    org_id: str | Unset = "default"
    discovery_source: str | Unset = "scanner"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        findings = []
        for findings_item_data in self.findings:
            findings_item = findings_item_data.to_dict()
            findings.append(findings_item)

        org_id = self.org_id

        discovery_source = self.discovery_source

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "findings": findings,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if discovery_source is not UNSET:
            field_dict["discovery_source"] = discovery_source

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.discover_from_findings_request_findings_item import DiscoverFromFindingsRequestFindingsItem

        d = dict(src_dict)
        findings = []
        _findings = d.pop("findings")
        for findings_item_data in _findings:
            findings_item = DiscoverFromFindingsRequestFindingsItem.from_dict(findings_item_data)

            findings.append(findings_item)

        org_id = d.pop("org_id", UNSET)

        discovery_source = d.pop("discovery_source", UNSET)

        discover_from_findings_request = cls(
            findings=findings,
            org_id=org_id,
            discovery_source=discovery_source,
        )

        discover_from_findings_request.additional_properties = d
        return discover_from_findings_request

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
