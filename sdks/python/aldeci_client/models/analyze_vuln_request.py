from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AnalyzeVulnRequest")


@_attrs_define
class AnalyzeVulnRequest:
    """Request for vulnerability analysis.

    Attributes:
        cve_id (None | str | Unset):
        finding_id (None | str | Unset):
        description (None | str | Unset):
        include_threat_intel (bool | Unset):  Default: True.
        include_epss (bool | Unset):  Default: True.
        include_kev (bool | Unset):  Default: True.
    """

    cve_id: None | str | Unset = UNSET
    finding_id: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    include_threat_intel: bool | Unset = True
    include_epss: bool | Unset = True
    include_kev: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        finding_id: None | str | Unset
        if isinstance(self.finding_id, Unset):
            finding_id = UNSET
        else:
            finding_id = self.finding_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        include_threat_intel = self.include_threat_intel

        include_epss = self.include_epss

        include_kev = self.include_kev

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if description is not UNSET:
            field_dict["description"] = description
        if include_threat_intel is not UNSET:
            field_dict["include_threat_intel"] = include_threat_intel
        if include_epss is not UNSET:
            field_dict["include_epss"] = include_epss
        if include_kev is not UNSET:
            field_dict["include_kev"] = include_kev

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_finding_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_id = _parse_finding_id(d.pop("finding_id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        include_threat_intel = d.pop("include_threat_intel", UNSET)

        include_epss = d.pop("include_epss", UNSET)

        include_kev = d.pop("include_kev", UNSET)

        analyze_vuln_request = cls(
            cve_id=cve_id,
            finding_id=finding_id,
            description=description,
            include_threat_intel=include_threat_intel,
            include_epss=include_epss,
            include_kev=include_kev,
        )

        analyze_vuln_request.additional_properties = d
        return analyze_vuln_request

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
