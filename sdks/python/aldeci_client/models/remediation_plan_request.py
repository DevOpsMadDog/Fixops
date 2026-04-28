from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.remediation_plan_request_vulnerability_data import RemediationPlanRequestVulnerabilityData


T = TypeVar("T", bound="RemediationPlanRequest")


@_attrs_define
class RemediationPlanRequest:
    """
    Attributes:
        vulnerability_data (RemediationPlanRequestVulnerabilityData | Unset): Vulnerability details: cve_id, name,
            severity, affected_component, cvss_score, etc.
    """

    vulnerability_data: RemediationPlanRequestVulnerabilityData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        vulnerability_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.vulnerability_data, Unset):
            vulnerability_data = self.vulnerability_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if vulnerability_data is not UNSET:
            field_dict["vulnerability_data"] = vulnerability_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.remediation_plan_request_vulnerability_data import RemediationPlanRequestVulnerabilityData

        d = dict(src_dict)
        _vulnerability_data = d.pop("vulnerability_data", UNSET)
        vulnerability_data: RemediationPlanRequestVulnerabilityData | Unset
        if isinstance(_vulnerability_data, Unset):
            vulnerability_data = UNSET
        else:
            vulnerability_data = RemediationPlanRequestVulnerabilityData.from_dict(_vulnerability_data)

        remediation_plan_request = cls(
            vulnerability_data=vulnerability_data,
        )

        remediation_plan_request.additional_properties = d
        return remediation_plan_request

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
