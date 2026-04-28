from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.incident_analysis_request_incident_data import IncidentAnalysisRequestIncidentData


T = TypeVar("T", bound="IncidentAnalysisRequest")


@_attrs_define
class IncidentAnalysisRequest:
    """
    Attributes:
        incident_data (IncidentAnalysisRequestIncidentData | Unset): Incident details: type, affected_systems, timeline,
            initial_iocs, severity, etc.
    """

    incident_data: IncidentAnalysisRequestIncidentData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        incident_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.incident_data, Unset):
            incident_data = self.incident_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if incident_data is not UNSET:
            field_dict["incident_data"] = incident_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.incident_analysis_request_incident_data import IncidentAnalysisRequestIncidentData

        d = dict(src_dict)
        _incident_data = d.pop("incident_data", UNSET)
        incident_data: IncidentAnalysisRequestIncidentData | Unset
        if isinstance(_incident_data, Unset):
            incident_data = UNSET
        else:
            incident_data = IncidentAnalysisRequestIncidentData.from_dict(_incident_data)

        incident_analysis_request = cls(
            incident_data=incident_data,
        )

        incident_analysis_request.additional_properties = d
        return incident_analysis_request

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
