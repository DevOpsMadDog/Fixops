from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CreateIncidentRequest")


@_attrs_define
class CreateIncidentRequest:
    """
    Attributes:
        org_id (str): Organisation identifier
        incident_name (str): Descriptive incident name
        incident_type (str): Type of cloud incident
        cloud_provider (str | Unset): Cloud provider Default: 'aws'.
        severity (str | Unset): Severity: critical/high/medium/low Default: 'medium'.
        affected_services (list[str] | None | Unset): List of affected services
        affected_regions (list[str] | None | Unset): List of affected regions
    """

    org_id: str
    incident_name: str
    incident_type: str
    cloud_provider: str | Unset = "aws"
    severity: str | Unset = "medium"
    affected_services: list[str] | None | Unset = UNSET
    affected_regions: list[str] | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        incident_name = self.incident_name

        incident_type = self.incident_type

        cloud_provider = self.cloud_provider

        severity = self.severity

        affected_services: list[str] | None | Unset
        if isinstance(self.affected_services, Unset):
            affected_services = UNSET
        elif isinstance(self.affected_services, list):
            affected_services = self.affected_services

        else:
            affected_services = self.affected_services

        affected_regions: list[str] | None | Unset
        if isinstance(self.affected_regions, Unset):
            affected_regions = UNSET
        elif isinstance(self.affected_regions, list):
            affected_regions = self.affected_regions

        else:
            affected_regions = self.affected_regions

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "incident_name": incident_name,
                "incident_type": incident_type,
            }
        )
        if cloud_provider is not UNSET:
            field_dict["cloud_provider"] = cloud_provider
        if severity is not UNSET:
            field_dict["severity"] = severity
        if affected_services is not UNSET:
            field_dict["affected_services"] = affected_services
        if affected_regions is not UNSET:
            field_dict["affected_regions"] = affected_regions

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        incident_name = d.pop("incident_name")

        incident_type = d.pop("incident_type")

        cloud_provider = d.pop("cloud_provider", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_affected_services(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                affected_services_type_0 = cast(list[str], data)

                return affected_services_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        affected_services = _parse_affected_services(d.pop("affected_services", UNSET))

        def _parse_affected_regions(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                affected_regions_type_0 = cast(list[str], data)

                return affected_regions_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        affected_regions = _parse_affected_regions(d.pop("affected_regions", UNSET))

        create_incident_request = cls(
            org_id=org_id,
            incident_name=incident_name,
            incident_type=incident_type,
            cloud_provider=cloud_provider,
            severity=severity,
            affected_services=affected_services,
            affected_regions=affected_regions,
        )

        create_incident_request.additional_properties = d
        return create_incident_request

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
