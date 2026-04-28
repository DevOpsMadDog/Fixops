from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.data_residency_region import DataResidencyRegion
from ..types import UNSET, Unset

T = TypeVar("T", bound="GeoRedundancyRecord")


@_attrs_define
class GeoRedundancyRecord:
    """Geographic backup location tracking for data residency compliance.

    Attributes:
        system_name (str):
        primary_location (str):
        id (str | Unset):
        backup_locations (list[str] | Unset):
        distance_km (float | None | Unset): Distance from primary to nearest backup (km)
        data_residency_region (DataResidencyRegion | Unset):
        residency_compliant (bool | Unset):  Default: False.
        required_residency (None | str | Unset):
        compliance_frameworks (list[str] | Unset):
        last_verified_at (None | str | Unset):
        notes (None | str | Unset):
        org_id (str | Unset):  Default: 'default'.
        created_at (str | Unset):
        updated_at (str | Unset):
    """

    system_name: str
    primary_location: str
    id: str | Unset = UNSET
    backup_locations: list[str] | Unset = UNSET
    distance_km: float | None | Unset = UNSET
    data_residency_region: DataResidencyRegion | Unset = UNSET
    residency_compliant: bool | Unset = False
    required_residency: None | str | Unset = UNSET
    compliance_frameworks: list[str] | Unset = UNSET
    last_verified_at: None | str | Unset = UNSET
    notes: None | str | Unset = UNSET
    org_id: str | Unset = "default"
    created_at: str | Unset = UNSET
    updated_at: str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        system_name = self.system_name

        primary_location = self.primary_location

        id = self.id

        backup_locations: list[str] | Unset = UNSET
        if not isinstance(self.backup_locations, Unset):
            backup_locations = self.backup_locations

        distance_km: float | None | Unset
        if isinstance(self.distance_km, Unset):
            distance_km = UNSET
        else:
            distance_km = self.distance_km

        data_residency_region: str | Unset = UNSET
        if not isinstance(self.data_residency_region, Unset):
            data_residency_region = self.data_residency_region.value

        residency_compliant = self.residency_compliant

        required_residency: None | str | Unset
        if isinstance(self.required_residency, Unset):
            required_residency = UNSET
        else:
            required_residency = self.required_residency

        compliance_frameworks: list[str] | Unset = UNSET
        if not isinstance(self.compliance_frameworks, Unset):
            compliance_frameworks = self.compliance_frameworks

        last_verified_at: None | str | Unset
        if isinstance(self.last_verified_at, Unset):
            last_verified_at = UNSET
        else:
            last_verified_at = self.last_verified_at

        notes: None | str | Unset
        if isinstance(self.notes, Unset):
            notes = UNSET
        else:
            notes = self.notes

        org_id = self.org_id

        created_at = self.created_at

        updated_at = self.updated_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "system_name": system_name,
                "primary_location": primary_location,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if backup_locations is not UNSET:
            field_dict["backup_locations"] = backup_locations
        if distance_km is not UNSET:
            field_dict["distance_km"] = distance_km
        if data_residency_region is not UNSET:
            field_dict["data_residency_region"] = data_residency_region
        if residency_compliant is not UNSET:
            field_dict["residency_compliant"] = residency_compliant
        if required_residency is not UNSET:
            field_dict["required_residency"] = required_residency
        if compliance_frameworks is not UNSET:
            field_dict["compliance_frameworks"] = compliance_frameworks
        if last_verified_at is not UNSET:
            field_dict["last_verified_at"] = last_verified_at
        if notes is not UNSET:
            field_dict["notes"] = notes
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if updated_at is not UNSET:
            field_dict["updated_at"] = updated_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        system_name = d.pop("system_name")

        primary_location = d.pop("primary_location")

        id = d.pop("id", UNSET)

        backup_locations = cast(list[str], d.pop("backup_locations", UNSET))

        def _parse_distance_km(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        distance_km = _parse_distance_km(d.pop("distance_km", UNSET))

        _data_residency_region = d.pop("data_residency_region", UNSET)
        data_residency_region: DataResidencyRegion | Unset
        if isinstance(_data_residency_region, Unset):
            data_residency_region = UNSET
        else:
            data_residency_region = DataResidencyRegion(_data_residency_region)

        residency_compliant = d.pop("residency_compliant", UNSET)

        def _parse_required_residency(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        required_residency = _parse_required_residency(d.pop("required_residency", UNSET))

        compliance_frameworks = cast(list[str], d.pop("compliance_frameworks", UNSET))

        def _parse_last_verified_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_verified_at = _parse_last_verified_at(d.pop("last_verified_at", UNSET))

        def _parse_notes(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        notes = _parse_notes(d.pop("notes", UNSET))

        org_id = d.pop("org_id", UNSET)

        created_at = d.pop("created_at", UNSET)

        updated_at = d.pop("updated_at", UNSET)

        geo_redundancy_record = cls(
            system_name=system_name,
            primary_location=primary_location,
            id=id,
            backup_locations=backup_locations,
            distance_km=distance_km,
            data_residency_region=data_residency_region,
            residency_compliant=residency_compliant,
            required_residency=required_residency,
            compliance_frameworks=compliance_frameworks,
            last_verified_at=last_verified_at,
            notes=notes,
            org_id=org_id,
            created_at=created_at,
            updated_at=updated_at,
        )

        geo_redundancy_record.additional_properties = d
        return geo_redundancy_record

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
