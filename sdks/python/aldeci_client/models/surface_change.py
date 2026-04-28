from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.change_type import ChangeType
from ..models.risk_tier import RiskTier
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.surface_change_details import SurfaceChangeDetails


T = TypeVar("T", bound="SurfaceChange")


@_attrs_define
class SurfaceChange:
    """A detected change in the attack surface.

    Attributes:
        change_type (ChangeType):
        asset_id (str):
        asset_name (str):
        description (str):
        id (str | Unset):
        org_id (str | Unset):  Default: 'default'.
        severity (RiskTier | Unset):
        detected_at (str | Unset):
        details (SurfaceChangeDetails | Unset):
    """

    change_type: ChangeType
    asset_id: str
    asset_name: str
    description: str
    id: str | Unset = UNSET
    org_id: str | Unset = "default"
    severity: RiskTier | Unset = UNSET
    detected_at: str | Unset = UNSET
    details: SurfaceChangeDetails | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        change_type = self.change_type.value

        asset_id = self.asset_id

        asset_name = self.asset_name

        description = self.description

        id = self.id

        org_id = self.org_id

        severity: str | Unset = UNSET
        if not isinstance(self.severity, Unset):
            severity = self.severity.value

        detected_at = self.detected_at

        details: dict[str, Any] | Unset = UNSET
        if not isinstance(self.details, Unset):
            details = self.details.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "change_type": change_type,
                "asset_id": asset_id,
                "asset_name": asset_name,
                "description": description,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if severity is not UNSET:
            field_dict["severity"] = severity
        if detected_at is not UNSET:
            field_dict["detected_at"] = detected_at
        if details is not UNSET:
            field_dict["details"] = details

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.surface_change_details import SurfaceChangeDetails

        d = dict(src_dict)
        change_type = ChangeType(d.pop("change_type"))

        asset_id = d.pop("asset_id")

        asset_name = d.pop("asset_name")

        description = d.pop("description")

        id = d.pop("id", UNSET)

        org_id = d.pop("org_id", UNSET)

        _severity = d.pop("severity", UNSET)
        severity: RiskTier | Unset
        if isinstance(_severity, Unset):
            severity = UNSET
        else:
            severity = RiskTier(_severity)

        detected_at = d.pop("detected_at", UNSET)

        _details = d.pop("details", UNSET)
        details: SurfaceChangeDetails | Unset
        if isinstance(_details, Unset):
            details = UNSET
        else:
            details = SurfaceChangeDetails.from_dict(_details)

        surface_change = cls(
            change_type=change_type,
            asset_id=asset_id,
            asset_name=asset_name,
            description=description,
            id=id,
            org_id=org_id,
            severity=severity,
            detected_at=detected_at,
            details=details,
        )

        surface_change.additional_properties = d
        return surface_change

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
