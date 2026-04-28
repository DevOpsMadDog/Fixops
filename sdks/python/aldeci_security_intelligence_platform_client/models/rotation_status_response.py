from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="RotationStatusResponse")


@_attrs_define
class RotationStatusResponse:
    """Response for /rotation-status endpoint.

    Attributes:
        org_id (str):
        total (int):
        active (int):
        rotated (int):
        false_positive (int):
        rotation_rate (float):
    """

    org_id: str
    total: int
    active: int
    rotated: int
    false_positive: int
    rotation_rate: float
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        total = self.total

        active = self.active

        rotated = self.rotated

        false_positive = self.false_positive

        rotation_rate = self.rotation_rate

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "total": total,
                "active": active,
                "rotated": rotated,
                "false_positive": false_positive,
                "rotation_rate": rotation_rate,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        total = d.pop("total")

        active = d.pop("active")

        rotated = d.pop("rotated")

        false_positive = d.pop("false_positive")

        rotation_rate = d.pop("rotation_rate")

        rotation_status_response = cls(
            org_id=org_id,
            total=total,
            active=active,
            rotated=rotated,
            false_positive=false_positive,
            rotation_rate=rotation_rate,
        )

        rotation_status_response.additional_properties = d
        return rotation_status_response

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
