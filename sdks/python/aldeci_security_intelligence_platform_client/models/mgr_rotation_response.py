from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="MgrRotationResponse")


@_attrs_define
class MgrRotationResponse:
    """
    Attributes:
        finding_id (str):
        category (str):
        rotation_steps (list[str]):
        rotation_script (str):
        estimated_downtime_minutes (int):
        requires_service_restart (bool):
        vault_path (None | str):
        status (str):
        created_at (str):
    """

    finding_id: str
    category: str
    rotation_steps: list[str]
    rotation_script: str
    estimated_downtime_minutes: int
    requires_service_restart: bool
    vault_path: None | str
    status: str
    created_at: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        category = self.category

        rotation_steps = self.rotation_steps

        rotation_script = self.rotation_script

        estimated_downtime_minutes = self.estimated_downtime_minutes

        requires_service_restart = self.requires_service_restart

        vault_path: None | str
        vault_path = self.vault_path

        status = self.status

        created_at = self.created_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "category": category,
                "rotation_steps": rotation_steps,
                "rotation_script": rotation_script,
                "estimated_downtime_minutes": estimated_downtime_minutes,
                "requires_service_restart": requires_service_restart,
                "vault_path": vault_path,
                "status": status,
                "created_at": created_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        category = d.pop("category")

        rotation_steps = cast(list[str], d.pop("rotation_steps"))

        rotation_script = d.pop("rotation_script")

        estimated_downtime_minutes = d.pop("estimated_downtime_minutes")

        requires_service_restart = d.pop("requires_service_restart")

        def _parse_vault_path(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        vault_path = _parse_vault_path(d.pop("vault_path"))

        status = d.pop("status")

        created_at = d.pop("created_at")

        mgr_rotation_response = cls(
            finding_id=finding_id,
            category=category,
            rotation_steps=rotation_steps,
            rotation_script=rotation_script,
            estimated_downtime_minutes=estimated_downtime_minutes,
            requires_service_restart=requires_service_restart,
            vault_path=vault_path,
            status=status,
            created_at=created_at,
        )

        mgr_rotation_response.additional_properties = d
        return mgr_rotation_response

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
