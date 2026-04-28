from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="ConfigureResponse")


@_attrs_define
class ConfigureResponse:
    """
    Attributes:
        success (bool):
        configured (bool):
        project_key (str):
        sync_direction (str):
        conflict_resolution (str):
    """

    success: bool
    configured: bool
    project_key: str
    sync_direction: str
    conflict_resolution: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        success = self.success

        configured = self.configured

        project_key = self.project_key

        sync_direction = self.sync_direction

        conflict_resolution = self.conflict_resolution

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "success": success,
                "configured": configured,
                "project_key": project_key,
                "sync_direction": sync_direction,
                "conflict_resolution": conflict_resolution,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        success = d.pop("success")

        configured = d.pop("configured")

        project_key = d.pop("project_key")

        sync_direction = d.pop("sync_direction")

        conflict_resolution = d.pop("conflict_resolution")

        configure_response = cls(
            success=success,
            configured=configured,
            project_key=project_key,
            sync_direction=sync_direction,
            conflict_resolution=conflict_resolution,
        )

        configure_response.additional_properties = d
        return configure_response

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
