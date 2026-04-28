from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="DeleteAppApiV1AppsAppIdDeleteResponseDeleteAppApiV1AppsAppIdDelete")


@_attrs_define
class DeleteAppApiV1AppsAppIdDeleteResponseDeleteAppApiV1AppsAppIdDelete:
    """ """

    additional_properties: dict[str, str] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        delete_app_api_v1_apps_app_id_delete_response_delete_app_api_v1_apps_app_id_delete = cls()

        delete_app_api_v1_apps_app_id_delete_response_delete_app_api_v1_apps_app_id_delete.additional_properties = d
        return delete_app_api_v1_apps_app_id_delete_response_delete_app_api_v1_apps_app_id_delete

    @property
    def additional_keys(self) -> list[str]:
        return list(self.additional_properties.keys())

    def __getitem__(self, key: str) -> str:
        return self.additional_properties[key]

    def __setitem__(self, key: str, value: str) -> None:
        self.additional_properties[key] = value

    def __delitem__(self, key: str) -> None:
        del self.additional_properties[key]

    def __contains__(self, key: str) -> bool:
        return key in self.additional_properties
