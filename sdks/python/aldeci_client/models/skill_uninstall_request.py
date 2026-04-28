from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SkillUninstallRequest")


@_attrs_define
class SkillUninstallRequest:
    """
    Attributes:
        skill_id (str):
        purge_data (bool | Unset): Delete cached skill data on disk Default: False.
    """

    skill_id: str
    purge_data: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        skill_id = self.skill_id

        purge_data = self.purge_data

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "skill_id": skill_id,
            }
        )
        if purge_data is not UNSET:
            field_dict["purge_data"] = purge_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        skill_id = d.pop("skill_id")

        purge_data = d.pop("purge_data", UNSET)

        skill_uninstall_request = cls(
            skill_id=skill_id,
            purge_data=purge_data,
        )

        skill_uninstall_request.additional_properties = d
        return skill_uninstall_request

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
