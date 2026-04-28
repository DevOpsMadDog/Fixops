from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AttackPathCreate")


@_attrs_define
class AttackPathCreate:
    """
    Attributes:
        tactic (str | Unset):  Default: ''.
        technique_id (str | Unset):  Default: ''.
        technique_name (str | Unset):  Default: ''.
        success (bool | Unset):  Default: False.
        detection_time_seconds (float | None | Unset):
    """

    tactic: str | Unset = ""
    technique_id: str | Unset = ""
    technique_name: str | Unset = ""
    success: bool | Unset = False
    detection_time_seconds: float | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tactic = self.tactic

        technique_id = self.technique_id

        technique_name = self.technique_name

        success = self.success

        detection_time_seconds: float | None | Unset
        if isinstance(self.detection_time_seconds, Unset):
            detection_time_seconds = UNSET
        else:
            detection_time_seconds = self.detection_time_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if tactic is not UNSET:
            field_dict["tactic"] = tactic
        if technique_id is not UNSET:
            field_dict["technique_id"] = technique_id
        if technique_name is not UNSET:
            field_dict["technique_name"] = technique_name
        if success is not UNSET:
            field_dict["success"] = success
        if detection_time_seconds is not UNSET:
            field_dict["detection_time_seconds"] = detection_time_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tactic = d.pop("tactic", UNSET)

        technique_id = d.pop("technique_id", UNSET)

        technique_name = d.pop("technique_name", UNSET)

        success = d.pop("success", UNSET)

        def _parse_detection_time_seconds(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        detection_time_seconds = _parse_detection_time_seconds(d.pop("detection_time_seconds", UNSET))

        attack_path_create = cls(
            tactic=tactic,
            technique_id=technique_id,
            technique_name=technique_name,
            success=success,
            detection_time_seconds=detection_time_seconds,
        )

        attack_path_create.additional_properties = d
        return attack_path_create

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
