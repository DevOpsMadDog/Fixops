from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GradeRequest")


@_attrs_define
class GradeRequest:
    """Request to grade a drill's team response.

    Override fields allow manual override of auto-computed timings
    (e.g. when detection was reported verbally before the system was updated).

        Attributes:
            override_detection_minutes (int | None | Unset): Override auto-computed detection time (minutes from injection)
            override_remediation_minutes (int | None | Unset): Override auto-computed remediation time (minutes from
                injection)
    """

    override_detection_minutes: int | None | Unset = UNSET
    override_remediation_minutes: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        override_detection_minutes: int | None | Unset
        if isinstance(self.override_detection_minutes, Unset):
            override_detection_minutes = UNSET
        else:
            override_detection_minutes = self.override_detection_minutes

        override_remediation_minutes: int | None | Unset
        if isinstance(self.override_remediation_minutes, Unset):
            override_remediation_minutes = UNSET
        else:
            override_remediation_minutes = self.override_remediation_minutes

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if override_detection_minutes is not UNSET:
            field_dict["override_detection_minutes"] = override_detection_minutes
        if override_remediation_minutes is not UNSET:
            field_dict["override_remediation_minutes"] = override_remediation_minutes

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_override_detection_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        override_detection_minutes = _parse_override_detection_minutes(d.pop("override_detection_minutes", UNSET))

        def _parse_override_remediation_minutes(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        override_remediation_minutes = _parse_override_remediation_minutes(d.pop("override_remediation_minutes", UNSET))

        grade_request = cls(
            override_detection_minutes=override_detection_minutes,
            override_remediation_minutes=override_remediation_minutes,
        )

        grade_request.additional_properties = d
        return grade_request

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
