from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FrameworkCreate")


@_attrs_define
class FrameworkCreate:
    """
    Attributes:
        name (str): Framework name, e.g. SOC2, ISO27001
        version (str | Unset): Framework version Default: '1.0'.
        total_controls (int | Unset):  Default: 0.
        implemented_controls (int | Unset):  Default: 0.
        compliance_score (float | Unset):  Default: 0.0.
        last_assessed (None | str | Unset):
    """

    name: str
    version: str | Unset = "1.0"
    total_controls: int | Unset = 0
    implemented_controls: int | Unset = 0
    compliance_score: float | Unset = 0.0
    last_assessed: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        version = self.version

        total_controls = self.total_controls

        implemented_controls = self.implemented_controls

        compliance_score = self.compliance_score

        last_assessed: None | str | Unset
        if isinstance(self.last_assessed, Unset):
            last_assessed = UNSET
        else:
            last_assessed = self.last_assessed

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if version is not UNSET:
            field_dict["version"] = version
        if total_controls is not UNSET:
            field_dict["total_controls"] = total_controls
        if implemented_controls is not UNSET:
            field_dict["implemented_controls"] = implemented_controls
        if compliance_score is not UNSET:
            field_dict["compliance_score"] = compliance_score
        if last_assessed is not UNSET:
            field_dict["last_assessed"] = last_assessed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        version = d.pop("version", UNSET)

        total_controls = d.pop("total_controls", UNSET)

        implemented_controls = d.pop("implemented_controls", UNSET)

        compliance_score = d.pop("compliance_score", UNSET)

        def _parse_last_assessed(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_assessed = _parse_last_assessed(d.pop("last_assessed", UNSET))

        framework_create = cls(
            name=name,
            version=version,
            total_controls=total_controls,
            implemented_controls=implemented_controls,
            compliance_score=compliance_score,
            last_assessed=last_assessed,
        )

        framework_create.additional_properties = d
        return framework_create

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
