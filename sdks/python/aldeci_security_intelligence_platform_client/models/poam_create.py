from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="POAMCreate")


@_attrs_define
class POAMCreate:
    """
    Attributes:
        control_id (str):
        framework (str):
        title (str):
        description (str):
        responsible_party (str | Unset):  Default: 'Security Team'.
        risk_level (str | Unset): critical | high | medium | low Default: 'medium'.
        target_date (None | str | Unset):
    """

    control_id: str
    framework: str
    title: str
    description: str
    responsible_party: str | Unset = "Security Team"
    risk_level: str | Unset = "medium"
    target_date: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        control_id = self.control_id

        framework = self.framework

        title = self.title

        description = self.description

        responsible_party = self.responsible_party

        risk_level = self.risk_level

        target_date: None | str | Unset
        if isinstance(self.target_date, Unset):
            target_date = UNSET
        else:
            target_date = self.target_date

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "control_id": control_id,
                "framework": framework,
                "title": title,
                "description": description,
            }
        )
        if responsible_party is not UNSET:
            field_dict["responsible_party"] = responsible_party
        if risk_level is not UNSET:
            field_dict["risk_level"] = risk_level
        if target_date is not UNSET:
            field_dict["target_date"] = target_date

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        control_id = d.pop("control_id")

        framework = d.pop("framework")

        title = d.pop("title")

        description = d.pop("description")

        responsible_party = d.pop("responsible_party", UNSET)

        risk_level = d.pop("risk_level", UNSET)

        def _parse_target_date(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        target_date = _parse_target_date(d.pop("target_date", UNSET))

        poam_create = cls(
            control_id=control_id,
            framework=framework,
            title=title,
            description=description,
            responsible_party=responsible_party,
            risk_level=risk_level,
            target_date=target_date,
        )

        poam_create.additional_properties = d
        return poam_create

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
