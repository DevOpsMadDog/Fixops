from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="OperatorCreate")


@_attrs_define
class OperatorCreate:
    """
    Attributes:
        name (str):
        specialization (str | Unset):  Default: 'network'.
        certifications (str | Unset):  Default: ''.
        active_engagement_id (None | str | Unset):
    """

    name: str
    specialization: str | Unset = "network"
    certifications: str | Unset = ""
    active_engagement_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        specialization = self.specialization

        certifications = self.certifications

        active_engagement_id: None | str | Unset
        if isinstance(self.active_engagement_id, Unset):
            active_engagement_id = UNSET
        else:
            active_engagement_id = self.active_engagement_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if specialization is not UNSET:
            field_dict["specialization"] = specialization
        if certifications is not UNSET:
            field_dict["certifications"] = certifications
        if active_engagement_id is not UNSET:
            field_dict["active_engagement_id"] = active_engagement_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        specialization = d.pop("specialization", UNSET)

        certifications = d.pop("certifications", UNSET)

        def _parse_active_engagement_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        active_engagement_id = _parse_active_engagement_id(d.pop("active_engagement_id", UNSET))

        operator_create = cls(
            name=name,
            specialization=specialization,
            certifications=certifications,
            active_engagement_id=active_engagement_id,
        )

        operator_create.additional_properties = d
        return operator_create

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
