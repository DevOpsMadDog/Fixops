from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PackageStatusReq")


@_attrs_define
class PackageStatusReq:
    """
    Attributes:
        org_id (str):
        status (str):
        attack_type (None | str | Unset):
    """

    org_id: str
    status: str
    attack_type: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        status = self.status

        attack_type: None | str | Unset
        if isinstance(self.attack_type, Unset):
            attack_type = UNSET
        else:
            attack_type = self.attack_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "status": status,
            }
        )
        if attack_type is not UNSET:
            field_dict["attack_type"] = attack_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        status = d.pop("status")

        def _parse_attack_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        attack_type = _parse_attack_type(d.pop("attack_type", UNSET))

        package_status_req = cls(
            org_id=org_id,
            status=status,
            attack_type=attack_type,
        )

        package_status_req.additional_properties = d
        return package_status_req

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
