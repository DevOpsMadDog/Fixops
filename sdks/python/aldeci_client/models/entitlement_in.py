from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="EntitlementIn")


@_attrs_define
class EntitlementIn:
    """
    Attributes:
        identity_id (str):
        identity_name (str | Unset):  Default: ''.
        identity_type (str | Unset):  Default: 'user'.
        entitlement (str | Unset):  Default: ''.
        system (str | Unset):  Default: ''.
        granted_date (str | Unset):  Default: ''.
        last_used (None | str | Unset):
        is_orphaned (bool | Unset):  Default: False.
        is_excessive (bool | Unset):  Default: False.
        risk_score (float | Unset):  Default: 0.0.
    """

    identity_id: str
    identity_name: str | Unset = ""
    identity_type: str | Unset = "user"
    entitlement: str | Unset = ""
    system: str | Unset = ""
    granted_date: str | Unset = ""
    last_used: None | str | Unset = UNSET
    is_orphaned: bool | Unset = False
    is_excessive: bool | Unset = False
    risk_score: float | Unset = 0.0
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        identity_id = self.identity_id

        identity_name = self.identity_name

        identity_type = self.identity_type

        entitlement = self.entitlement

        system = self.system

        granted_date = self.granted_date

        last_used: None | str | Unset
        if isinstance(self.last_used, Unset):
            last_used = UNSET
        else:
            last_used = self.last_used

        is_orphaned = self.is_orphaned

        is_excessive = self.is_excessive

        risk_score = self.risk_score

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "identity_id": identity_id,
            }
        )
        if identity_name is not UNSET:
            field_dict["identity_name"] = identity_name
        if identity_type is not UNSET:
            field_dict["identity_type"] = identity_type
        if entitlement is not UNSET:
            field_dict["entitlement"] = entitlement
        if system is not UNSET:
            field_dict["system"] = system
        if granted_date is not UNSET:
            field_dict["granted_date"] = granted_date
        if last_used is not UNSET:
            field_dict["last_used"] = last_used
        if is_orphaned is not UNSET:
            field_dict["is_orphaned"] = is_orphaned
        if is_excessive is not UNSET:
            field_dict["is_excessive"] = is_excessive
        if risk_score is not UNSET:
            field_dict["risk_score"] = risk_score

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        identity_id = d.pop("identity_id")

        identity_name = d.pop("identity_name", UNSET)

        identity_type = d.pop("identity_type", UNSET)

        entitlement = d.pop("entitlement", UNSET)

        system = d.pop("system", UNSET)

        granted_date = d.pop("granted_date", UNSET)

        def _parse_last_used(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        last_used = _parse_last_used(d.pop("last_used", UNSET))

        is_orphaned = d.pop("is_orphaned", UNSET)

        is_excessive = d.pop("is_excessive", UNSET)

        risk_score = d.pop("risk_score", UNSET)

        entitlement_in = cls(
            identity_id=identity_id,
            identity_name=identity_name,
            identity_type=identity_type,
            entitlement=entitlement,
            system=system,
            granted_date=granted_date,
            last_used=last_used,
            is_orphaned=is_orphaned,
            is_excessive=is_excessive,
            risk_score=risk_score,
        )

        entitlement_in.additional_properties = d
        return entitlement_in

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
