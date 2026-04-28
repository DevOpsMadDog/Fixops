from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="AssignOwnerRequest")


@_attrs_define
class AssignOwnerRequest:
    """
    Attributes:
        owner_email (str):
        owner_name (None | str | Unset):
        team (None | str | Unset):
        business_unit (None | str | Unset):
        cost_center (None | str | Unset):
    """

    owner_email: str
    owner_name: None | str | Unset = UNSET
    team: None | str | Unset = UNSET
    business_unit: None | str | Unset = UNSET
    cost_center: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        owner_email = self.owner_email

        owner_name: None | str | Unset
        if isinstance(self.owner_name, Unset):
            owner_name = UNSET
        else:
            owner_name = self.owner_name

        team: None | str | Unset
        if isinstance(self.team, Unset):
            team = UNSET
        else:
            team = self.team

        business_unit: None | str | Unset
        if isinstance(self.business_unit, Unset):
            business_unit = UNSET
        else:
            business_unit = self.business_unit

        cost_center: None | str | Unset
        if isinstance(self.cost_center, Unset):
            cost_center = UNSET
        else:
            cost_center = self.cost_center

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "owner_email": owner_email,
            }
        )
        if owner_name is not UNSET:
            field_dict["owner_name"] = owner_name
        if team is not UNSET:
            field_dict["team"] = team
        if business_unit is not UNSET:
            field_dict["business_unit"] = business_unit
        if cost_center is not UNSET:
            field_dict["cost_center"] = cost_center

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        owner_email = d.pop("owner_email")

        def _parse_owner_name(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        owner_name = _parse_owner_name(d.pop("owner_name", UNSET))

        def _parse_team(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        team = _parse_team(d.pop("team", UNSET))

        def _parse_business_unit(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        business_unit = _parse_business_unit(d.pop("business_unit", UNSET))

        def _parse_cost_center(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cost_center = _parse_cost_center(d.pop("cost_center", UNSET))

        assign_owner_request = cls(
            owner_email=owner_email,
            owner_name=owner_name,
            team=team,
            business_unit=business_unit,
            cost_center=cost_center,
        )

        assign_owner_request.additional_properties = d
        return assign_owner_request

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
