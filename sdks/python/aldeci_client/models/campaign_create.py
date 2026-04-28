from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="CampaignCreate")


@_attrs_define
class CampaignCreate:
    """
    Attributes:
        name (str):
        authorization_token (str): Required authorization token confirming written approval for this pentest
        description (str | Unset):  Default: ''.
        campaign_type (str | Unset):
            network_pentest|web_app|cloud_security|social_engineering|physical_access|full_red_team Default:
            'network_pentest'.
        target_scope (list[str] | Unset):
        attack_tactics (list[str] | Unset):
        operators_count (int | Unset):  Default: 3.
        authorized_by (str | Unset):  Default: ''.
        authorized_until (str | Unset):  Default: ''.
    """

    name: str
    authorization_token: str
    description: str | Unset = ""
    campaign_type: str | Unset = "network_pentest"
    target_scope: list[str] | Unset = UNSET
    attack_tactics: list[str] | Unset = UNSET
    operators_count: int | Unset = 3
    authorized_by: str | Unset = ""
    authorized_until: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        authorization_token = self.authorization_token

        description = self.description

        campaign_type = self.campaign_type

        target_scope: list[str] | Unset = UNSET
        if not isinstance(self.target_scope, Unset):
            target_scope = self.target_scope

        attack_tactics: list[str] | Unset = UNSET
        if not isinstance(self.attack_tactics, Unset):
            attack_tactics = self.attack_tactics

        operators_count = self.operators_count

        authorized_by = self.authorized_by

        authorized_until = self.authorized_until

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "authorization_token": authorization_token,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if campaign_type is not UNSET:
            field_dict["campaign_type"] = campaign_type
        if target_scope is not UNSET:
            field_dict["target_scope"] = target_scope
        if attack_tactics is not UNSET:
            field_dict["attack_tactics"] = attack_tactics
        if operators_count is not UNSET:
            field_dict["operators_count"] = operators_count
        if authorized_by is not UNSET:
            field_dict["authorized_by"] = authorized_by
        if authorized_until is not UNSET:
            field_dict["authorized_until"] = authorized_until

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        authorization_token = d.pop("authorization_token")

        description = d.pop("description", UNSET)

        campaign_type = d.pop("campaign_type", UNSET)

        target_scope = cast(list[str], d.pop("target_scope", UNSET))

        attack_tactics = cast(list[str], d.pop("attack_tactics", UNSET))

        operators_count = d.pop("operators_count", UNSET)

        authorized_by = d.pop("authorized_by", UNSET)

        authorized_until = d.pop("authorized_until", UNSET)

        campaign_create = cls(
            name=name,
            authorization_token=authorization_token,
            description=description,
            campaign_type=campaign_type,
            target_scope=target_scope,
            attack_tactics=attack_tactics,
            operators_count=operators_count,
            authorized_by=authorized_by,
            authorized_until=authorized_until,
        )

        campaign_create.additional_properties = d
        return campaign_create

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
