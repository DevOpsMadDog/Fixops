from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyCreate")


@_attrs_define
class PolicyCreate:
    """
    Attributes:
        policy_name (str):
        policy_type (str):
        scope (str | Unset):  Default: ''.
    """

    policy_name: str
    policy_type: str
    scope: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_name = self.policy_name

        policy_type = self.policy_type

        scope = self.scope

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_name": policy_name,
                "policy_type": policy_type,
            }
        )
        if scope is not UNSET:
            field_dict["scope"] = scope

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_name = d.pop("policy_name")

        policy_type = d.pop("policy_type")

        scope = d.pop("scope", UNSET)

        policy_create = cls(
            policy_name=policy_name,
            policy_type=policy_type,
            scope=scope,
        )

        policy_create.additional_properties = d
        return policy_create

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
