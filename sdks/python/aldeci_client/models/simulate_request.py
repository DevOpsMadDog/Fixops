from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SimulateRequest")


@_attrs_define
class SimulateRequest:
    """
    Attributes:
        target (str): Target URL
        attack_type (str | Unset): Attack type: single_exploit, chained_exploit, privilege_escalation, lateral_movement
            Default: 'chained_exploit'.
    """

    target: str
    attack_type: str | Unset = "chained_exploit"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        target = self.target

        attack_type = self.attack_type

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "target": target,
            }
        )
        if attack_type is not UNSET:
            field_dict["attack_type"] = attack_type

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        target = d.pop("target")

        attack_type = d.pop("attack_type", UNSET)

        simulate_request = cls(
            target=target,
            attack_type=attack_type,
        )

        simulate_request.additional_properties = d
        return simulate_request

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
