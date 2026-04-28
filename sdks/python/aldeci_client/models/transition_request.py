from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="TransitionRequest")


@_attrs_define
class TransitionRequest:
    """
    Attributes:
        new_status (str): Target lifecycle state
        actor (str | Unset): Who initiated the transition Default: 'system'.
    """

    new_status: str
    actor: str | Unset = "system"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_status = self.new_status

        actor = self.actor

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "new_status": new_status,
            }
        )
        if actor is not UNSET:
            field_dict["actor"] = actor

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_status = d.pop("new_status")

        actor = d.pop("actor", UNSET)

        transition_request = cls(
            new_status=new_status,
            actor=actor,
        )

        transition_request.additional_properties = d
        return transition_request

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
