from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.asset_lifecycle import AssetLifecycle

T = TypeVar("T", bound="LifecycleTransitionRequest")


@_attrs_define
class LifecycleTransitionRequest:
    """
    Attributes:
        new_state (AssetLifecycle):
    """

    new_state: AssetLifecycle
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        new_state = self.new_state.value

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "new_state": new_state,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        new_state = AssetLifecycle(d.pop("new_state"))

        lifecycle_transition_request = cls(
            new_state=new_state,
        )

        lifecycle_transition_request.additional_properties = d
        return lifecycle_transition_request

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
