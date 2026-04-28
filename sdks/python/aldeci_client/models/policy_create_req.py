from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="PolicyCreateReq")


@_attrs_define
class PolicyCreateReq:
    """
    Attributes:
        org_id (str):
        policy_name (str):
        workload_types (list[str] | Unset):
        controls (list[str] | Unset):
        enforcement (str | Unset):  Default: 'alert'.
        enabled (bool | Unset):  Default: True.
    """

    org_id: str
    policy_name: str
    workload_types: list[str] | Unset = UNSET
    controls: list[str] | Unset = UNSET
    enforcement: str | Unset = "alert"
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        policy_name = self.policy_name

        workload_types: list[str] | Unset = UNSET
        if not isinstance(self.workload_types, Unset):
            workload_types = self.workload_types

        controls: list[str] | Unset = UNSET
        if not isinstance(self.controls, Unset):
            controls = self.controls

        enforcement = self.enforcement

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "policy_name": policy_name,
            }
        )
        if workload_types is not UNSET:
            field_dict["workload_types"] = workload_types
        if controls is not UNSET:
            field_dict["controls"] = controls
        if enforcement is not UNSET:
            field_dict["enforcement"] = enforcement
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        policy_name = d.pop("policy_name")

        workload_types = cast(list[str], d.pop("workload_types", UNSET))

        controls = cast(list[str], d.pop("controls", UNSET))

        enforcement = d.pop("enforcement", UNSET)

        enabled = d.pop("enabled", UNSET)

        policy_create_req = cls(
            org_id=org_id,
            policy_name=policy_name,
            workload_types=workload_types,
            controls=controls,
            enforcement=enforcement,
            enabled=enabled,
        )

        policy_create_req.additional_properties = d
        return policy_create_req

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
