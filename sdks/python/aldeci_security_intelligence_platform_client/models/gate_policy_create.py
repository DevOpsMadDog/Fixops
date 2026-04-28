from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="GatePolicyCreate")


@_attrs_define
class GatePolicyCreate:
    """
    Attributes:
        name (str):
        pipeline_id (str | Unset):  Default: ''.
        block_on_critical (int | Unset):  Default: 1.
        block_on_high (int | Unset):  Default: 0.
        max_critical (int | Unset):  Default: 0.
        max_high (int | Unset):  Default: 5.
        max_medium (int | Unset):  Default: 20.
        enabled (int | Unset):  Default: 1.
    """

    name: str
    pipeline_id: str | Unset = ""
    block_on_critical: int | Unset = 1
    block_on_high: int | Unset = 0
    max_critical: int | Unset = 0
    max_high: int | Unset = 5
    max_medium: int | Unset = 20
    enabled: int | Unset = 1
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        pipeline_id = self.pipeline_id

        block_on_critical = self.block_on_critical

        block_on_high = self.block_on_high

        max_critical = self.max_critical

        max_high = self.max_high

        max_medium = self.max_medium

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if pipeline_id is not UNSET:
            field_dict["pipeline_id"] = pipeline_id
        if block_on_critical is not UNSET:
            field_dict["block_on_critical"] = block_on_critical
        if block_on_high is not UNSET:
            field_dict["block_on_high"] = block_on_high
        if max_critical is not UNSET:
            field_dict["max_critical"] = max_critical
        if max_high is not UNSET:
            field_dict["max_high"] = max_high
        if max_medium is not UNSET:
            field_dict["max_medium"] = max_medium
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        pipeline_id = d.pop("pipeline_id", UNSET)

        block_on_critical = d.pop("block_on_critical", UNSET)

        block_on_high = d.pop("block_on_high", UNSET)

        max_critical = d.pop("max_critical", UNSET)

        max_high = d.pop("max_high", UNSET)

        max_medium = d.pop("max_medium", UNSET)

        enabled = d.pop("enabled", UNSET)

        gate_policy_create = cls(
            name=name,
            pipeline_id=pipeline_id,
            block_on_critical=block_on_critical,
            block_on_high=block_on_high,
            max_critical=max_critical,
            max_high=max_high,
            max_medium=max_medium,
            enabled=enabled,
        )

        gate_policy_create.additional_properties = d
        return gate_policy_create

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
