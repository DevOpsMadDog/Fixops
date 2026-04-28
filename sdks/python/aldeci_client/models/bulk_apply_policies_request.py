from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BulkApplyPoliciesRequest")


@_attrs_define
class BulkApplyPoliciesRequest:
    """Request model for bulk policy application.

    Attributes:
        policy_ids (list[str]):
        target_ids (list[str]):
    """

    policy_ids: list[str]
    target_ids: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_ids = self.policy_ids

        target_ids = self.target_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_ids": policy_ids,
                "target_ids": target_ids,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        policy_ids = cast(list[str], d.pop("policy_ids"))

        target_ids = cast(list[str], d.pop("target_ids"))

        bulk_apply_policies_request = cls(
            policy_ids=policy_ids,
            target_ids=target_ids,
        )

        bulk_apply_policies_request.additional_properties = d
        return bulk_apply_policies_request

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
