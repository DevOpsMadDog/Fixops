from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.analyze_policy_request_policy import AnalyzePolicyRequestPolicy


T = TypeVar("T", bound="AnalyzePolicyRequest")


@_attrs_define
class AnalyzePolicyRequest:
    """
    Attributes:
        policy (AnalyzePolicyRequestPolicy): AWS IAM policy document JSON
        principal (str): IAM entity ARN or name this policy is attached to
    """

    policy: AnalyzePolicyRequestPolicy
    principal: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy = self.policy.to_dict()

        principal = self.principal

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy": policy,
                "principal": principal,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.analyze_policy_request_policy import AnalyzePolicyRequestPolicy

        d = dict(src_dict)
        policy = AnalyzePolicyRequestPolicy.from_dict(d.pop("policy"))

        principal = d.pop("principal")

        analyze_policy_request = cls(
            policy=policy,
            principal=principal,
        )

        analyze_policy_request.additional_properties = d
        return analyze_policy_request

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
