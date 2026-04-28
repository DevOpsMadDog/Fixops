from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.escalation_paths_request_policies_item import EscalationPathsRequestPoliciesItem


T = TypeVar("T", bound="EscalationPathsRequest")


@_attrs_define
class EscalationPathsRequest:
    """
    Attributes:
        policies (list[EscalationPathsRequestPoliciesItem]): List of {principal: str, policy: dict} objects
    """

    policies: list[EscalationPathsRequestPoliciesItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policies = []
        for policies_item_data in self.policies:
            policies_item = policies_item_data.to_dict()
            policies.append(policies_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policies": policies,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.escalation_paths_request_policies_item import EscalationPathsRequestPoliciesItem

        d = dict(src_dict)
        policies = []
        _policies = d.pop("policies")
        for policies_item_data in _policies:
            policies_item = EscalationPathsRequestPoliciesItem.from_dict(policies_item_data)

            policies.append(policies_item)

        escalation_paths_request = cls(
            policies=policies,
        )

        escalation_paths_request.additional_properties = d
        return escalation_paths_request

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
