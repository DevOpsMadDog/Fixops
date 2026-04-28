from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.analyze_account_request_policies_item import AnalyzeAccountRequestPoliciesItem


T = TypeVar("T", bound="AnalyzeAccountRequest")


@_attrs_define
class AnalyzeAccountRequest:
    """
    Attributes:
        account_id (str): AWS account ID (12-digit)
        policies (list[AnalyzeAccountRequestPoliciesItem]): List of {principal: str, policy: dict} objects
    """

    account_id: str
    policies: list[AnalyzeAccountRequestPoliciesItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        account_id = self.account_id

        policies = []
        for policies_item_data in self.policies:
            policies_item = policies_item_data.to_dict()
            policies.append(policies_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "account_id": account_id,
                "policies": policies,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.analyze_account_request_policies_item import AnalyzeAccountRequestPoliciesItem

        d = dict(src_dict)
        account_id = d.pop("account_id")

        policies = []
        _policies = d.pop("policies")
        for policies_item_data in _policies:
            policies_item = AnalyzeAccountRequestPoliciesItem.from_dict(policies_item_data)

            policies.append(policies_item)

        analyze_account_request = cls(
            account_id=account_id,
            policies=policies,
        )

        analyze_account_request.additional_properties = d
        return analyze_account_request

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
