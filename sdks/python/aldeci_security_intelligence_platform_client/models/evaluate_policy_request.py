from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evaluate_policy_request_packages_item import EvaluatePolicyRequestPackagesItem
    from ..models.evaluate_policy_request_policy import EvaluatePolicyRequestPolicy


T = TypeVar("T", bound="EvaluatePolicyRequest")


@_attrs_define
class EvaluatePolicyRequest:
    """Re-evaluate a list of package scan results against a given policy.

    Attributes:
        packages (list[EvaluatePolicyRequestPackagesItem]):
        policy (EvaluatePolicyRequestPolicy):
        org_id (str | Unset):  Default: 'default'.
    """

    packages: list[EvaluatePolicyRequestPackagesItem]
    policy: EvaluatePolicyRequestPolicy
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        packages = []
        for packages_item_data in self.packages:
            packages_item = packages_item_data.to_dict()
            packages.append(packages_item)

        policy = self.policy.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "packages": packages,
                "policy": policy,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_policy_request_packages_item import EvaluatePolicyRequestPackagesItem
        from ..models.evaluate_policy_request_policy import EvaluatePolicyRequestPolicy

        d = dict(src_dict)
        packages = []
        _packages = d.pop("packages")
        for packages_item_data in _packages:
            packages_item = EvaluatePolicyRequestPackagesItem.from_dict(packages_item_data)

            packages.append(packages_item)

        policy = EvaluatePolicyRequestPolicy.from_dict(d.pop("policy"))

        org_id = d.pop("org_id", UNSET)

        evaluate_policy_request = cls(
            packages=packages,
            policy=policy,
            org_id=org_id,
        )

        evaluate_policy_request.additional_properties = d
        return evaluate_policy_request

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
