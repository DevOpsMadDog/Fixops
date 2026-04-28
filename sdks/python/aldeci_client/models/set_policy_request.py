from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.set_policy_request_rules import SetPolicyRequestRules


T = TypeVar("T", bound="SetPolicyRequest")


@_attrs_define
class SetPolicyRequest:
    """Configure license policy rules for an org.

    Attributes:
        rules (SetPolicyRequestRules):
        org_id (str | Unset):  Default: 'default'.
    """

    rules: SetPolicyRequestRules
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        rules = self.rules.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "rules": rules,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.set_policy_request_rules import SetPolicyRequestRules

        d = dict(src_dict)
        rules = SetPolicyRequestRules.from_dict(d.pop("rules"))

        org_id = d.pop("org_id", UNSET)

        set_policy_request = cls(
            rules=rules,
            org_id=org_id,
        )

        set_policy_request.additional_properties = d
        return set_policy_request

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
