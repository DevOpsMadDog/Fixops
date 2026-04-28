from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.policy_feedback_request_context import PolicyFeedbackRequestContext


T = TypeVar("T", bound="PolicyFeedbackRequest")


@_attrs_define
class PolicyFeedbackRequest:
    """
    Attributes:
        policy_id (str): Policy ID
        rule_id (str): Rule ID within policy
        violated (bool): Was the policy violated?
        was_justified (bool): Was the action justified?
        context (PolicyFeedbackRequestContext | Unset):
    """

    policy_id: str
    rule_id: str
    violated: bool
    was_justified: bool
    context: PolicyFeedbackRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_id = self.policy_id

        rule_id = self.rule_id

        violated = self.violated

        was_justified = self.was_justified

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_id": policy_id,
                "rule_id": rule_id,
                "violated": violated,
                "was_justified": was_justified,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.policy_feedback_request_context import PolicyFeedbackRequestContext

        d = dict(src_dict)
        policy_id = d.pop("policy_id")

        rule_id = d.pop("rule_id")

        violated = d.pop("violated")

        was_justified = d.pop("was_justified")

        _context = d.pop("context", UNSET)
        context: PolicyFeedbackRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = PolicyFeedbackRequestContext.from_dict(_context)

        policy_feedback_request = cls(
            policy_id=policy_id,
            rule_id=rule_id,
            violated=violated,
            was_justified=was_justified,
            context=context,
        )

        policy_feedback_request.additional_properties = d
        return policy_feedback_request

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
