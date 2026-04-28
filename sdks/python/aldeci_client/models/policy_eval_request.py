from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.policy_eval_request_input_data import PolicyEvalRequestInputData


T = TypeVar("T", bound="PolicyEvalRequest")


@_attrs_define
class PolicyEvalRequest:
    """
    Attributes:
        policy_name (str):
        input_data (PolicyEvalRequestInputData):
    """

    policy_name: str
    input_data: PolicyEvalRequestInputData
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        policy_name = self.policy_name

        input_data = self.input_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "policy_name": policy_name,
                "input_data": input_data,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.policy_eval_request_input_data import PolicyEvalRequestInputData

        d = dict(src_dict)
        policy_name = d.pop("policy_name")

        input_data = PolicyEvalRequestInputData.from_dict(d.pop("input_data"))

        policy_eval_request = cls(
            policy_name=policy_name,
            input_data=input_data,
        )

        policy_eval_request.additional_properties = d
        return policy_eval_request

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
