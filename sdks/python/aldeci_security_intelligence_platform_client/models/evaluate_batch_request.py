from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.policy_scope import PolicyScope
from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.evaluate_batch_request_inputs_item import EvaluateBatchRequestInputsItem


T = TypeVar("T", bound="EvaluateBatchRequest")


@_attrs_define
class EvaluateBatchRequest:
    """
    Attributes:
        inputs (list[EvaluateBatchRequestInputsItem]):
        scope (PolicyScope):
        org_id (None | str | Unset):
    """

    inputs: list[EvaluateBatchRequestInputsItem]
    scope: PolicyScope
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        inputs = []
        for inputs_item_data in self.inputs:
            inputs_item = inputs_item_data.to_dict()
            inputs.append(inputs_item)

        scope = self.scope.value

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "inputs": inputs,
                "scope": scope,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_batch_request_inputs_item import EvaluateBatchRequestInputsItem

        d = dict(src_dict)
        inputs = []
        _inputs = d.pop("inputs")
        for inputs_item_data in _inputs:
            inputs_item = EvaluateBatchRequestInputsItem.from_dict(inputs_item_data)

            inputs.append(inputs_item)

        scope = PolicyScope(d.pop("scope"))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        evaluate_batch_request = cls(
            inputs=inputs,
            scope=scope,
            org_id=org_id,
        )

        evaluate_batch_request.additional_properties = d
        return evaluate_batch_request

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
