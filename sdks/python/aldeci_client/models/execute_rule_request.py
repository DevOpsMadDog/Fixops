from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.execute_rule_request_context import ExecuteRuleRequestContext


T = TypeVar("T", bound="ExecuteRuleRequest")


@_attrs_define
class ExecuteRuleRequest:
    """
    Attributes:
        context (ExecuteRuleRequestContext | Unset):
    """

    context: ExecuteRuleRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.execute_rule_request_context import ExecuteRuleRequestContext

        d = dict(src_dict)
        _context = d.pop("context", UNSET)
        context: ExecuteRuleRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = ExecuteRuleRequestContext.from_dict(_context)

        execute_rule_request = cls(
            context=context,
        )

        execute_rule_request.additional_properties = d
        return execute_rule_request

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
