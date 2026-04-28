from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.evaluate_context_request_context import EvaluateContextRequestContext


T = TypeVar("T", bound="EvaluateContextRequest")


@_attrs_define
class EvaluateContextRequest:
    """Request body for evaluating a context dict against all active policies.

    Attributes:
        context (EvaluateContextRequestContext): Arbitrary context to evaluate (finding, asset, user, etc.)
    """

    context: EvaluateContextRequestContext
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "context": context,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.evaluate_context_request_context import EvaluateContextRequestContext

        d = dict(src_dict)
        context = EvaluateContextRequestContext.from_dict(d.pop("context"))

        evaluate_context_request = cls(
            context=context,
        )

        evaluate_context_request.additional_properties = d
        return evaluate_context_request

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
