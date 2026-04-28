from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.decide_request_context import DecideRequestContext
    from ..models.decide_request_finding import DecideRequestFinding


T = TypeVar("T", bound="DecideRequest")


@_attrs_define
class DecideRequest:
    """
    Attributes:
        finding (DecideRequestFinding): Finding to analyze
        context (DecideRequestContext | Unset): Additional context
    """

    finding: DecideRequestFinding
    context: DecideRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding = self.finding.to_dict()

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding": finding,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.decide_request_context import DecideRequestContext
        from ..models.decide_request_finding import DecideRequestFinding

        d = dict(src_dict)
        finding = DecideRequestFinding.from_dict(d.pop("finding"))

        _context = d.pop("context", UNSET)
        context: DecideRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = DecideRequestContext.from_dict(_context)

        decide_request = cls(
            finding=finding,
            context=context,
        )

        decide_request.additional_properties = d
        return decide_request

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
