from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.check_canary_request_context import CheckCanaryRequestContext


T = TypeVar("T", bound="CheckCanaryRequest")


@_attrs_define
class CheckCanaryRequest:
    """
    Attributes:
        token_value (str): Value to check against known canaries
        source_ip (str): IP address of the accessor
        context (CheckCanaryRequestContext | Unset): Optional context (user_agent, headers, etc.)
    """

    token_value: str
    source_ip: str
    context: CheckCanaryRequestContext | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        token_value = self.token_value

        source_ip = self.source_ip

        context: dict[str, Any] | Unset = UNSET
        if not isinstance(self.context, Unset):
            context = self.context.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "token_value": token_value,
                "source_ip": source_ip,
            }
        )
        if context is not UNSET:
            field_dict["context"] = context

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.check_canary_request_context import CheckCanaryRequestContext

        d = dict(src_dict)
        token_value = d.pop("token_value")

        source_ip = d.pop("source_ip")

        _context = d.pop("context", UNSET)
        context: CheckCanaryRequestContext | Unset
        if isinstance(_context, Unset):
            context = UNSET
        else:
            context = CheckCanaryRequestContext.from_dict(_context)

        check_canary_request = cls(
            token_value=token_value,
            source_ip=source_ip,
            context=context,
        )

        check_canary_request.additional_properties = d
        return check_canary_request

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
