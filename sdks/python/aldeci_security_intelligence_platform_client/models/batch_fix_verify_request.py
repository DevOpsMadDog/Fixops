from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.fix_verify_request import FixVerifyRequest


T = TypeVar("T", bound="BatchFixVerifyRequest")


@_attrs_define
class BatchFixVerifyRequest:
    """Batch verification request.

    Attributes:
        fixes (list[FixVerifyRequest]): Up to 50 fixes to verify
    """

    fixes: list[FixVerifyRequest]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fixes = []
        for fixes_item_data in self.fixes:
            fixes_item = fixes_item_data.to_dict()
            fixes.append(fixes_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "fixes": fixes,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fix_verify_request import FixVerifyRequest

        d = dict(src_dict)
        fixes = []
        _fixes = d.pop("fixes")
        for fixes_item_data in _fixes:
            fixes_item = FixVerifyRequest.from_dict(fixes_item_data)

            fixes.append(fixes_item)

        batch_fix_verify_request = cls(
            fixes=fixes,
        )

        batch_fix_verify_request.additional_properties = d
        return batch_fix_verify_request

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
