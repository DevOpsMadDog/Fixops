from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.verify_fix_request import VerifyFixRequest


T = TypeVar("T", bound="BulkVerifyRequest")


@_attrs_define
class BulkVerifyRequest:
    """Request body for POST /api/v1/verify/bulk.

    Up to 20 fix verifications in a single request.

        Attributes:
            fixes (list[VerifyFixRequest]): List of fix verification requests (max 20)
            fail_fast (bool | Unset): Stop on first failed verification Default: False.
    """

    fixes: list[VerifyFixRequest]
    fail_fast: bool | Unset = False
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        fixes = []
        for fixes_item_data in self.fixes:
            fixes_item = fixes_item_data.to_dict()
            fixes.append(fixes_item)

        fail_fast = self.fail_fast

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "fixes": fixes,
            }
        )
        if fail_fast is not UNSET:
            field_dict["fail_fast"] = fail_fast

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.verify_fix_request import VerifyFixRequest

        d = dict(src_dict)
        fixes = []
        _fixes = d.pop("fixes")
        for fixes_item_data in _fixes:
            fixes_item = VerifyFixRequest.from_dict(fixes_item_data)

            fixes.append(fixes_item)

        fail_fast = d.pop("fail_fast", UNSET)

        bulk_verify_request = cls(
            fixes=fixes,
            fail_fast=fail_fast,
        )

        bulk_verify_request.additional_properties = d
        return bulk_verify_request

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
