from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="BulkStatusUpdateResponse")


@_attrs_define
class BulkStatusUpdateResponse:
    """Response from bulk update.

    Attributes:
        updated (int):
        failed (int):
        total_requested (int):
        errors (list[str]):
    """

    updated: int
    failed: int
    total_requested: int
    errors: list[str]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        updated = self.updated

        failed = self.failed

        total_requested = self.total_requested

        errors = self.errors

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "updated": updated,
                "failed": failed,
                "total_requested": total_requested,
                "errors": errors,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        updated = d.pop("updated")

        failed = d.pop("failed")

        total_requested = d.pop("total_requested")

        errors = cast(list[str], d.pop("errors"))

        bulk_status_update_response = cls(
            updated=updated,
            failed=failed,
            total_requested=total_requested,
            errors=errors,
        )

        bulk_status_update_response.additional_properties = d
        return bulk_status_update_response

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
