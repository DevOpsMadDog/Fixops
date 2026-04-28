from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.fix_response_details_item import FixResponseDetailsItem


T = TypeVar("T", bound="FixResponse")


@_attrs_define
class FixResponse:
    """Result of an auto-fix operation.

    Attributes:
        dry_run (bool):
        fixes_applied (int):
        fixes_skipped (int):
        errors (int):
        details (list[FixResponseDetailsItem]):
    """

    dry_run: bool
    fixes_applied: int
    fixes_skipped: int
    errors: int
    details: list[FixResponseDetailsItem]
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dry_run = self.dry_run

        fixes_applied = self.fixes_applied

        fixes_skipped = self.fixes_skipped

        errors = self.errors

        details = []
        for details_item_data in self.details:
            details_item = details_item_data.to_dict()
            details.append(details_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dry_run": dry_run,
                "fixes_applied": fixes_applied,
                "fixes_skipped": fixes_skipped,
                "errors": errors,
                "details": details,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.fix_response_details_item import FixResponseDetailsItem

        d = dict(src_dict)
        dry_run = d.pop("dry_run")

        fixes_applied = d.pop("fixes_applied")

        fixes_skipped = d.pop("fixes_skipped")

        errors = d.pop("errors")

        details = []
        _details = d.pop("details")
        for details_item_data in _details:
            details_item = FixResponseDetailsItem.from_dict(details_item_data)

            details.append(details_item)

        fix_response = cls(
            dry_run=dry_run,
            fixes_applied=fixes_applied,
            fixes_skipped=fixes_skipped,
            errors=errors,
            details=details,
        )

        fix_response.additional_properties = d
        return fix_response

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
