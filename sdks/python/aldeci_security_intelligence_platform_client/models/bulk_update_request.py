from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.bulk_update_request_updates import BulkUpdateRequestUpdates


T = TypeVar("T", bound="BulkUpdateRequest")


@_attrs_define
class BulkUpdateRequest:
    """Request model for bulk update operations.

    Attributes:
        ids (list[str]):
        updates (BulkUpdateRequestUpdates):
    """

    ids: list[str]
    updates: BulkUpdateRequestUpdates
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ids = self.ids

        updates = self.updates.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ids": ids,
                "updates": updates,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.bulk_update_request_updates import BulkUpdateRequestUpdates

        d = dict(src_dict)
        ids = cast(list[str], d.pop("ids"))

        updates = BulkUpdateRequestUpdates.from_dict(d.pop("updates"))

        bulk_update_request = cls(
            ids=ids,
            updates=updates,
        )

        bulk_update_request.additional_properties = d
        return bulk_update_request

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
