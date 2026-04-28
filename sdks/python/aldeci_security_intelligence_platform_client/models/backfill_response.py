from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.backfill_response_items_item import BackfillResponseItemsItem


T = TypeVar("T", bound="BackfillResponse")


@_attrs_define
class BackfillResponse:
    """Backfill operation result.

    Attributes:
        dry_run (bool):
        would_index (int):
        actually_indexed (int):
        skipped (int):
        errors (int):
        items (list[BackfillResponseItemsItem]):
        started_at (str):
        completed_at (None | str):
    """

    dry_run: bool
    would_index: int
    actually_indexed: int
    skipped: int
    errors: int
    items: list[BackfillResponseItemsItem]
    started_at: str
    completed_at: None | str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        dry_run = self.dry_run

        would_index = self.would_index

        actually_indexed = self.actually_indexed

        skipped = self.skipped

        errors = self.errors

        items = []
        for items_item_data in self.items:
            items_item = items_item_data.to_dict()
            items.append(items_item)

        started_at = self.started_at

        completed_at: None | str
        completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "dry_run": dry_run,
                "would_index": would_index,
                "actually_indexed": actually_indexed,
                "skipped": skipped,
                "errors": errors,
                "items": items,
                "started_at": started_at,
                "completed_at": completed_at,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.backfill_response_items_item import BackfillResponseItemsItem

        d = dict(src_dict)
        dry_run = d.pop("dry_run")

        would_index = d.pop("would_index")

        actually_indexed = d.pop("actually_indexed")

        skipped = d.pop("skipped")

        errors = d.pop("errors")

        items = []
        _items = d.pop("items")
        for items_item_data in _items:
            items_item = BackfillResponseItemsItem.from_dict(items_item_data)

            items.append(items_item)

        started_at = d.pop("started_at")

        def _parse_completed_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        completed_at = _parse_completed_at(d.pop("completed_at"))

        backfill_response = cls(
            dry_run=dry_run,
            would_index=would_index,
            actually_indexed=actually_indexed,
            skipped=skipped,
            errors=errors,
            items=items,
            started_at=started_at,
            completed_at=completed_at,
        )

        backfill_response.additional_properties = d
        return backfill_response

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
