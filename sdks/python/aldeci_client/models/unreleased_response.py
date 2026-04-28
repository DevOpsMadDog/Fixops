from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

if TYPE_CHECKING:
    from ..models.unreleased_response_entries_item import UnreleasedResponseEntriesItem


T = TypeVar("T", bound="UnreleasedResponse")


@_attrs_define
class UnreleasedResponse:
    """Response for /unreleased.

    Attributes:
        since_tag (str):
        entry_count (int):
        entries (list[UnreleasedResponseEntriesItem]):
        suggested_version (str):
    """

    since_tag: str
    entry_count: int
    entries: list[UnreleasedResponseEntriesItem]
    suggested_version: str
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        since_tag = self.since_tag

        entry_count = self.entry_count

        entries = []
        for entries_item_data in self.entries:
            entries_item = entries_item_data.to_dict()
            entries.append(entries_item)

        suggested_version = self.suggested_version

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "since_tag": since_tag,
                "entry_count": entry_count,
                "entries": entries,
                "suggested_version": suggested_version,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.unreleased_response_entries_item import UnreleasedResponseEntriesItem

        d = dict(src_dict)
        since_tag = d.pop("since_tag")

        entry_count = d.pop("entry_count")

        entries = []
        _entries = d.pop("entries")
        for entries_item_data in _entries:
            entries_item = UnreleasedResponseEntriesItem.from_dict(entries_item_data)

            entries.append(entries_item)

        suggested_version = d.pop("suggested_version")

        unreleased_response = cls(
            since_tag=since_tag,
            entry_count=entry_count,
            entries=entries,
            suggested_version=suggested_version,
        )

        unreleased_response.additional_properties = d
        return unreleased_response

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
