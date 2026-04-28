from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.feed_item_create_raw_data import FeedItemCreateRawData


T = TypeVar("T", bound="FeedItemCreate")


@_attrs_define
class FeedItemCreate:
    """
    Attributes:
        source_id (str):
        feed_type (str | Unset):  Default: 'cve'.
        title (str | Unset):  Default: ''.
        description (str | Unset):  Default: ''.
        severity (str | Unset):  Default: 'medium'.
        iocs (list[Any] | Unset):
        cves (list[Any] | Unset):
        tags (list[Any] | Unset):
        raw_data (FeedItemCreateRawData | Unset):
    """

    source_id: str
    feed_type: str | Unset = "cve"
    title: str | Unset = ""
    description: str | Unset = ""
    severity: str | Unset = "medium"
    iocs: list[Any] | Unset = UNSET
    cves: list[Any] | Unset = UNSET
    tags: list[Any] | Unset = UNSET
    raw_data: FeedItemCreateRawData | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        source_id = self.source_id

        feed_type = self.feed_type

        title = self.title

        description = self.description

        severity = self.severity

        iocs: list[Any] | Unset = UNSET
        if not isinstance(self.iocs, Unset):
            iocs = self.iocs

        cves: list[Any] | Unset = UNSET
        if not isinstance(self.cves, Unset):
            cves = self.cves

        tags: list[Any] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        raw_data: dict[str, Any] | Unset = UNSET
        if not isinstance(self.raw_data, Unset):
            raw_data = self.raw_data.to_dict()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "source_id": source_id,
            }
        )
        if feed_type is not UNSET:
            field_dict["feed_type"] = feed_type
        if title is not UNSET:
            field_dict["title"] = title
        if description is not UNSET:
            field_dict["description"] = description
        if severity is not UNSET:
            field_dict["severity"] = severity
        if iocs is not UNSET:
            field_dict["iocs"] = iocs
        if cves is not UNSET:
            field_dict["cves"] = cves
        if tags is not UNSET:
            field_dict["tags"] = tags
        if raw_data is not UNSET:
            field_dict["raw_data"] = raw_data

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.feed_item_create_raw_data import FeedItemCreateRawData

        d = dict(src_dict)
        source_id = d.pop("source_id")

        feed_type = d.pop("feed_type", UNSET)

        title = d.pop("title", UNSET)

        description = d.pop("description", UNSET)

        severity = d.pop("severity", UNSET)

        iocs = cast(list[Any], d.pop("iocs", UNSET))

        cves = cast(list[Any], d.pop("cves", UNSET))

        tags = cast(list[Any], d.pop("tags", UNSET))

        _raw_data = d.pop("raw_data", UNSET)
        raw_data: FeedItemCreateRawData | Unset
        if isinstance(_raw_data, Unset):
            raw_data = UNSET
        else:
            raw_data = FeedItemCreateRawData.from_dict(_raw_data)

        feed_item_create = cls(
            source_id=source_id,
            feed_type=feed_type,
            title=title,
            description=description,
            severity=severity,
            iocs=iocs,
            cves=cves,
            tags=tags,
            raw_data=raw_data,
        )

        feed_item_create.additional_properties = d
        return feed_item_create

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
