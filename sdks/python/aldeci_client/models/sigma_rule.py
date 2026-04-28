from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.hunt_severity import HuntSeverity
from ..types import UNSET, Unset

T = TypeVar("T", bound="SigmaRule")


@_attrs_define
class SigmaRule:
    """A Sigma detection rule.

    Attributes:
        name (str):
        id (str | Unset):
        description (str | Unset):  Default: ''.
        author (str | Unset):  Default: ''.
        status (str | Unset):  Default: 'experimental'.
        logsource_category (str | Unset):  Default: ''.
        logsource_product (str | Unset):  Default: ''.
        detection_keywords (list[str] | Unset):
        detection_condition (str | Unset):  Default: ''.
        false_positives (list[str] | Unset):
        level (HuntSeverity | Unset):
        tags (list[str] | Unset):
        raw_yaml (str | Unset):  Default: ''.
        search_query (str | Unset):  Default: ''.
        created_at (datetime.datetime | Unset):
        enabled (bool | Unset):  Default: True.
    """

    name: str
    id: str | Unset = UNSET
    description: str | Unset = ""
    author: str | Unset = ""
    status: str | Unset = "experimental"
    logsource_category: str | Unset = ""
    logsource_product: str | Unset = ""
    detection_keywords: list[str] | Unset = UNSET
    detection_condition: str | Unset = ""
    false_positives: list[str] | Unset = UNSET
    level: HuntSeverity | Unset = UNSET
    tags: list[str] | Unset = UNSET
    raw_yaml: str | Unset = ""
    search_query: str | Unset = ""
    created_at: datetime.datetime | Unset = UNSET
    enabled: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        id = self.id

        description = self.description

        author = self.author

        status = self.status

        logsource_category = self.logsource_category

        logsource_product = self.logsource_product

        detection_keywords: list[str] | Unset = UNSET
        if not isinstance(self.detection_keywords, Unset):
            detection_keywords = self.detection_keywords

        detection_condition = self.detection_condition

        false_positives: list[str] | Unset = UNSET
        if not isinstance(self.false_positives, Unset):
            false_positives = self.false_positives

        level: str | Unset = UNSET
        if not isinstance(self.level, Unset):
            level = self.level.value

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        raw_yaml = self.raw_yaml

        search_query = self.search_query

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        enabled = self.enabled

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if author is not UNSET:
            field_dict["author"] = author
        if status is not UNSET:
            field_dict["status"] = status
        if logsource_category is not UNSET:
            field_dict["logsource_category"] = logsource_category
        if logsource_product is not UNSET:
            field_dict["logsource_product"] = logsource_product
        if detection_keywords is not UNSET:
            field_dict["detection_keywords"] = detection_keywords
        if detection_condition is not UNSET:
            field_dict["detection_condition"] = detection_condition
        if false_positives is not UNSET:
            field_dict["false_positives"] = false_positives
        if level is not UNSET:
            field_dict["level"] = level
        if tags is not UNSET:
            field_dict["tags"] = tags
        if raw_yaml is not UNSET:
            field_dict["raw_yaml"] = raw_yaml
        if search_query is not UNSET:
            field_dict["search_query"] = search_query
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if enabled is not UNSET:
            field_dict["enabled"] = enabled

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        id = d.pop("id", UNSET)

        description = d.pop("description", UNSET)

        author = d.pop("author", UNSET)

        status = d.pop("status", UNSET)

        logsource_category = d.pop("logsource_category", UNSET)

        logsource_product = d.pop("logsource_product", UNSET)

        detection_keywords = cast(list[str], d.pop("detection_keywords", UNSET))

        detection_condition = d.pop("detection_condition", UNSET)

        false_positives = cast(list[str], d.pop("false_positives", UNSET))

        _level = d.pop("level", UNSET)
        level: HuntSeverity | Unset
        if isinstance(_level, Unset):
            level = UNSET
        else:
            level = HuntSeverity(_level)

        tags = cast(list[str], d.pop("tags", UNSET))

        raw_yaml = d.pop("raw_yaml", UNSET)

        search_query = d.pop("search_query", UNSET)

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        enabled = d.pop("enabled", UNSET)

        sigma_rule = cls(
            name=name,
            id=id,
            description=description,
            author=author,
            status=status,
            logsource_category=logsource_category,
            logsource_product=logsource_product,
            detection_keywords=detection_keywords,
            detection_condition=detection_condition,
            false_positives=false_positives,
            level=level,
            tags=tags,
            raw_yaml=raw_yaml,
            search_query=search_query,
            created_at=created_at,
            enabled=enabled,
        )

        sigma_rule.additional_properties = d
        return sigma_rule

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
