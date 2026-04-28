from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.hunt_severity import HuntSeverity
from ..models.ioc_type import IOCType
from ..types import UNSET, Unset

T = TypeVar("T", bound="IOC")


@_attrs_define
class IOC:
    """An Indicator of Compromise.

    Attributes:
        type_ (IOCType):
        value (str):
        id (str | Unset):
        description (str | Unset):  Default: ''.
        confidence (int | Unset):  Default: 50.
        severity (HuntSeverity | Unset):
        source (str | Unset):  Default: 'manual'.
        tags (list[str] | Unset):
        stix_id (None | str | Unset):
        first_seen (datetime.datetime | Unset):
        last_seen (datetime.datetime | Unset):
        active (bool | Unset):  Default: True.
    """

    type_: IOCType
    value: str
    id: str | Unset = UNSET
    description: str | Unset = ""
    confidence: int | Unset = 50
    severity: HuntSeverity | Unset = UNSET
    source: str | Unset = "manual"
    tags: list[str] | Unset = UNSET
    stix_id: None | str | Unset = UNSET
    first_seen: datetime.datetime | Unset = UNSET
    last_seen: datetime.datetime | Unset = UNSET
    active: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        type_ = self.type_.value

        value = self.value

        id = self.id

        description = self.description

        confidence = self.confidence

        severity: str | Unset = UNSET
        if not isinstance(self.severity, Unset):
            severity = self.severity.value

        source = self.source

        tags: list[str] | Unset = UNSET
        if not isinstance(self.tags, Unset):
            tags = self.tags

        stix_id: None | str | Unset
        if isinstance(self.stix_id, Unset):
            stix_id = UNSET
        else:
            stix_id = self.stix_id

        first_seen: str | Unset = UNSET
        if not isinstance(self.first_seen, Unset):
            first_seen = self.first_seen.isoformat()

        last_seen: str | Unset = UNSET
        if not isinstance(self.last_seen, Unset):
            last_seen = self.last_seen.isoformat()

        active = self.active

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "type": type_,
                "value": value,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if description is not UNSET:
            field_dict["description"] = description
        if confidence is not UNSET:
            field_dict["confidence"] = confidence
        if severity is not UNSET:
            field_dict["severity"] = severity
        if source is not UNSET:
            field_dict["source"] = source
        if tags is not UNSET:
            field_dict["tags"] = tags
        if stix_id is not UNSET:
            field_dict["stix_id"] = stix_id
        if first_seen is not UNSET:
            field_dict["first_seen"] = first_seen
        if last_seen is not UNSET:
            field_dict["last_seen"] = last_seen
        if active is not UNSET:
            field_dict["active"] = active

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        type_ = IOCType(d.pop("type"))

        value = d.pop("value")

        id = d.pop("id", UNSET)

        description = d.pop("description", UNSET)

        confidence = d.pop("confidence", UNSET)

        _severity = d.pop("severity", UNSET)
        severity: HuntSeverity | Unset
        if isinstance(_severity, Unset):
            severity = UNSET
        else:
            severity = HuntSeverity(_severity)

        source = d.pop("source", UNSET)

        tags = cast(list[str], d.pop("tags", UNSET))

        def _parse_stix_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        stix_id = _parse_stix_id(d.pop("stix_id", UNSET))

        _first_seen = d.pop("first_seen", UNSET)
        first_seen: datetime.datetime | Unset
        if isinstance(_first_seen, Unset):
            first_seen = UNSET
        else:
            first_seen = isoparse(_first_seen)

        _last_seen = d.pop("last_seen", UNSET)
        last_seen: datetime.datetime | Unset
        if isinstance(_last_seen, Unset):
            last_seen = UNSET
        else:
            last_seen = isoparse(_last_seen)

        active = d.pop("active", UNSET)

        ioc = cls(
            type_=type_,
            value=value,
            id=id,
            description=description,
            confidence=confidence,
            severity=severity,
            source=source,
            tags=tags,
            stix_id=stix_id,
            first_seen=first_seen,
            last_seen=last_seen,
            active=active,
        )

        ioc.additional_properties = d
        return ioc

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
