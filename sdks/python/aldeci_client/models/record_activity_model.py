from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordActivityModel")


@_attrs_define
class RecordActivityModel:
    """
    Attributes:
        activity_type (str):
        description (str | Unset):  Default: ''.
        affected_sectors (str | Unset):  Default: ''.
        ttps_used (list[str] | Unset):
        indicators (list[str] | Unset):
        source (str | Unset):  Default: ''.
        verified (bool | Unset):  Default: False.
        org_id (str | Unset):  Default: 'default'.
    """

    activity_type: str
    description: str | Unset = ""
    affected_sectors: str | Unset = ""
    ttps_used: list[str] | Unset = UNSET
    indicators: list[str] | Unset = UNSET
    source: str | Unset = ""
    verified: bool | Unset = False
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        activity_type = self.activity_type

        description = self.description

        affected_sectors = self.affected_sectors

        ttps_used: list[str] | Unset = UNSET
        if not isinstance(self.ttps_used, Unset):
            ttps_used = self.ttps_used

        indicators: list[str] | Unset = UNSET
        if not isinstance(self.indicators, Unset):
            indicators = self.indicators

        source = self.source

        verified = self.verified

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "activity_type": activity_type,
            }
        )
        if description is not UNSET:
            field_dict["description"] = description
        if affected_sectors is not UNSET:
            field_dict["affected_sectors"] = affected_sectors
        if ttps_used is not UNSET:
            field_dict["ttps_used"] = ttps_used
        if indicators is not UNSET:
            field_dict["indicators"] = indicators
        if source is not UNSET:
            field_dict["source"] = source
        if verified is not UNSET:
            field_dict["verified"] = verified
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        activity_type = d.pop("activity_type")

        description = d.pop("description", UNSET)

        affected_sectors = d.pop("affected_sectors", UNSET)

        ttps_used = cast(list[str], d.pop("ttps_used", UNSET))

        indicators = cast(list[str], d.pop("indicators", UNSET))

        source = d.pop("source", UNSET)

        verified = d.pop("verified", UNSET)

        org_id = d.pop("org_id", UNSET)

        record_activity_model = cls(
            activity_type=activity_type,
            description=description,
            affected_sectors=affected_sectors,
            ttps_used=ttps_used,
            indicators=indicators,
            source=source,
            verified=verified,
            org_id=org_id,
        )

        record_activity_model.additional_properties = d
        return record_activity_model

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
