from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="ThreatIntelRequest")


@_attrs_define
class ThreatIntelRequest:
    """Request for threat intelligence.

    Attributes:
        cve_ids (list[str] | Unset):
        asset_ids (list[str] | Unset):
        include_dark_web (bool | Unset):  Default: True.
        include_zero_day (bool | Unset):  Default: True.
    """

    cve_ids: list[str] | Unset = UNSET
    asset_ids: list[str] | Unset = UNSET
    include_dark_web: bool | Unset = True
    include_zero_day: bool | Unset = True
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_ids: list[str] | Unset = UNSET
        if not isinstance(self.cve_ids, Unset):
            cve_ids = self.cve_ids

        asset_ids: list[str] | Unset = UNSET
        if not isinstance(self.asset_ids, Unset):
            asset_ids = self.asset_ids

        include_dark_web = self.include_dark_web

        include_zero_day = self.include_zero_day

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_ids is not UNSET:
            field_dict["cve_ids"] = cve_ids
        if asset_ids is not UNSET:
            field_dict["asset_ids"] = asset_ids
        if include_dark_web is not UNSET:
            field_dict["include_dark_web"] = include_dark_web
        if include_zero_day is not UNSET:
            field_dict["include_zero_day"] = include_zero_day

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        cve_ids = cast(list[str], d.pop("cve_ids", UNSET))

        asset_ids = cast(list[str], d.pop("asset_ids", UNSET))

        include_dark_web = d.pop("include_dark_web", UNSET)

        include_zero_day = d.pop("include_zero_day", UNSET)

        threat_intel_request = cls(
            cve_ids=cve_ids,
            asset_ids=asset_ids,
            include_dark_web=include_dark_web,
            include_zero_day=include_zero_day,
        )

        threat_intel_request.additional_properties = d
        return threat_intel_request

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
