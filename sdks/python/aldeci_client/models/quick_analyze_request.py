from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuickAnalyzeRequest")


@_attrs_define
class QuickAnalyzeRequest:
    """Quick vulnerability analysis request.

    Attributes:
        cve_id (None | str | Unset):
        finding_id (None | str | Unset):
        asset_id (None | str | Unset):
        description (None | str | Unset):
    """

    cve_id: None | str | Unset = UNSET
    finding_id: None | str | Unset = UNSET
    asset_id: None | str | Unset = UNSET
    description: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        finding_id: None | str | Unset
        if isinstance(self.finding_id, Unset):
            finding_id = UNSET
        else:
            finding_id = self.finding_id

        asset_id: None | str | Unset
        if isinstance(self.asset_id, Unset):
            asset_id = UNSET
        else:
            asset_id = self.asset_id

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if finding_id is not UNSET:
            field_dict["finding_id"] = finding_id
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_finding_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        finding_id = _parse_finding_id(d.pop("finding_id", UNSET))

        def _parse_asset_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_id = _parse_asset_id(d.pop("asset_id", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        quick_analyze_request = cls(
            cve_id=cve_id,
            finding_id=finding_id,
            asset_id=asset_id,
            description=description,
        )

        quick_analyze_request.additional_properties = d
        return quick_analyze_request

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
