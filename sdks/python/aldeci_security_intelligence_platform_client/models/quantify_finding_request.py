from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="QuantifyFindingRequest")


@_attrs_define
class QuantifyFindingRequest:
    """Request body for auto-quantifying a finding.

    Attributes:
        id (None | str | Unset):
        title (None | str | Unset):
        severity (str | Unset):  Default: 'medium'.
        asset_type (None | str | Unset):
        asset_value_usd (float | None | Unset):
        description (None | str | Unset):
    """

    id: None | str | Unset = UNSET
    title: None | str | Unset = UNSET
    severity: str | Unset = "medium"
    asset_type: None | str | Unset = UNSET
    asset_value_usd: float | None | Unset = UNSET
    description: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        id: None | str | Unset
        if isinstance(self.id, Unset):
            id = UNSET
        else:
            id = self.id

        title: None | str | Unset
        if isinstance(self.title, Unset):
            title = UNSET
        else:
            title = self.title

        severity = self.severity

        asset_type: None | str | Unset
        if isinstance(self.asset_type, Unset):
            asset_type = UNSET
        else:
            asset_type = self.asset_type

        asset_value_usd: float | None | Unset
        if isinstance(self.asset_value_usd, Unset):
            asset_value_usd = UNSET
        else:
            asset_value_usd = self.asset_value_usd

        description: None | str | Unset
        if isinstance(self.description, Unset):
            description = UNSET
        else:
            description = self.description

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if id is not UNSET:
            field_dict["id"] = id
        if title is not UNSET:
            field_dict["title"] = title
        if severity is not UNSET:
            field_dict["severity"] = severity
        if asset_type is not UNSET:
            field_dict["asset_type"] = asset_type
        if asset_value_usd is not UNSET:
            field_dict["asset_value_usd"] = asset_value_usd
        if description is not UNSET:
            field_dict["description"] = description

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        id = _parse_id(d.pop("id", UNSET))

        def _parse_title(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        title = _parse_title(d.pop("title", UNSET))

        severity = d.pop("severity", UNSET)

        def _parse_asset_type(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_type = _parse_asset_type(d.pop("asset_type", UNSET))

        def _parse_asset_value_usd(data: object) -> float | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(float | None | Unset, data)

        asset_value_usd = _parse_asset_value_usd(d.pop("asset_value_usd", UNSET))

        def _parse_description(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        description = _parse_description(d.pop("description", UNSET))

        quantify_finding_request = cls(
            id=id,
            title=title,
            severity=severity,
            asset_type=asset_type,
            asset_value_usd=asset_value_usd,
            description=description,
        )

        quantify_finding_request.additional_properties = d
        return quantify_finding_request

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
