from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordUtilizationRequest")


@_attrs_define
class RecordUtilizationRequest:
    """
    Attributes:
        org_id (str | Unset): Organisation ID Default: 'default'.
        utilization_pct (float | Unset): Utilization percentage 0-100 Default: 0.0.
        direction (str | Unset): Traffic direction: inbound/outbound/both Default: 'both'.
        recorded_at (None | str | Unset): ISO-8601 timestamp
    """

    org_id: str | Unset = "default"
    utilization_pct: float | Unset = 0.0
    direction: str | Unset = "both"
    recorded_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        utilization_pct = self.utilization_pct

        direction = self.direction

        recorded_at: None | str | Unset
        if isinstance(self.recorded_at, Unset):
            recorded_at = UNSET
        else:
            recorded_at = self.recorded_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if utilization_pct is not UNSET:
            field_dict["utilization_pct"] = utilization_pct
        if direction is not UNSET:
            field_dict["direction"] = direction
        if recorded_at is not UNSET:
            field_dict["recorded_at"] = recorded_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id", UNSET)

        utilization_pct = d.pop("utilization_pct", UNSET)

        direction = d.pop("direction", UNSET)

        def _parse_recorded_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        recorded_at = _parse_recorded_at(d.pop("recorded_at", UNSET))

        record_utilization_request = cls(
            org_id=org_id,
            utilization_pct=utilization_pct,
            direction=direction,
            recorded_at=recorded_at,
        )

        record_utilization_request.additional_properties = d
        return record_utilization_request

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
