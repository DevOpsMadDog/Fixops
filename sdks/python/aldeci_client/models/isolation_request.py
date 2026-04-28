from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IsolationRequest")


@_attrs_define
class IsolationRequest:
    """
    Attributes:
        entity_id (str): Entity to score
        metric_names (list[str]): Feature metric names
        current_values (list[float]): Current feature vector
        window_days (int | Unset): Training window in days Default: 14.
        org_id (str | Unset): Organisation ID Default: 'default'.
    """

    entity_id: str
    metric_names: list[str]
    current_values: list[float]
    window_days: int | Unset = 14
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        entity_id = self.entity_id

        metric_names = self.metric_names

        current_values = self.current_values

        window_days = self.window_days

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "entity_id": entity_id,
                "metric_names": metric_names,
                "current_values": current_values,
            }
        )
        if window_days is not UNSET:
            field_dict["window_days"] = window_days
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        entity_id = d.pop("entity_id")

        metric_names = cast(list[str], d.pop("metric_names"))

        current_values = cast(list[float], d.pop("current_values"))

        window_days = d.pop("window_days", UNSET)

        org_id = d.pop("org_id", UNSET)

        isolation_request = cls(
            entity_id=entity_id,
            metric_names=metric_names,
            current_values=current_values,
            window_days=window_days,
            org_id=org_id,
        )

        isolation_request.additional_properties = d
        return isolation_request

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
