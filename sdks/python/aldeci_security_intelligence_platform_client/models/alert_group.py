from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.risk_level import RiskLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="AlertGroup")


@_attrs_define
class AlertGroup:
    """A cluster of related anomalies.

    Attributes:
        label (str):
        anomaly_ids (list[str]):
        grouping_reason (str):
        anomaly_count (int):
        highest_risk (RiskLevel):
        id (str | Unset):
        entity_id (None | str | Unset):
        created_at (datetime.datetime | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    label: str
    anomaly_ids: list[str]
    grouping_reason: str
    anomaly_count: int
    highest_risk: RiskLevel
    id: str | Unset = UNSET
    entity_id: None | str | Unset = UNSET
    created_at: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        label = self.label

        anomaly_ids = self.anomaly_ids

        grouping_reason = self.grouping_reason

        anomaly_count = self.anomaly_count

        highest_risk = self.highest_risk.value

        id = self.id

        entity_id: None | str | Unset
        if isinstance(self.entity_id, Unset):
            entity_id = UNSET
        else:
            entity_id = self.entity_id

        created_at: str | Unset = UNSET
        if not isinstance(self.created_at, Unset):
            created_at = self.created_at.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "label": label,
                "anomaly_ids": anomaly_ids,
                "grouping_reason": grouping_reason,
                "anomaly_count": anomaly_count,
                "highest_risk": highest_risk,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if entity_id is not UNSET:
            field_dict["entity_id"] = entity_id
        if created_at is not UNSET:
            field_dict["created_at"] = created_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        label = d.pop("label")

        anomaly_ids = cast(list[str], d.pop("anomaly_ids"))

        grouping_reason = d.pop("grouping_reason")

        anomaly_count = d.pop("anomaly_count")

        highest_risk = RiskLevel(d.pop("highest_risk"))

        id = d.pop("id", UNSET)

        def _parse_entity_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        entity_id = _parse_entity_id(d.pop("entity_id", UNSET))

        _created_at = d.pop("created_at", UNSET)
        created_at: datetime.datetime | Unset
        if isinstance(_created_at, Unset):
            created_at = UNSET
        else:
            created_at = isoparse(_created_at)

        org_id = d.pop("org_id", UNSET)

        alert_group = cls(
            label=label,
            anomaly_ids=anomaly_ids,
            grouping_reason=grouping_reason,
            anomaly_count=anomaly_count,
            highest_risk=highest_risk,
            id=id,
            entity_id=entity_id,
            created_at=created_at,
            org_id=org_id,
        )

        alert_group.additional_properties = d
        return alert_group

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
