from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.sla_status_enum import SLAStatusEnum

T = TypeVar("T", bound="SLATracking")


@_attrs_define
class SLATracking:
    """
    Attributes:
        tracking_id (str):
        finding_id (str):
        severity (str):
        policy_id (None | str):
        org_id (str):
        created_at (datetime.datetime):
        deadline (datetime.datetime):
        status (SLAStatusEnum):
        time_remaining (None | str):
        resolution_time (datetime.datetime | None):
    """

    tracking_id: str
    finding_id: str
    severity: str
    policy_id: None | str
    org_id: str
    created_at: datetime.datetime
    deadline: datetime.datetime
    status: SLAStatusEnum
    time_remaining: None | str
    resolution_time: datetime.datetime | None
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        tracking_id = self.tracking_id

        finding_id = self.finding_id

        severity = self.severity

        policy_id: None | str
        policy_id = self.policy_id

        org_id = self.org_id

        created_at = self.created_at.isoformat()

        deadline = self.deadline.isoformat()

        status = self.status.value

        time_remaining: None | str
        time_remaining = self.time_remaining

        resolution_time: None | str
        if isinstance(self.resolution_time, datetime.datetime):
            resolution_time = self.resolution_time.isoformat()
        else:
            resolution_time = self.resolution_time

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "tracking_id": tracking_id,
                "finding_id": finding_id,
                "severity": severity,
                "policy_id": policy_id,
                "org_id": org_id,
                "created_at": created_at,
                "deadline": deadline,
                "status": status,
                "time_remaining": time_remaining,
                "resolution_time": resolution_time,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        tracking_id = d.pop("tracking_id")

        finding_id = d.pop("finding_id")

        severity = d.pop("severity")

        def _parse_policy_id(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        policy_id = _parse_policy_id(d.pop("policy_id"))

        org_id = d.pop("org_id")

        created_at = isoparse(d.pop("created_at"))

        deadline = isoparse(d.pop("deadline"))

        status = SLAStatusEnum(d.pop("status"))

        def _parse_time_remaining(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        time_remaining = _parse_time_remaining(d.pop("time_remaining"))

        def _parse_resolution_time(data: object) -> datetime.datetime | None:
            if data is None:
                return data
            try:
                if not isinstance(data, str):
                    raise TypeError()
                resolution_time_type_0 = isoparse(data)

                return resolution_time_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(datetime.datetime | None, data)

        resolution_time = _parse_resolution_time(d.pop("resolution_time"))

        sla_tracking = cls(
            tracking_id=tracking_id,
            finding_id=finding_id,
            severity=severity,
            policy_id=policy_id,
            org_id=org_id,
            created_at=created_at,
            deadline=deadline,
            status=status,
            time_remaining=time_remaining,
            resolution_time=resolution_time,
        )

        sla_tracking.additional_properties = d
        return sla_tracking

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
