from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.risk_level import RiskLevel
from ..types import UNSET, Unset

T = TypeVar("T", bound="UserRiskScore")


@_attrs_define
class UserRiskScore:
    """Composite UEBA risk score for a user.

    Attributes:
        user_id (str):
        risk_score (float):
        risk_level (RiskLevel):
        login_anomaly_score (float):
        access_pattern_score (float):
        data_volume_score (float):
        travel_anomaly_score (float):
        contributing_anomalies (list[str]):
        computed_at (datetime.datetime | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    user_id: str
    risk_score: float
    risk_level: RiskLevel
    login_anomaly_score: float
    access_pattern_score: float
    data_volume_score: float
    travel_anomaly_score: float
    contributing_anomalies: list[str]
    computed_at: datetime.datetime | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_id = self.user_id

        risk_score = self.risk_score

        risk_level = self.risk_level.value

        login_anomaly_score = self.login_anomaly_score

        access_pattern_score = self.access_pattern_score

        data_volume_score = self.data_volume_score

        travel_anomaly_score = self.travel_anomaly_score

        contributing_anomalies = self.contributing_anomalies

        computed_at: str | Unset = UNSET
        if not isinstance(self.computed_at, Unset):
            computed_at = self.computed_at.isoformat()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_id": user_id,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "login_anomaly_score": login_anomaly_score,
                "access_pattern_score": access_pattern_score,
                "data_volume_score": data_volume_score,
                "travel_anomaly_score": travel_anomaly_score,
                "contributing_anomalies": contributing_anomalies,
            }
        )
        if computed_at is not UNSET:
            field_dict["computed_at"] = computed_at
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_id = d.pop("user_id")

        risk_score = d.pop("risk_score")

        risk_level = RiskLevel(d.pop("risk_level"))

        login_anomaly_score = d.pop("login_anomaly_score")

        access_pattern_score = d.pop("access_pattern_score")

        data_volume_score = d.pop("data_volume_score")

        travel_anomaly_score = d.pop("travel_anomaly_score")

        contributing_anomalies = cast(list[str], d.pop("contributing_anomalies"))

        _computed_at = d.pop("computed_at", UNSET)
        computed_at: datetime.datetime | Unset
        if isinstance(_computed_at, Unset):
            computed_at = UNSET
        else:
            computed_at = isoparse(_computed_at)

        org_id = d.pop("org_id", UNSET)

        user_risk_score = cls(
            user_id=user_id,
            risk_score=risk_score,
            risk_level=risk_level,
            login_anomaly_score=login_anomaly_score,
            access_pattern_score=access_pattern_score,
            data_volume_score=data_volume_score,
            travel_anomaly_score=travel_anomaly_score,
            contributing_anomalies=contributing_anomalies,
            computed_at=computed_at,
            org_id=org_id,
        )

        user_risk_score.additional_properties = d
        return user_risk_score

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
