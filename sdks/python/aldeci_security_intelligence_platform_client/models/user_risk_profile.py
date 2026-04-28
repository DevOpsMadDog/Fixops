from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..models.alert_level import AlertLevel
from ..models.threat_indicator import ThreatIndicator
from ..types import UNSET, Unset

T = TypeVar("T", bound="UserRiskProfile")


@_attrs_define
class UserRiskProfile:
    """Risk assessment for a single user.

    Attributes:
        user_email (str):
        risk_score (float):
        indicators (list[ThreatIndicator]):
        alert_level (AlertLevel): Severity of a user risk profile.
        org_id (str):
        last_assessed (datetime.datetime | Unset):
    """

    user_email: str
    risk_score: float
    indicators: list[ThreatIndicator]
    alert_level: AlertLevel
    org_id: str
    last_assessed: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        user_email = self.user_email

        risk_score = self.risk_score

        indicators = []
        for indicators_item_data in self.indicators:
            indicators_item = indicators_item_data.value
            indicators.append(indicators_item)

        alert_level = self.alert_level.value

        org_id = self.org_id

        last_assessed: str | Unset = UNSET
        if not isinstance(self.last_assessed, Unset):
            last_assessed = self.last_assessed.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "user_email": user_email,
                "risk_score": risk_score,
                "indicators": indicators,
                "alert_level": alert_level,
                "org_id": org_id,
            }
        )
        if last_assessed is not UNSET:
            field_dict["last_assessed"] = last_assessed

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        user_email = d.pop("user_email")

        risk_score = d.pop("risk_score")

        indicators = []
        _indicators = d.pop("indicators")
        for indicators_item_data in _indicators:
            indicators_item = ThreatIndicator(indicators_item_data)

            indicators.append(indicators_item)

        alert_level = AlertLevel(d.pop("alert_level"))

        org_id = d.pop("org_id")

        _last_assessed = d.pop("last_assessed", UNSET)
        last_assessed: datetime.datetime | Unset
        if isinstance(_last_assessed, Unset):
            last_assessed = UNSET
        else:
            last_assessed = isoparse(_last_assessed)

        user_risk_profile = cls(
            user_email=user_email,
            risk_score=risk_score,
            indicators=indicators,
            alert_level=alert_level,
            org_id=org_id,
            last_assessed=last_assessed,
        )

        user_risk_profile.additional_properties = d
        return user_risk_profile

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
