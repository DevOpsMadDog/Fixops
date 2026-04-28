from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

T = TypeVar("T", bound="SLAStatusResponse")


@_attrs_define
class SLAStatusResponse:
    """SLA status response for a single finding.

    Attributes:
        finding_id (str):
        status (str):
        severity (str):
        asset_tier (str):
        deadline (str):
        discovered_at (str):
        pct_elapsed (float):
        escalation_level (str):
        breached_at (None | str):
        resolved_at (None | str):
        frameworks (list[str]):
        business_hours (bool):
    """

    finding_id: str
    status: str
    severity: str
    asset_tier: str
    deadline: str
    discovered_at: str
    pct_elapsed: float
    escalation_level: str
    breached_at: None | str
    resolved_at: None | str
    frameworks: list[str]
    business_hours: bool
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        finding_id = self.finding_id

        status = self.status

        severity = self.severity

        asset_tier = self.asset_tier

        deadline = self.deadline

        discovered_at = self.discovered_at

        pct_elapsed = self.pct_elapsed

        escalation_level = self.escalation_level

        breached_at: None | str
        breached_at = self.breached_at

        resolved_at: None | str
        resolved_at = self.resolved_at

        frameworks = self.frameworks

        business_hours = self.business_hours

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "finding_id": finding_id,
                "status": status,
                "severity": severity,
                "asset_tier": asset_tier,
                "deadline": deadline,
                "discovered_at": discovered_at,
                "pct_elapsed": pct_elapsed,
                "escalation_level": escalation_level,
                "breached_at": breached_at,
                "resolved_at": resolved_at,
                "frameworks": frameworks,
                "business_hours": business_hours,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        finding_id = d.pop("finding_id")

        status = d.pop("status")

        severity = d.pop("severity")

        asset_tier = d.pop("asset_tier")

        deadline = d.pop("deadline")

        discovered_at = d.pop("discovered_at")

        pct_elapsed = d.pop("pct_elapsed")

        escalation_level = d.pop("escalation_level")

        def _parse_breached_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        breached_at = _parse_breached_at(d.pop("breached_at"))

        def _parse_resolved_at(data: object) -> None | str:
            if data is None:
                return data
            return cast(None | str, data)

        resolved_at = _parse_resolved_at(d.pop("resolved_at"))

        frameworks = cast(list[str], d.pop("frameworks"))

        business_hours = d.pop("business_hours")

        sla_status_response = cls(
            finding_id=finding_id,
            status=status,
            severity=severity,
            asset_tier=asset_tier,
            deadline=deadline,
            discovered_at=discovered_at,
            pct_elapsed=pct_elapsed,
            escalation_level=escalation_level,
            breached_at=breached_at,
            resolved_at=resolved_at,
            frameworks=frameworks,
            business_hours=business_hours,
        )

        sla_status_response.additional_properties = d
        return sla_status_response

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
