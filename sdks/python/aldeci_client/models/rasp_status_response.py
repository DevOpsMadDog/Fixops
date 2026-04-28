from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.rasp_mode import RaspMode

if TYPE_CHECKING:
    from ..models.rasp_status_response_by_category import RaspStatusResponseByCategory
    from ..models.rasp_status_response_by_severity import RaspStatusResponseBySeverity
    from ..models.rasp_status_response_top_attacker_ips import RaspStatusResponseTopAttackerIps


T = TypeVar("T", bound="RaspStatusResponse")


@_attrs_define
class RaspStatusResponse:
    """Combined status + metrics snapshot.

    Attributes:
        mode (RaspMode): Operating mode for the RASP engine.
        engine_uptime_seconds (float):
        requests_inspected (int):
        threats_detected (int):
        threats_blocked (int):
        threats_allowed_monitor (int):
        threats_redirected (int):
        false_positive_rate (float):
        by_category (RaspStatusResponseByCategory):
        by_severity (RaspStatusResponseBySeverity):
        top_attacker_ips (RaspStatusResponseTopAttackerIps):
        active_rules (int):
        blocked_ips (int):
    """

    mode: RaspMode
    engine_uptime_seconds: float
    requests_inspected: int
    threats_detected: int
    threats_blocked: int
    threats_allowed_monitor: int
    threats_redirected: int
    false_positive_rate: float
    by_category: RaspStatusResponseByCategory
    by_severity: RaspStatusResponseBySeverity
    top_attacker_ips: RaspStatusResponseTopAttackerIps
    active_rules: int
    blocked_ips: int
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        mode = self.mode.value

        engine_uptime_seconds = self.engine_uptime_seconds

        requests_inspected = self.requests_inspected

        threats_detected = self.threats_detected

        threats_blocked = self.threats_blocked

        threats_allowed_monitor = self.threats_allowed_monitor

        threats_redirected = self.threats_redirected

        false_positive_rate = self.false_positive_rate

        by_category = self.by_category.to_dict()

        by_severity = self.by_severity.to_dict()

        top_attacker_ips = self.top_attacker_ips.to_dict()

        active_rules = self.active_rules

        blocked_ips = self.blocked_ips

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "mode": mode,
                "engine_uptime_seconds": engine_uptime_seconds,
                "requests_inspected": requests_inspected,
                "threats_detected": threats_detected,
                "threats_blocked": threats_blocked,
                "threats_allowed_monitor": threats_allowed_monitor,
                "threats_redirected": threats_redirected,
                "false_positive_rate": false_positive_rate,
                "by_category": by_category,
                "by_severity": by_severity,
                "top_attacker_ips": top_attacker_ips,
                "active_rules": active_rules,
                "blocked_ips": blocked_ips,
            }
        )

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.rasp_status_response_by_category import RaspStatusResponseByCategory
        from ..models.rasp_status_response_by_severity import RaspStatusResponseBySeverity
        from ..models.rasp_status_response_top_attacker_ips import RaspStatusResponseTopAttackerIps

        d = dict(src_dict)
        mode = RaspMode(d.pop("mode"))

        engine_uptime_seconds = d.pop("engine_uptime_seconds")

        requests_inspected = d.pop("requests_inspected")

        threats_detected = d.pop("threats_detected")

        threats_blocked = d.pop("threats_blocked")

        threats_allowed_monitor = d.pop("threats_allowed_monitor")

        threats_redirected = d.pop("threats_redirected")

        false_positive_rate = d.pop("false_positive_rate")

        by_category = RaspStatusResponseByCategory.from_dict(d.pop("by_category"))

        by_severity = RaspStatusResponseBySeverity.from_dict(d.pop("by_severity"))

        top_attacker_ips = RaspStatusResponseTopAttackerIps.from_dict(d.pop("top_attacker_ips"))

        active_rules = d.pop("active_rules")

        blocked_ips = d.pop("blocked_ips")

        rasp_status_response = cls(
            mode=mode,
            engine_uptime_seconds=engine_uptime_seconds,
            requests_inspected=requests_inspected,
            threats_detected=threats_detected,
            threats_blocked=threats_blocked,
            threats_allowed_monitor=threats_allowed_monitor,
            threats_redirected=threats_redirected,
            false_positive_rate=false_positive_rate,
            by_category=by_category,
            by_severity=by_severity,
            top_attacker_ips=top_attacker_ips,
            active_rules=active_rules,
            blocked_ips=blocked_ips,
        )

        rasp_status_response.additional_properties = d
        return rasp_status_response

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
