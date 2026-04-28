from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.canary_alert_request_headers import CanaryAlertRequestHeaders


T = TypeVar("T", bound="CanaryAlert")


@_attrs_define
class CanaryAlert:
    """Fired when a canary token is accessed / used.

    Attributes:
        canary_id (str):
        source_ip (str):
        org_id (str):
        id (str | Unset):
        triggered_at (datetime.datetime | Unset):
        user_agent (str | Unset):  Default: ''.
        request_headers (CanaryAlertRequestHeaders | Unset):
        severity (str | Unset):  Default: 'critical'.
    """

    canary_id: str
    source_ip: str
    org_id: str
    id: str | Unset = UNSET
    triggered_at: datetime.datetime | Unset = UNSET
    user_agent: str | Unset = ""
    request_headers: CanaryAlertRequestHeaders | Unset = UNSET
    severity: str | Unset = "critical"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        canary_id = self.canary_id

        source_ip = self.source_ip

        org_id = self.org_id

        id = self.id

        triggered_at: str | Unset = UNSET
        if not isinstance(self.triggered_at, Unset):
            triggered_at = self.triggered_at.isoformat()

        user_agent = self.user_agent

        request_headers: dict[str, Any] | Unset = UNSET
        if not isinstance(self.request_headers, Unset):
            request_headers = self.request_headers.to_dict()

        severity = self.severity

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "canary_id": canary_id,
                "source_ip": source_ip,
                "org_id": org_id,
            }
        )
        if id is not UNSET:
            field_dict["id"] = id
        if triggered_at is not UNSET:
            field_dict["triggered_at"] = triggered_at
        if user_agent is not UNSET:
            field_dict["user_agent"] = user_agent
        if request_headers is not UNSET:
            field_dict["request_headers"] = request_headers
        if severity is not UNSET:
            field_dict["severity"] = severity

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.canary_alert_request_headers import CanaryAlertRequestHeaders

        d = dict(src_dict)
        canary_id = d.pop("canary_id")

        source_ip = d.pop("source_ip")

        org_id = d.pop("org_id")

        id = d.pop("id", UNSET)

        _triggered_at = d.pop("triggered_at", UNSET)
        triggered_at: datetime.datetime | Unset
        if isinstance(_triggered_at, Unset):
            triggered_at = UNSET
        else:
            triggered_at = isoparse(_triggered_at)

        user_agent = d.pop("user_agent", UNSET)

        _request_headers = d.pop("request_headers", UNSET)
        request_headers: CanaryAlertRequestHeaders | Unset
        if isinstance(_request_headers, Unset):
            request_headers = UNSET
        else:
            request_headers = CanaryAlertRequestHeaders.from_dict(_request_headers)

        severity = d.pop("severity", UNSET)

        canary_alert = cls(
            canary_id=canary_id,
            source_ip=source_ip,
            org_id=org_id,
            id=id,
            triggered_at=triggered_at,
            user_agent=user_agent,
            request_headers=request_headers,
            severity=severity,
        )

        canary_alert.additional_properties = d
        return canary_alert

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
