from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SlackAlertRequest")


@_attrs_define
class SlackAlertRequest:
    """For ad-hoc alert notifications via the API.

    Attributes:
        title (str): Alert title
        message (str | Unset): Alert details Default: ''.
        severity (str | Unset): critical | high | medium | low Default: 'critical'.
        alert_id (None | str | Unset): Alert ID
        source_engine (None | str | Unset): Source engine name
        org_id (None | str | Unset): Organisation ID
    """

    title: str
    message: str | Unset = ""
    severity: str | Unset = "critical"
    alert_id: None | str | Unset = UNSET
    source_engine: None | str | Unset = UNSET
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        title = self.title

        message = self.message

        severity = self.severity

        alert_id: None | str | Unset
        if isinstance(self.alert_id, Unset):
            alert_id = UNSET
        else:
            alert_id = self.alert_id

        source_engine: None | str | Unset
        if isinstance(self.source_engine, Unset):
            source_engine = UNSET
        else:
            source_engine = self.source_engine

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "title": title,
            }
        )
        if message is not UNSET:
            field_dict["message"] = message
        if severity is not UNSET:
            field_dict["severity"] = severity
        if alert_id is not UNSET:
            field_dict["alert_id"] = alert_id
        if source_engine is not UNSET:
            field_dict["source_engine"] = source_engine
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        title = d.pop("title")

        message = d.pop("message", UNSET)

        severity = d.pop("severity", UNSET)

        def _parse_alert_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        alert_id = _parse_alert_id(d.pop("alert_id", UNSET))

        def _parse_source_engine(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        source_engine = _parse_source_engine(d.pop("source_engine", UNSET))

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        slack_alert_request = cls(
            title=title,
            message=message,
            severity=severity,
            alert_id=alert_id,
            source_engine=source_engine,
            org_id=org_id,
        )

        slack_alert_request.additional_properties = d
        return slack_alert_request

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
