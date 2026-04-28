from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.send_now_request_filters import SendNowRequestFilters


T = TypeVar("T", bound="SendNowRequest")


@_attrs_define
class SendNowRequest:
    """
    Attributes:
        report_type (str): One of: ['executive_summary', 'vulnerability_digest', 'compliance_status',
            'threat_intel_brief', 'kpi_scorecard']
        recipients (list[str] | Unset):
        channels (list[str] | Unset):
        format_ (str | Unset):  Default: 'json'.
        filters (SendNowRequestFilters | Unset):
        org_id (str | Unset):  Default: 'default'.
    """

    report_type: str
    recipients: list[str] | Unset = UNSET
    channels: list[str] | Unset = UNSET
    format_: str | Unset = "json"
    filters: SendNowRequestFilters | Unset = UNSET
    org_id: str | Unset = "default"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        report_type = self.report_type

        recipients: list[str] | Unset = UNSET
        if not isinstance(self.recipients, Unset):
            recipients = self.recipients

        channels: list[str] | Unset = UNSET
        if not isinstance(self.channels, Unset):
            channels = self.channels

        format_ = self.format_

        filters: dict[str, Any] | Unset = UNSET
        if not isinstance(self.filters, Unset):
            filters = self.filters.to_dict()

        org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "report_type": report_type,
            }
        )
        if recipients is not UNSET:
            field_dict["recipients"] = recipients
        if channels is not UNSET:
            field_dict["channels"] = channels
        if format_ is not UNSET:
            field_dict["format"] = format_
        if filters is not UNSET:
            field_dict["filters"] = filters
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.send_now_request_filters import SendNowRequestFilters

        d = dict(src_dict)
        report_type = d.pop("report_type")

        recipients = cast(list[str], d.pop("recipients", UNSET))

        channels = cast(list[str], d.pop("channels", UNSET))

        format_ = d.pop("format", UNSET)

        _filters = d.pop("filters", UNSET)
        filters: SendNowRequestFilters | Unset
        if isinstance(_filters, Unset):
            filters = UNSET
        else:
            filters = SendNowRequestFilters.from_dict(_filters)

        org_id = d.pop("org_id", UNSET)

        send_now_request = cls(
            report_type=report_type,
            recipients=recipients,
            channels=channels,
            format_=format_,
            filters=filters,
            org_id=org_id,
        )

        send_now_request.additional_properties = d
        return send_now_request

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
