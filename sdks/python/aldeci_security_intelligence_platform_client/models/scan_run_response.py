from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="ScanRunResponse")


@_attrs_define
class ScanRunResponse:
    """Response returned immediately when a scan is triggered.

    Attributes:
        scan_id (str):
        message (str):
        status (str | Unset):  Default: 'running'.
        triggered_at (datetime.datetime | Unset):
    """

    scan_id: str
    message: str
    status: str | Unset = "running"
    triggered_at: datetime.datetime | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        scan_id = self.scan_id

        message = self.message

        status = self.status

        triggered_at: str | Unset = UNSET
        if not isinstance(self.triggered_at, Unset):
            triggered_at = self.triggered_at.isoformat()

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "scan_id": scan_id,
                "message": message,
            }
        )
        if status is not UNSET:
            field_dict["status"] = status
        if triggered_at is not UNSET:
            field_dict["triggered_at"] = triggered_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        scan_id = d.pop("scan_id")

        message = d.pop("message")

        status = d.pop("status", UNSET)

        _triggered_at = d.pop("triggered_at", UNSET)
        triggered_at: datetime.datetime | Unset
        if isinstance(_triggered_at, Unset):
            triggered_at = UNSET
        else:
            triggered_at = isoparse(_triggered_at)

        scan_run_response = cls(
            scan_id=scan_id,
            message=message,
            status=status,
            triggered_at=triggered_at,
        )

        scan_run_response.additional_properties = d
        return scan_run_response

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
