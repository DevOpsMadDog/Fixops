from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordAccessEventRequest")


@_attrs_define
class RecordAccessEventRequest:
    """
    Attributes:
        app_id (str):
        org_id (str | Unset):  Default: 'default'.
        user_id (str | Unset):  Default: ''.
        access_type (str | Unset):  Default: 'oauth'.
        data_accessed (str | Unset):  Default: ''.
        bytes_transferred (int | Unset):  Default: 0.
        source_ip (str | Unset):  Default: ''.
        success (bool | Unset):  Default: True.
        occurred_at (None | str | Unset):
    """

    app_id: str
    org_id: str | Unset = "default"
    user_id: str | Unset = ""
    access_type: str | Unset = "oauth"
    data_accessed: str | Unset = ""
    bytes_transferred: int | Unset = 0
    source_ip: str | Unset = ""
    success: bool | Unset = True
    occurred_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        app_id = self.app_id

        org_id = self.org_id

        user_id = self.user_id

        access_type = self.access_type

        data_accessed = self.data_accessed

        bytes_transferred = self.bytes_transferred

        source_ip = self.source_ip

        success = self.success

        occurred_at: None | str | Unset
        if isinstance(self.occurred_at, Unset):
            occurred_at = UNSET
        else:
            occurred_at = self.occurred_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "app_id": app_id,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if user_id is not UNSET:
            field_dict["user_id"] = user_id
        if access_type is not UNSET:
            field_dict["access_type"] = access_type
        if data_accessed is not UNSET:
            field_dict["data_accessed"] = data_accessed
        if bytes_transferred is not UNSET:
            field_dict["bytes_transferred"] = bytes_transferred
        if source_ip is not UNSET:
            field_dict["source_ip"] = source_ip
        if success is not UNSET:
            field_dict["success"] = success
        if occurred_at is not UNSET:
            field_dict["occurred_at"] = occurred_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        app_id = d.pop("app_id")

        org_id = d.pop("org_id", UNSET)

        user_id = d.pop("user_id", UNSET)

        access_type = d.pop("access_type", UNSET)

        data_accessed = d.pop("data_accessed", UNSET)

        bytes_transferred = d.pop("bytes_transferred", UNSET)

        source_ip = d.pop("source_ip", UNSET)

        success = d.pop("success", UNSET)

        def _parse_occurred_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        occurred_at = _parse_occurred_at(d.pop("occurred_at", UNSET))

        record_access_event_request = cls(
            app_id=app_id,
            org_id=org_id,
            user_id=user_id,
            access_type=access_type,
            data_accessed=data_accessed,
            bytes_transferred=bytes_transferred,
            source_ip=source_ip,
            success=success,
            occurred_at=occurred_at,
        )

        record_access_event_request.additional_properties = d
        return record_access_event_request

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
