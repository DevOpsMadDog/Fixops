from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="LogSourceCreate")


@_attrs_define
class LogSourceCreate:
    """
    Attributes:
        name (str):
        log_type (str):
        org_id (str | Unset):  Default: 'default'.
        format_ (str | Unset):  Default: 'json'.
        retention_days (int | Unset):  Default: 90.
        status (str | Unset):  Default: 'active'.
    """

    name: str
    log_type: str
    org_id: str | Unset = "default"
    format_: str | Unset = "json"
    retention_days: int | Unset = 90
    status: str | Unset = "active"
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        name = self.name

        log_type = self.log_type

        org_id = self.org_id

        format_ = self.format_

        retention_days = self.retention_days

        status = self.status

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "name": name,
                "log_type": log_type,
            }
        )
        if org_id is not UNSET:
            field_dict["org_id"] = org_id
        if format_ is not UNSET:
            field_dict["format"] = format_
        if retention_days is not UNSET:
            field_dict["retention_days"] = retention_days
        if status is not UNSET:
            field_dict["status"] = status

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        name = d.pop("name")

        log_type = d.pop("log_type")

        org_id = d.pop("org_id", UNSET)

        format_ = d.pop("format", UNSET)

        retention_days = d.pop("retention_days", UNSET)

        status = d.pop("status", UNSET)

        log_source_create = cls(
            name=name,
            log_type=log_type,
            org_id=org_id,
            format_=format_,
            retention_days=retention_days,
            status=status,
        )

        log_source_create.additional_properties = d
        return log_source_create

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
