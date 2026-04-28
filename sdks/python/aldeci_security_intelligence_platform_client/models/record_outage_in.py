from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordOutageIn")


@_attrs_define
class RecordOutageIn:
    """
    Attributes:
        org_id (str):
        started_at (str):
        outage_type (str | Unset):  Default: 'unplanned'.
        severity (str | Unset):  Default: 'medium'.
        affected_users (int | Unset):  Default: 0.
        root_cause (str | Unset):  Default: ''.
    """

    org_id: str
    started_at: str
    outage_type: str | Unset = "unplanned"
    severity: str | Unset = "medium"
    affected_users: int | Unset = 0
    root_cause: str | Unset = ""
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        org_id = self.org_id

        started_at = self.started_at

        outage_type = self.outage_type

        severity = self.severity

        affected_users = self.affected_users

        root_cause = self.root_cause

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "org_id": org_id,
                "started_at": started_at,
            }
        )
        if outage_type is not UNSET:
            field_dict["outage_type"] = outage_type
        if severity is not UNSET:
            field_dict["severity"] = severity
        if affected_users is not UNSET:
            field_dict["affected_users"] = affected_users
        if root_cause is not UNSET:
            field_dict["root_cause"] = root_cause

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        org_id = d.pop("org_id")

        started_at = d.pop("started_at")

        outage_type = d.pop("outage_type", UNSET)

        severity = d.pop("severity", UNSET)

        affected_users = d.pop("affected_users", UNSET)

        root_cause = d.pop("root_cause", UNSET)

        record_outage_in = cls(
            org_id=org_id,
            started_at=started_at,
            outage_type=outage_type,
            severity=severity,
            affected_users=affected_users,
            root_cause=root_cause,
        )

        record_outage_in.additional_properties = d
        return record_outage_in

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
