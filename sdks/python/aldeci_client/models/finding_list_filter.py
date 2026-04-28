from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="FindingListFilter")


@_attrs_define
class FindingListFilter:
    """Filters for listing findings.

    Attributes:
        severity (list[str] | None | Unset): Filter by severity
        status (list[str] | None | Unset): Filter by status
        connector (None | str | Unset): Filter by source connector
        cve_id (None | str | Unset): Filter by CVE ID
        asset_id (None | str | Unset): Filter by asset ID
        assigned_to (None | str | Unset): Filter by assignee
        date_from (None | str | Unset): Created after (ISO 8601)
        date_to (None | str | Unset): Created before (ISO 8601)
    """

    severity: list[str] | None | Unset = UNSET
    status: list[str] | None | Unset = UNSET
    connector: None | str | Unset = UNSET
    cve_id: None | str | Unset = UNSET
    asset_id: None | str | Unset = UNSET
    assigned_to: None | str | Unset = UNSET
    date_from: None | str | Unset = UNSET
    date_to: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        severity: list[str] | None | Unset
        if isinstance(self.severity, Unset):
            severity = UNSET
        elif isinstance(self.severity, list):
            severity = self.severity

        else:
            severity = self.severity

        status: list[str] | None | Unset
        if isinstance(self.status, Unset):
            status = UNSET
        elif isinstance(self.status, list):
            status = self.status

        else:
            status = self.status

        connector: None | str | Unset
        if isinstance(self.connector, Unset):
            connector = UNSET
        else:
            connector = self.connector

        cve_id: None | str | Unset
        if isinstance(self.cve_id, Unset):
            cve_id = UNSET
        else:
            cve_id = self.cve_id

        asset_id: None | str | Unset
        if isinstance(self.asset_id, Unset):
            asset_id = UNSET
        else:
            asset_id = self.asset_id

        assigned_to: None | str | Unset
        if isinstance(self.assigned_to, Unset):
            assigned_to = UNSET
        else:
            assigned_to = self.assigned_to

        date_from: None | str | Unset
        if isinstance(self.date_from, Unset):
            date_from = UNSET
        else:
            date_from = self.date_from

        date_to: None | str | Unset
        if isinstance(self.date_to, Unset):
            date_to = UNSET
        else:
            date_to = self.date_to

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update({})
        if severity is not UNSET:
            field_dict["severity"] = severity
        if status is not UNSET:
            field_dict["status"] = status
        if connector is not UNSET:
            field_dict["connector"] = connector
        if cve_id is not UNSET:
            field_dict["cve_id"] = cve_id
        if asset_id is not UNSET:
            field_dict["asset_id"] = asset_id
        if assigned_to is not UNSET:
            field_dict["assigned_to"] = assigned_to
        if date_from is not UNSET:
            field_dict["date_from"] = date_from
        if date_to is not UNSET:
            field_dict["date_to"] = date_to

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)

        def _parse_severity(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                severity_type_0 = cast(list[str], data)

                return severity_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        severity = _parse_severity(d.pop("severity", UNSET))

        def _parse_status(data: object) -> list[str] | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            try:
                if not isinstance(data, list):
                    raise TypeError()
                status_type_0 = cast(list[str], data)

                return status_type_0
            except (TypeError, ValueError, AttributeError, KeyError):
                pass
            return cast(list[str] | None | Unset, data)

        status = _parse_status(d.pop("status", UNSET))

        def _parse_connector(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        connector = _parse_connector(d.pop("connector", UNSET))

        def _parse_cve_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        cve_id = _parse_cve_id(d.pop("cve_id", UNSET))

        def _parse_asset_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        asset_id = _parse_asset_id(d.pop("asset_id", UNSET))

        def _parse_assigned_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        assigned_to = _parse_assigned_to(d.pop("assigned_to", UNSET))

        def _parse_date_from(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date_from = _parse_date_from(d.pop("date_from", UNSET))

        def _parse_date_to(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        date_to = _parse_date_to(d.pop("date_to", UNSET))

        finding_list_filter = cls(
            severity=severity,
            status=status,
            connector=connector,
            cve_id=cve_id,
            asset_id=asset_id,
            assigned_to=assigned_to,
            date_from=date_from,
            date_to=date_to,
        )

        finding_list_filter.additional_properties = d
        return finding_list_filter

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
