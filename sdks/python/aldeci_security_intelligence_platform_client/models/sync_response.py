from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="SyncResponse")


@_attrs_define
class SyncResponse:
    """
    Attributes:
        sync_id (str):
        provider (str):
        account_id (str):
        started_at (str):
        status (str):
        completed_at (None | str | Unset):
        resources_found (int | Unset):  Default: 0.
        findings_found (int | Unset):  Default: 0.
        error (None | str | Unset):
    """

    sync_id: str
    provider: str
    account_id: str
    started_at: str
    status: str
    completed_at: None | str | Unset = UNSET
    resources_found: int | Unset = 0
    findings_found: int | Unset = 0
    error: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        sync_id = self.sync_id

        provider = self.provider

        account_id = self.account_id

        started_at = self.started_at

        status = self.status

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        resources_found = self.resources_found

        findings_found = self.findings_found

        error: None | str | Unset
        if isinstance(self.error, Unset):
            error = UNSET
        else:
            error = self.error

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "sync_id": sync_id,
                "provider": provider,
                "account_id": account_id,
                "started_at": started_at,
                "status": status,
            }
        )
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at
        if resources_found is not UNSET:
            field_dict["resources_found"] = resources_found
        if findings_found is not UNSET:
            field_dict["findings_found"] = findings_found
        if error is not UNSET:
            field_dict["error"] = error

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        sync_id = d.pop("sync_id")

        provider = d.pop("provider")

        account_id = d.pop("account_id")

        started_at = d.pop("started_at")

        status = d.pop("status")

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        resources_found = d.pop("resources_found", UNSET)

        findings_found = d.pop("findings_found", UNSET)

        def _parse_error(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error = _parse_error(d.pop("error", UNSET))

        sync_response = cls(
            sync_id=sync_id,
            provider=provider,
            account_id=account_id,
            started_at=started_at,
            status=status,
            completed_at=completed_at,
            resources_found=resources_found,
            findings_found=findings_found,
            error=error,
        )

        sync_response.additional_properties = d
        return sync_response

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
