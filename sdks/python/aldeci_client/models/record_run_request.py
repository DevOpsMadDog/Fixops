from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="RecordRunRequest")


@_attrs_define
class RecordRunRequest:
    """
    Attributes:
        run_status (str): queued | running | completed | failed | partial
        records_in (int | Unset): Records read from source Default: 0.
        records_out (int | Unset): Records successfully processed Default: 0.
        records_failed (int | Unset): Records that failed processing Default: 0.
        duration_seconds (int | Unset): Wall-clock duration of the run Default: 0.
        error_message (None | str | Unset): Error detail if run failed
        started_at (None | str | Unset): ISO-8601 run start time
        completed_at (None | str | Unset): ISO-8601 run completion time
    """

    run_status: str
    records_in: int | Unset = 0
    records_out: int | Unset = 0
    records_failed: int | Unset = 0
    duration_seconds: int | Unset = 0
    error_message: None | str | Unset = UNSET
    started_at: None | str | Unset = UNSET
    completed_at: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        run_status = self.run_status

        records_in = self.records_in

        records_out = self.records_out

        records_failed = self.records_failed

        duration_seconds = self.duration_seconds

        error_message: None | str | Unset
        if isinstance(self.error_message, Unset):
            error_message = UNSET
        else:
            error_message = self.error_message

        started_at: None | str | Unset
        if isinstance(self.started_at, Unset):
            started_at = UNSET
        else:
            started_at = self.started_at

        completed_at: None | str | Unset
        if isinstance(self.completed_at, Unset):
            completed_at = UNSET
        else:
            completed_at = self.completed_at

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "run_status": run_status,
            }
        )
        if records_in is not UNSET:
            field_dict["records_in"] = records_in
        if records_out is not UNSET:
            field_dict["records_out"] = records_out
        if records_failed is not UNSET:
            field_dict["records_failed"] = records_failed
        if duration_seconds is not UNSET:
            field_dict["duration_seconds"] = duration_seconds
        if error_message is not UNSET:
            field_dict["error_message"] = error_message
        if started_at is not UNSET:
            field_dict["started_at"] = started_at
        if completed_at is not UNSET:
            field_dict["completed_at"] = completed_at

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        run_status = d.pop("run_status")

        records_in = d.pop("records_in", UNSET)

        records_out = d.pop("records_out", UNSET)

        records_failed = d.pop("records_failed", UNSET)

        duration_seconds = d.pop("duration_seconds", UNSET)

        def _parse_error_message(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        error_message = _parse_error_message(d.pop("error_message", UNSET))

        def _parse_started_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        started_at = _parse_started_at(d.pop("started_at", UNSET))

        def _parse_completed_at(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        completed_at = _parse_completed_at(d.pop("completed_at", UNSET))

        record_run_request = cls(
            run_status=run_status,
            records_in=records_in,
            records_out=records_out,
            records_failed=records_failed,
            duration_seconds=duration_seconds,
            error_message=error_message,
            started_at=started_at,
            completed_at=completed_at,
        )

        record_run_request.additional_properties = d
        return record_run_request

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
