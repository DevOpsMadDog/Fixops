from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

T = TypeVar("T", bound="PullJobResponse")


@_attrs_define
class PullJobResponse:
    """Response for POST /api/v1/connectors/{name}/pull.

    Attributes:
        job_id (str): Async pull job ID
        connector (str): Connector name
        timestamp (datetime.datetime): When pull was triggered
        expected_completion_seconds (int | None | Unset): Estimated seconds until completion
    """

    job_id: str
    connector: str
    timestamp: datetime.datetime
    expected_completion_seconds: int | None | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        job_id = self.job_id

        connector = self.connector

        timestamp = self.timestamp.isoformat()

        expected_completion_seconds: int | None | Unset
        if isinstance(self.expected_completion_seconds, Unset):
            expected_completion_seconds = UNSET
        else:
            expected_completion_seconds = self.expected_completion_seconds

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "job_id": job_id,
                "connector": connector,
                "timestamp": timestamp,
            }
        )
        if expected_completion_seconds is not UNSET:
            field_dict["expected_completion_seconds"] = expected_completion_seconds

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        job_id = d.pop("job_id")

        connector = d.pop("connector")

        timestamp = isoparse(d.pop("timestamp"))

        def _parse_expected_completion_seconds(data: object) -> int | None | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(int | None | Unset, data)

        expected_completion_seconds = _parse_expected_completion_seconds(d.pop("expected_completion_seconds", UNSET))

        pull_job_response = cls(
            job_id=job_id,
            connector=connector,
            timestamp=timestamp,
            expected_completion_seconds=expected_completion_seconds,
        )

        pull_job_response.additional_properties = d
        return pull_job_response

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
