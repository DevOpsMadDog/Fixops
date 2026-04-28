from __future__ import annotations

import datetime
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, TypeVar

from attrs import define as _attrs_define
from attrs import field as _attrs_field
from dateutil.parser import isoparse

from ..types import UNSET, Unset

if TYPE_CHECKING:
    from ..models.ingest_result_errors_item import IngestResultErrorsItem


T = TypeVar("T", bound="IngestResult")


@_attrs_define
class IngestResult:
    """Response for POST /api/v1/connectors/ingest.

    Attributes:
        ingest_id (str): Unique ID for this ingest batch
        source (str): Connector source name
        timestamp (datetime.datetime): When ingest was processed
        accepted_count (int): Number of findings accepted
        duplicate_count (int): Number of duplicates skipped
        error_count (int): Number of parsing errors
        job_id (str): Background pipeline job ID
        errors (list[IngestResultErrorsItem] | Unset): Error details
    """

    ingest_id: str
    source: str
    timestamp: datetime.datetime
    accepted_count: int
    duplicate_count: int
    error_count: int
    job_id: str
    errors: list[IngestResultErrorsItem] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ingest_id = self.ingest_id

        source = self.source

        timestamp = self.timestamp.isoformat()

        accepted_count = self.accepted_count

        duplicate_count = self.duplicate_count

        error_count = self.error_count

        job_id = self.job_id

        errors: list[dict[str, Any]] | Unset = UNSET
        if not isinstance(self.errors, Unset):
            errors = []
            for errors_item_data in self.errors:
                errors_item = errors_item_data.to_dict()
                errors.append(errors_item)

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ingest_id": ingest_id,
                "source": source,
                "timestamp": timestamp,
                "accepted_count": accepted_count,
                "duplicate_count": duplicate_count,
                "error_count": error_count,
                "job_id": job_id,
            }
        )
        if errors is not UNSET:
            field_dict["errors"] = errors

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        from ..models.ingest_result_errors_item import IngestResultErrorsItem

        d = dict(src_dict)
        ingest_id = d.pop("ingest_id")

        source = d.pop("source")

        timestamp = isoparse(d.pop("timestamp"))

        accepted_count = d.pop("accepted_count")

        duplicate_count = d.pop("duplicate_count")

        error_count = d.pop("error_count")

        job_id = d.pop("job_id")

        _errors = d.pop("errors", UNSET)
        errors: list[IngestResultErrorsItem] | Unset = UNSET
        if _errors is not UNSET:
            errors = []
            for errors_item_data in _errors:
                errors_item = IngestResultErrorsItem.from_dict(errors_item_data)

                errors.append(errors_item)

        ingest_result = cls(
            ingest_id=ingest_id,
            source=source,
            timestamp=timestamp,
            accepted_count=accepted_count,
            duplicate_count=duplicate_count,
            error_count=error_count,
            job_id=job_id,
            errors=errors,
        )

        ingest_result.additional_properties = d
        return ingest_result

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
