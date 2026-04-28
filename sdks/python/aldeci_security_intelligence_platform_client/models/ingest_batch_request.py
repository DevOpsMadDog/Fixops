from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..models.log_format import LogFormat
from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestBatchRequest")


@_attrs_define
class IngestBatchRequest:
    """Batch log ingestion request.

    Attributes:
        lines (list[str]): List of raw log lines
        format_ (LogFormat | Unset): Supported wire formats for log ingestion.
        run_anomaly_detection (bool | Unset): Run anomaly detection on the batch Default: True.
        org_id (None | str | Unset):
    """

    lines: list[str]
    format_: LogFormat | Unset = UNSET
    run_anomaly_detection: bool | Unset = True
    org_id: None | str | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        lines = self.lines

        format_: str | Unset = UNSET
        if not isinstance(self.format_, Unset):
            format_ = self.format_.value

        run_anomaly_detection = self.run_anomaly_detection

        org_id: None | str | Unset
        if isinstance(self.org_id, Unset):
            org_id = UNSET
        else:
            org_id = self.org_id

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "lines": lines,
            }
        )
        if format_ is not UNSET:
            field_dict["format"] = format_
        if run_anomaly_detection is not UNSET:
            field_dict["run_anomaly_detection"] = run_anomaly_detection
        if org_id is not UNSET:
            field_dict["org_id"] = org_id

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        lines = cast(list[str], d.pop("lines"))

        _format_ = d.pop("format", UNSET)
        format_: LogFormat | Unset
        if isinstance(_format_, Unset):
            format_ = UNSET
        else:
            format_ = LogFormat(_format_)

        run_anomaly_detection = d.pop("run_anomaly_detection", UNSET)

        def _parse_org_id(data: object) -> None | str | Unset:
            if data is None:
                return data
            if isinstance(data, Unset):
                return data
            return cast(None | str | Unset, data)

        org_id = _parse_org_id(d.pop("org_id", UNSET))

        ingest_batch_request = cls(
            lines=lines,
            format_=format_,
            run_anomaly_detection=run_anomaly_detection,
            org_id=org_id,
        )

        ingest_batch_request.additional_properties = d
        return ingest_batch_request

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
