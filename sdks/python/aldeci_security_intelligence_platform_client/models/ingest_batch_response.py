from __future__ import annotations

from collections.abc import Mapping
from typing import Any, TypeVar, cast

from attrs import define as _attrs_define
from attrs import field as _attrs_field

from ..types import UNSET, Unset

T = TypeVar("T", bound="IngestBatchResponse")


@_attrs_define
class IngestBatchResponse:
    """Response after batch ingestion.

    Attributes:
        ingested (int):
        anomalies_detected (int):
        anomaly_ids (list[str] | Unset):
    """

    ingested: int
    anomalies_detected: int
    anomaly_ids: list[str] | Unset = UNSET
    additional_properties: dict[str, Any] = _attrs_field(init=False, factory=dict)

    def to_dict(self) -> dict[str, Any]:
        ingested = self.ingested

        anomalies_detected = self.anomalies_detected

        anomaly_ids: list[str] | Unset = UNSET
        if not isinstance(self.anomaly_ids, Unset):
            anomaly_ids = self.anomaly_ids

        field_dict: dict[str, Any] = {}
        field_dict.update(self.additional_properties)
        field_dict.update(
            {
                "ingested": ingested,
                "anomalies_detected": anomalies_detected,
            }
        )
        if anomaly_ids is not UNSET:
            field_dict["anomaly_ids"] = anomaly_ids

        return field_dict

    @classmethod
    def from_dict(cls: type[T], src_dict: Mapping[str, Any]) -> T:
        d = dict(src_dict)
        ingested = d.pop("ingested")

        anomalies_detected = d.pop("anomalies_detected")

        anomaly_ids = cast(list[str], d.pop("anomaly_ids", UNSET))

        ingest_batch_response = cls(
            ingested=ingested,
            anomalies_detected=anomalies_detected,
            anomaly_ids=anomaly_ids,
        )

        ingest_batch_response.additional_properties = d
        return ingest_batch_response

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
